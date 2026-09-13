//go:build with_iwan && linux

package iwan

// This file implements one Linux TUN interface backed by multiple queue file
// descriptors.  It deliberately does not create a second interface: every
// descriptor is attached to the same IFF_MULTI_QUEUE device.  The wrapper
// keeps sing-tun's GSO/batch implementation for each queue and leaves route
// ownership to the existing system device.

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
)

type linuxTUNQueues interface {
	tun.LinuxTUN
	QueueCount() int
	Queue(index int) tun.LinuxTUN
}

type multiQueueLinuxTun struct {
	queues    []tun.LinuxTUN
	name      string
	closeOnce sync.Once
	writePool sync.Pool
}

var _ linuxTUNQueues = (*multiQueueLinuxTun)(nil)

func (t *multiQueueLinuxTun) QueueCount() int { return len(t.queues) }

func (t *multiQueueLinuxTun) Queue(index int) tun.LinuxTUN {
	if index < 0 || index >= len(t.queues) {
		return nil
	}
	return t.queues[index]
}

func (t *multiQueueLinuxTun) Name() (string, error) { return t.name, nil }

func (t *multiQueueLinuxTun) Start() error {
	for index, queue := range t.queues {
		if err := queue.Start(); err != nil {
			for _, started := range t.queues[:index] {
				_ = started.Close()
			}
			return fmt.Errorf("start queue %d: %w", index, err)
		}
	}
	return nil
}

func (t *multiQueueLinuxTun) Close() error {
	var err error
	t.closeOnce.Do(func() {
		for _, queue := range t.queues {
			err = errors.Join(err, queue.Close())
		}
	})
	return err
}

func (t *multiQueueLinuxTun) UpdateRouteOptions(options tun.Options) error { return nil }

func (t *multiQueueLinuxTun) Read(p []byte) (int, error) {
	if len(t.queues) == 0 {
		return 0, os.ErrClosed
	}
	return t.queues[0].Read(p)
}

func (t *multiQueueLinuxTun) Write(p []byte) (int, error) {
	if len(t.queues) == 0 {
		return 0, os.ErrClosed
	}
	return t.queues[int(systemPacketFlowHash(p)%uint32(len(t.queues)))].Write(p)
}

func (t *multiQueueLinuxTun) FrontHeadroom() int { return t.queues[0].FrontHeadroom() }
func (t *multiQueueLinuxTun) BatchSize() int     { return t.queues[0].BatchSize() }
func (t *multiQueueLinuxTun) TXChecksumOffload() bool {
	return t.queues[0].TXChecksumOffload()
}
func (t *multiQueueLinuxTun) BatchRead(buffers [][]byte, offset int, readN []int) (int, error) {
	return t.queues[0].BatchRead(buffers, offset, readN)
}
func (t *multiQueueLinuxTun) BatchWrite(buffers [][]byte, offset int) (int, error) {
	if len(t.queues) == 0 {
		return 0, os.ErrClosed
	}
	if len(t.queues) == 1 {
		return t.queues[0].BatchWrite(buffers, offset)
	}
	workspace := t.writePool.Get().(*multiQueueWriteWorkspace)
	if cap(workspace.buffers) < len(t.queues) {
		workspace.buffers = make([][][]byte, len(t.queues))
	} else {
		workspace.buffers = workspace.buffers[:len(t.queues)]
	}
	for index := range workspace.buffers {
		workspace.buffers[index] = workspace.buffers[index][:0]
	}
	defer func() {
		for index := range workspace.buffers {
			clear(workspace.buffers[index])
			workspace.buffers[index] = workspace.buffers[index][:0]
		}
		t.writePool.Put(workspace)
	}()
	for _, packet := range buffers {
		payload := packet
		if offset > 0 && offset < len(packet) {
			payload = packet[offset:]
		}
		index := int(systemPacketFlowHash(payload) % uint32(len(t.queues)))
		workspace.buffers[index] = append(workspace.buffers[index], packet)
	}
	total := 0
	for index, queueBuffers := range workspace.buffers {
		if len(queueBuffers) == 0 {
			continue
		}
		written, err := t.queues[index].BatchWrite(queueBuffers, offset)
		total += written
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

type multiQueueWriteWorkspace struct {
	buffers [][][]byte
}

func desiredSystemTunQueues() int {
	queues := runtime.GOMAXPROCS(0)
	if value, err := strconv.Atoi(strings.TrimSpace(os.Getenv("SINGBOX_IWAN_TUN_QUEUES"))); err == nil && value > 0 {
		queues = value
	}
	if queues < 1 {
		queues = 1
	}
	if queues > 4 {
		queues = 4
	}
	return queues
}

func newSystemTun(options tun.Options) (tun.Tun, int, error) {
	queueCount := desiredSystemTunQueues()
	// The multi-queue wrapper intentionally owns only the minimal external
	// configuration needed by iWAN's system device.  Keep sing-tun's full
	// route/rule and network-namespace lifecycle whenever those options are in
	// use; this also makes the fallback semantics explicit for future callers.
	if queueCount > 1 && !options.AutoRoute && options.NetNs == "" {
		multi, err := newMultiQueueLinuxTun(options, queueCount)
		if err == nil {
			return multi, queueCount, nil
		}
		if options.Logger != nil {
			options.Logger.Debug("iWAN multi-queue TUN unavailable, falling back to single queue: ", err)
		}
	}
	device, err := tun.New(options)
	return device, 1, err
}

func newMultiQueueLinuxTun(options tun.Options, queueCount int) (*multiQueueLinuxTun, error) {
	if options.Name == "" {
		return nil, fmt.Errorf("multi-queue TUN requires a stable interface name")
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)
	if options.GSO {
		flags |= unix.IFF_VNET_HDR
	}
	controlPath := "/dev/net/tun"
	queues := make([]tun.LinuxTUN, 0, queueCount)
	actualName := options.Name
	for index := 0; index < queueCount; index++ {
		fd, name, err := openMultiQueueFD(controlPath, options.Name, flags)
		if err != nil {
			for _, queue := range queues {
				_ = queue.Close()
			}
			return nil, fmt.Errorf("open queue %d: %w", index, err)
		}
		if index == 0 {
			actualName = name
		}
		queueOptions := options
		queueOptions.Name = actualName
		queueOptions.FileDescriptor = fd
		queueOptions.EXP_ExternalConfiguration = true
		device, err := tun.New(queueOptions)
		if err != nil {
			_ = unix.Close(fd)
			for _, queue := range queues {
				_ = queue.Close()
			}
			return nil, fmt.Errorf("wrap queue %d: %w", index, err)
		}
		linuxQueue, ok := device.(tun.LinuxTUN)
		if !ok {
			_ = device.Close()
			for _, queue := range queues {
				_ = queue.Close()
			}
			return nil, fmt.Errorf("queue %d is not a LinuxTUN", index)
		}
		queues = append(queues, linuxQueue)
	}
	if err := configureMultiQueueLink(actualName, options); err != nil {
		for _, queue := range queues {
			_ = queue.Close()
		}
		return nil, err
	}
	return &multiQueueLinuxTun{
		queues: queues,
		name:   actualName,
		writePool: sync.Pool{New: func() any {
			return &multiQueueWriteWorkspace{buffers: make([][][]byte, queueCount)}
		}},
	}, nil
}

func openMultiQueueFD(path, name string, flags uint16) (int, string, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return -1, "", err
	}
	ifr.SetUint16(flags)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return -1, "", err
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return -1, "", err
	}
	return fd, ifr.Name(), nil
}

func configureMultiQueueLink(name string, options tun.Options) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find multi-queue TUN %s: %w", name, err)
	}
	if options.MTU != 0 {
		if err = netlink.LinkSetMTU(link, int(options.MTU)); err != nil && !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("set multi-queue TUN MTU: %w", err)
		}
	}
	for _, address := range options.Inet4Address {
		addr, parseErr := netlink.ParseAddr(address.String())
		if parseErr != nil {
			return parseErr
		}
		if err = netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("add multi-queue TUN IPv4 address: %w", err)
		}
	}
	for _, address := range options.Inet6Address {
		addr, parseErr := netlink.ParseAddr(address.String())
		if parseErr != nil {
			return parseErr
		}
		if err = netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("add multi-queue TUN IPv6 address: %w", err)
		}
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set multi-queue TUN up: %w", err)
	}
	// Match sing-tun's native Linux start path for the non-auto-route system
	// mode: inherited strict reverse-path filtering would otherwise drop
	// replies entering this interface before iWAN sees them.
	if content, readErr := os.ReadFile("/proc/sys/net/ipv4/conf/all/rp_filter"); readErr == nil {
		if value, parseErr := strconv.Atoi(strings.TrimSpace(string(content))); parseErr == nil && value == 1 {
			_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+name+"/rp_filter", []byte("2"), 0o644)
		}
	}
	return nil
}
