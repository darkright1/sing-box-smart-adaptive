//go:build with_iwan && linux

package iwan

import (
	"hash/fnv"
	"sync"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const systemDeviceMultiQueueShardCapacity = 256

// readLoopLinuxQueues gives every TUN queue its own reader.  Packets are then
// sharded by their 5-tuple into bounded workers.  A shard is the ordering
// domain: packets from one flow never race another worker, while unrelated
// UDP flows can be encrypted and sent in parallel.
func (d *systemDevice) readLoopLinuxQueues(device linuxTUNQueues, mtu int) {
	dispatcher := newSystemDevicePacketDispatcher(d, device.QueueCount(), mtu)
	var readers sync.WaitGroup
	errCh := make(chan error, 1)
	var stop sync.Once
	closeQueues := func() { stop.Do(func() { _ = device.Close() }) }
	for index := 0; index < device.QueueCount(); index++ {
		queue := device.Queue(index)
		readers.Add(1)
		go func() {
			defer readers.Done()
			d.readLoopLinuxQueue(queue, mtu, dispatcher, errCh, closeQueues)
		}()
	}
	readers.Wait()
	dispatcher.Close()
	select {
	case err := <-errCh:
		if !E.IsClosed(err) {
			d.options.Logger.Error(E.Cause(err, "multi-queue TUN packet worker"))
		}
	default:
	}
}

func (d *systemDevice) readLoopLinuxQueue(tunInterface tun.LinuxTUN, mtu int, dispatcher *systemDevicePacketDispatcher, errCh chan<- error, stop func()) {
	batchSize := tunInterface.BatchSize()
	packetBuffers := make([]*buf.Buffer, batchSize)
	readBuffers := make([][]byte, batchSize)
	packetSizes := make([]int, batchSize)
	for i := range packetBuffers {
		packetBuffers[i] = dispatcher.acquire()
	}
	defer buf.ReleaseMulti(packetBuffers)
	for {
		for i, packetBuffer := range packetBuffers {
			packetBuffer.Reset()
			packetBuffer.Resize(PacketHeadroom, 0)
			readBuffers[i] = packetBuffer.FreeBytes()[:mtu]
		}
		packetCount, readErr := tunInterface.BatchRead(readBuffers, 0, packetSizes)
		blockIPv6 := d.blockIPv6Enabled()
		for i := range packetCount {
			packetBuffer := packetBuffers[i]
			packetBuffer.Truncate(packetSizes[i])
			if blockIPv6 && header.IPVersion(packetBuffer.Bytes()) == header.IPv6Version {
				continue
			}
			// The reader owns packetBuffers for the next BatchRead. Detach an
			// accepted packet before handing it to a worker so a concurrent
			// worker can never observe the reader resetting/reusing its storage.
			packetBuffers[i] = dispatcher.acquire()
			packetBuffer.IncRef()
			if !dispatcher.Submit(packetBuffer) {
				packetBuffer.DecRef()
				dispatcher.recycle(packetBuffer)
			}
		}
		if readErr != nil {
			select {
			case errCh <- readErr:
			default:
			}
			stop()
			return
		}
	}
}

type systemDevicePacketDispatcher struct {
	device     *systemDevice
	shards     []chan *buf.Buffer
	bufferPool sync.Pool
	workers    sync.WaitGroup
	closed     chan struct{}
}

func newSystemDevicePacketDispatcher(device *systemDevice, shardCount, mtu int) *systemDevicePacketDispatcher {
	if shardCount < 1 {
		shardCount = 1
	}
	dispatcher := &systemDevicePacketDispatcher{
		device: device,
		shards: make([]chan *buf.Buffer, shardCount),
		closed: make(chan struct{}),
	}
	bufferSize := PacketHeadroom + mtu + systemDevicePacketRearSpace
	dispatcher.bufferPool.New = func() any { return buf.NewSize(bufferSize) }
	for i := range dispatcher.shards {
		dispatcher.shards[i] = make(chan *buf.Buffer, systemDeviceMultiQueueShardCapacity)
		dispatcher.workers.Add(1)
		go dispatcher.worker(dispatcher.shards[i])
	}
	return dispatcher
}

func (d *systemDevicePacketDispatcher) acquire() *buf.Buffer {
	packet := d.bufferPool.Get().(*buf.Buffer)
	packet.Reset()
	return packet
}

func (d *systemDevicePacketDispatcher) recycle(packet *buf.Buffer) {
	packet.Reset()
	d.bufferPool.Put(packet)
}

func (d *systemDevicePacketDispatcher) Submit(packet *buf.Buffer) bool {
	index := systemPacketFlowHash(packet.Bytes()) % uint32(len(d.shards))
	select {
	case d.shards[index] <- packet:
		return true
	case <-d.closed:
		return false
	default:
		return false
	}
}

func (d *systemDevicePacketDispatcher) Close() {
	select {
	case <-d.closed:
		return
	default:
		close(d.closed)
	}
	for _, shard := range d.shards {
		close(shard)
	}
	d.workers.Wait()
}

func (d *systemDevicePacketDispatcher) worker(shard <-chan *buf.Buffer) {
	defer d.workers.Done()
	for packet := range shard {
		batch := []*buf.Buffer{packet}
		for len(batch) < systemDeviceWriteBatchSize {
			select {
			case next := <-shard:
				if next == nil {
					goto flush
				}
				batch = append(batch, next)
			default:
				goto flush
			}
		}
	flush:
		if err := d.device.writeOutbound(batch); err != nil {
			d.device.options.Logger.Error(E.Cause(err, "write multi-queue packet batch"))
		}
		for _, item := range batch {
			item.DecRef()
			d.recycle(item)
		}
	}
}

func systemPacketFlowHash(packet []byte) uint32 {
	hash := fnv.New32a()
	if len(packet) == 0 {
		return 0
	}
	version := header.IPVersion(packet)
	if version == header.IPv4Version && len(packet) >= 20 {
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < 20 || headerLength > len(packet) {
			headerLength = 20
		}
		_, _ = hash.Write(packet[12:20])
		protocol := packet[9]
		_, _ = hash.Write([]byte{protocol})
		if (protocol == 6 || protocol == 17) && len(packet) >= headerLength+4 {
			_, _ = hash.Write(packet[headerLength : headerLength+4])
		}
		return hash.Sum32()
	}
	if version == header.IPv6Version && len(packet) >= 40 {
		_, _ = hash.Write(packet[8:40])
		protocol := packet[6]
		_, _ = hash.Write([]byte{protocol})
		if (protocol == 6 || protocol == 17) && len(packet) >= 44 {
			_, _ = hash.Write(packet[40:44])
		}
		return hash.Sum32()
	}
	_, _ = hash.Write(packet)
	return hash.Sum32()
}
