//go:build with_iwan && !linux

package iwan

import "github.com/sagernet/sing-tun"

func tuneSystemTunQueue(string) error { return nil }

type linuxTUNQueues interface {
	tun.LinuxTUN
	QueueCount() int
	Queue(index int) tun.LinuxTUN
}

func newSystemTun(options tun.Options) (tun.Tun, int, error) {
	device, err := tun.New(options)
	return device, 1, err
}

func (d *systemDevice) readLoopLinuxQueues(_ linuxTUNQueues, _ int) {}
