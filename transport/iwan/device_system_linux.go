//go:build with_iwan && linux

package iwan

import "github.com/sagernet/netlink"

// A native TUN defaults to a very small pfifo queue (often 500 packets).  At
// high-PPS UDP rates that queue drops bursts before the synchronous BatchWrite
// path can drain them. Keep a bounded queue: it absorbs scheduler bursts
// without turning sustained overload into unbounded memory growth.
func tuneSystemTunQueue(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetTxQLen(link, 10000)
}
