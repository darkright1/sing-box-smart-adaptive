//go:build with_iwan && !linux

package iwan

func tuneSystemTunQueue(string) error { return nil }
