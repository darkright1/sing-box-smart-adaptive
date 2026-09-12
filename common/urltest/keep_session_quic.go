//go:build with_quic

package urltest

import (
	"context"
)

func contextWithQUICKeepSession(ctx context.Context) context.Context {
	// sing-quic 1.15 no longer exposes a keep-session context marker.  Keep the
	// helper so callers remain version-neutral; the transport owns reuse.
	return ctx
}
