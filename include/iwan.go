//go:build with_iwan

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerIWANEndpoint(registry *endpoint.Registry) {
	// Keep the private build fail-closed until the Router-backed transport
	// adapter is complete. The protocol codec is available to the private
	// integration tests under with_iwan, but a half-wired endpoint must never
	// enter a production binary.
	endpoint.RegisterUnsupported[option.IWANEndpointOptions](registry, C.TypeIWAN, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.IWANEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New("private iWAN transport adapter is not production-ready")
	})
}
