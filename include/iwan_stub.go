//go:build !with_iwan

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
	endpoint.RegisterUnsupported[option.IWANEndpointOptions](registry, C.TypeIWAN, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.IWANEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New("iWAN is private and not included in this build, rebuild with -tags with_iwan")
	})
}
