//go:build with_iwan

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/protocol/iwan"
)

func registerIWANEndpoint(registry *endpoint.Registry) {
	iwan.RegisterEndpoint(registry)
}
