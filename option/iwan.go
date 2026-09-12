package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
)

// IWANEndpointOptions describes the private iWAN endpoint contract.  The
// protocol is intentionally kept behind the with_iwan build tag; schema
// parsing remains available in every build so a missing feature produces a
// deterministic unsupported-endpoint error instead of an unknown type error.
//
// Client and server use the same endpoint type and select their role with
// mode.  No external iWAN process is started by sing-box.
type IWANEndpointOptions struct {
	Mode       string                           `json:"mode,omitempty" enum:"client,server"`
	System     bool                             `json:"system,omitempty"`
	Name       string                           `json:"name,omitempty"`
	MTU        uint32                           `json:"mtu,omitempty"`
	Address    badoption.Listable[netip.Prefix] `json:"address,omitempty"`
	Listen     ListenOptions                    `json:"listen,omitempty"`
	Server     string                           `json:"server,omitempty"`
	ServerPort uint16                           `json:"server_port,omitempty"`
	Username   string                           `json:"username,omitempty"`
	Password   string                           `json:"password,omitempty"`
	SRPassword string                           `json:"sr_password,omitempty"`
	Encrypt    bool                             `json:"encrypt,omitempty"`
	PipeID     uint16                           `json:"pipe_id,omitempty"`
	PipeIndex  uint16                           `json:"pipe_index,omitempty"`
	Links      []uint32                         `json:"links,omitempty"`
	PoolCIDR   string                           `json:"pool,omitempty"`
	Gateway    *badoption.Addr                  `json:"gateway,omitempty"`
	DNS        badoption.Listable[netip.Addr]   `json:"dns,omitempty"`
	Users      []auth.User                      `json:"users,omitempty"`
	DialerOptions
}
