package option

import (
	"github.com/sagernet/sing-box/common/json"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type _Outbound struct {
	Type                  string                        `json:"type"`
	Tag                   string                        `json:"tag,omitempty"`
	DirectOptions         DirectOutboundOptions         `json:"-"`
	SocksOptions          SocksOutboundOptions          `json:"-"`
	HTTPOptions           HTTPOutboundOptions           `json:"-"`
	ShadowsocksOptions    ShadowsocksOutboundOptions    `json:"-"`
	VMessOptions          VMessOutboundOptions          `json:"-"`
	TrojanOptions         TrojanOutboundOptions         `json:"-"`
	WireGuardOptions      WireGuardOutboundOptions      `json:"-"`
	HysteriaOptions       HysteriaOutboundOptions       `json:"-"`
	TorOptions            TorOutboundOptions            `json:"-"`
	SSHOptions            SSHOutboundOptions            `json:"-"`
	ShadowTLSOptions      ShadowTLSOutboundOptions      `json:"-"`
	ShadowsocksROptions   ShadowsocksROutboundOptions   `json:"-"`
	VLESSOptions          VLESSOutboundOptions          `json:"-"`
	SelectorOptions       SelectorOutboundOptions       `json:"-"`
	URLTestOptions        URLTestOutboundOptions        `json:"-"`
	DynamicURLTestOptions DynamicURLTestOutboundOptions `json:"-"`
}

type Outbound _Outbound

func (h Outbound) MarshalJSON() ([]byte, error) {
	var v any
	switch h.Type {
	case C.TypeDirect:
		v = h.DirectOptions
	case C.TypeBlock, C.TypeDNS:
		v = nil
	case C.TypeSocks:
		v = h.SocksOptions
	case C.TypeHTTP:
		v = h.HTTPOptions
	case C.TypeShadowsocks:
		v = h.ShadowsocksOptions
	case C.TypeVMess:
		v = h.VMessOptions
	case C.TypeTrojan:
		v = h.TrojanOptions
	case C.TypeWireGuard:
		v = h.WireGuardOptions
	case C.TypeHysteria:
		v = h.HysteriaOptions
	case C.TypeTor:
		v = h.TorOptions
	case C.TypeSSH:
		v = h.SSHOptions
	case C.TypeShadowTLS:
		v = h.ShadowTLSOptions
	case C.TypeShadowsocksR:
		v = h.ShadowsocksROptions
	case C.TypeVLESS:
		v = h.VLESSOptions
	case C.TypeSelector:
		v = h.SelectorOptions
	case C.TypeURLTest:
		v = h.URLTestOptions
	case C.TypeDynamicURLTest:
		v = h.DynamicURLTestOptions
	default:
		return nil, E.New("unknown outbound type: ", h.Type)
	}
	return MarshallObjects((_Outbound)(h), v)
}

func (h *Outbound) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_Outbound)(h))
	if err != nil {
		return err
	}
	var v any
	switch h.Type {
	case C.TypeDirect:
		v = &h.DirectOptions
	case C.TypeBlock, C.TypeDNS:
		v = nil
	case C.TypeSocks:
		v = &h.SocksOptions
	case C.TypeHTTP:
		v = &h.HTTPOptions
	case C.TypeShadowsocks:
		v = &h.ShadowsocksOptions
	case C.TypeVMess:
		v = &h.VMessOptions
	case C.TypeTrojan:
		v = &h.TrojanOptions
	case C.TypeWireGuard:
		v = &h.WireGuardOptions
	case C.TypeHysteria:
		v = &h.HysteriaOptions
	case C.TypeTor:
		v = &h.TorOptions
	case C.TypeSSH:
		v = &h.SSHOptions
	case C.TypeShadowTLS:
		v = &h.ShadowTLSOptions
	case C.TypeShadowsocksR:
		v = &h.ShadowsocksROptions
	case C.TypeVLESS:
		v = &h.VLESSOptions
	case C.TypeSelector:
		v = &h.SelectorOptions
	case C.TypeURLTest:
		v = &h.URLTestOptions
	case C.TypeDynamicURLTest:
		v = &h.DynamicURLTestOptions
	default:
		return E.New("unknown outbound type: ", h.Type)
	}
	err = UnmarshallExcluded(bytes, (*_Outbound)(h), v)
	if err != nil {
		return E.Cause(err, "outbound options")
	}
	return nil
}

func (h *Outbound) SetDetour(detour string) {
	switch h.Type {
	case C.TypeDirect:
		h.DirectOptions.Detour = detour
	case C.TypeBlock, C.TypeDNS:
	case C.TypeSocks:
		h.SocksOptions.Detour = detour
	case C.TypeHTTP:
		h.HTTPOptions.Detour = detour
	case C.TypeShadowsocks:
		h.ShadowsocksOptions.Detour = detour
	case C.TypeVMess:
		h.VMessOptions.Detour = detour
	case C.TypeTrojan:
		h.TrojanOptions.Detour = detour
	case C.TypeWireGuard:
		h.WireGuardOptions.Detour = detour
	case C.TypeHysteria:
		h.HysteriaOptions.Detour = detour
	case C.TypeTor:
		h.TorOptions.Detour = detour
	case C.TypeSSH:
		h.SSHOptions.Detour = detour
	case C.TypeShadowTLS:
		h.ShadowTLSOptions.Detour = detour
	case C.TypeShadowsocksR:
		h.ShadowsocksROptions.Detour = detour
	case C.TypeVLESS:
		h.VLESSOptions.Detour = detour
	case C.TypeSelector:
	case C.TypeURLTest:
	case C.TypeDynamicURLTest:
	default:
	}
}

func (h *Outbound) ReplaceServer(server string, serverPort uint16) {
	switch h.Type {
	case C.TypeDirect:
	case C.TypeBlock, C.TypeDNS:
	case C.TypeSocks:
		h.SocksOptions.Server, h.SocksOptions.ServerPort = server, serverPort
	case C.TypeHTTP:
		h.HTTPOptions.Server, h.HTTPOptions.ServerPort = server, serverPort
	case C.TypeShadowsocks:
		h.ShadowsocksOptions.Server, h.ShadowsocksOptions.ServerPort = server, serverPort
	case C.TypeVMess:
		h.VMessOptions.Server, h.VMessOptions.ServerPort = server, serverPort
	case C.TypeTrojan:
		h.TrojanOptions.Server, h.TrojanOptions.ServerPort = server, serverPort
	case C.TypeWireGuard:
		h.WireGuardOptions.Server, h.WireGuardOptions.ServerPort = server, serverPort
	case C.TypeHysteria:
		h.HysteriaOptions.Server, h.HysteriaOptions.ServerPort = server, serverPort
	case C.TypeTor:
	case C.TypeSSH:
		h.SSHOptions.Server, h.SSHOptions.ServerPort = server, serverPort
	case C.TypeShadowTLS:
		h.ShadowTLSOptions.Server, h.ShadowTLSOptions.ServerPort = server, serverPort
	case C.TypeShadowsocksR:
		h.ShadowsocksROptions.Server, h.ShadowsocksROptions.ServerPort = server, serverPort
	case C.TypeVLESS:
		h.VLESSOptions.Server, h.VLESSOptions.ServerPort = server, serverPort
	case C.TypeSelector:
	case C.TypeURLTest:
	case C.TypeDynamicURLTest:
	default:
	}
}

func (h *Outbound) TargetInfo() (scheme, host string, port uint16) {
	switch h.Type {
	case C.TypeDirect:
	case C.TypeBlock, C.TypeDNS:
	case C.TypeSocks:
		scheme, host, port = C.TypeSocks, h.SocksOptions.Server, h.SocksOptions.ServerPort
	case C.TypeHTTP:
		scheme, host, port = C.TypeHTTP, h.HTTPOptions.Server, h.HTTPOptions.ServerPort
	case C.TypeShadowsocks:
		scheme, host, port = C.TypeShadowsocks, h.ShadowsocksOptions.Server, h.ShadowsocksOptions.ServerPort
	case C.TypeVMess:
		scheme, host, port = C.TypeVMess, h.VMessOptions.Server, h.VMessOptions.ServerPort
	case C.TypeTrojan:
		scheme, host, port = C.TypeTrojan, h.TrojanOptions.Server, h.TrojanOptions.ServerPort
	case C.TypeWireGuard:
		scheme, host, port = C.TypeWireGuard, h.WireGuardOptions.Server, h.WireGuardOptions.ServerPort
	case C.TypeHysteria:
		scheme, host, port = C.TypeHysteria, h.HysteriaOptions.Server, h.HysteriaOptions.ServerPort
	case C.TypeTor:
	case C.TypeSSH:
		scheme, host, port = C.TypeSSH, h.SSHOptions.Server, h.SSHOptions.ServerPort
	case C.TypeShadowTLS:
		scheme, host, port = C.TypeShadowTLS, h.ShadowTLSOptions.Server, h.ShadowTLSOptions.ServerPort
	case C.TypeShadowsocksR:
		scheme, host, port = C.TypeShadowsocksR, h.ShadowsocksROptions.Server, h.ShadowsocksROptions.ServerPort
	case C.TypeVLESS:
		scheme, host, port = C.TypeVLESS, h.VLESSOptions.Server, h.VLESSOptions.ServerPort
	case C.TypeSelector:
	case C.TypeURLTest:
	case C.TypeDynamicURLTest:
	default:
	}
	return
}

type DialerOptions struct {
	Detour             string         `json:"detour,omitempty"`
	BindInterface      string         `json:"bind_interface,omitempty"`
	Inet4BindAddress   *ListenAddress `json:"inet4_bind_address,omitempty"`
	Inet6BindAddress   *ListenAddress `json:"inet6_bind_address,omitempty"`
	ProtectPath        string         `json:"protect_path,omitempty"`
	RoutingMark        int            `json:"routing_mark,omitempty"`
	ReuseAddr          bool           `json:"reuse_addr,omitempty"`
	ConnectTimeout     Duration       `json:"connect_timeout,omitempty"`
	TCPFastOpen        bool           `json:"tcp_fast_open,omitempty"`
	UDPFragment        *bool          `json:"udp_fragment,omitempty"`
	UDPFragmentDefault bool           `json:"-"`
	DomainStrategy     DomainStrategy `json:"domain_strategy,omitempty"`
	FallbackDelay      Duration       `json:"fallback_delay,omitempty"`
}

type ServerOptions struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}

func (o ServerOptions) Build() M.Socksaddr {
	return M.ParseSocksaddrHostPort(o.Server, o.ServerPort)
}

type MultiplexOptions struct {
	Enabled        bool   `json:"enabled,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	MaxConnections int    `json:"max_connections,omitempty"`
	MinStreams     int    `json:"min_streams,omitempty"`
	MaxStreams     int    `json:"max_streams,omitempty"`
}
