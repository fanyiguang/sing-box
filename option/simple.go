package option

import "github.com/sagernet/sing/common/auth"

type SocksInboundOptions struct {
	ListenOptions
	Users []auth.User        `json:"users,omitempty"`
	TLS   *InboundTLSOptions `json:"tls,omitempty"`
}

type HTTPMixedInboundOptions struct {
	ListenOptions
	Users          []auth.User `json:"users,omitempty"`
	SetSystemProxy bool        `json:"set_system_proxy,omitempty"`
	InboundTLSOptionsContainer
}

type SocksOutboundOptions struct {
	DialerOptions
	ServerOptions
	Version    string             `json:"version,omitempty"`
	Username   string             `json:"username,omitempty"`
	Password   string             `json:"password,omitempty"`
	Network    NetworkList        `json:"network,omitempty"`
	UseAddr    bool               `json:"user_addr,omitempty"`
	UDPOverTCP *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
	OutboundTLSOptionsContainer
}

type HTTPOutboundOptions struct {
	DialerOptions
	ServerOptions
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	OutboundTLSOptionsContainer
	Path           string     `json:"path,omitempty"`
	Headers        HTTPHeader `json:"headers,omitempty"`
	EnableAutoMode bool       `json:"auto_mode,omitempty"`
}

type SystemOutboundOptions struct {
	DialerOptions
	PacEngine      string `json:"pac_engine"`      // system or javascript, default: javascript
	ReloadInterval int    `json:"reload_interval"` // unit：second, default 3 second
}
