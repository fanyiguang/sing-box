package parser

import (
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/exceptions"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

func GetInboundFromURL(url *url.URL, index int) (option.Inbound, error) {
	switch strings.ToLower(url.Scheme) {
	case constant.TypeSOCKS, "socks5":
		return parseInboundSocks(url, index, false)
	//case "ssl":
	//	return parseInboundSocks(url, index, true)
	case constant.TypeMixed, "auto":
		return parseInboundMixed(url, index)
	case constant.TypeHTTP:
		return parseInboundHttp(url, index, false)
	case "https":
		return parseInboundHttp(url, index, true)
	default:
		return option.Inbound{}, exceptions.New("unknown inbound type ", url.Scheme)
	}
}

func parseInboundSocks(url *url.URL, index int, enableTLS bool) (option.Inbound, error) {
	var user []auth.User
	auth := GetAuthInfoFromUrl(url)
	if auth != nil {
		user = append(user, *auth)
	}

	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Inbound{}, err
	}

	//var tls *option.InboundTLSOptions
	//if enableTLS {
	//	tls = &option.InboundTLSOptions{
	//		Enabled:  true,
	//		Insecure: true,
	//	}
	//}
	return option.Inbound{
		Type: constant.TypeSOCKS,
		Tag:  constant.TypeSOCKS + strconv.Itoa(index),
		SocksOptions: option.SocksInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     option.NewListenAddress(addr),
				ListenPort: port,
			},
			Users: user,
			//TLS:   tls,
		},
	}, nil
}

func GetHostAndPortFromUrl(url *url.URL) (netip.Addr, uint16, error) {
	host, p, err := net.SplitHostPort(url.Host)
	if err != nil {
		return netip.Addr{}, 0, exceptions.Cause(err, "get inbound config error")
	}

	if host == "" {
		host = "127.0.0.1"
	}

	port, err := strconv.Atoi(p)
	if err != nil {
		return netip.Addr{}, 0, exceptions.Cause(err, p, "is not number")
	}
	if port >= 65535 || port <= 0 {
		return netip.Addr{}, 0, exceptions.New(p, "is not in range [1-65535]")
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, exceptions.New("error ip addr: ", host)
	}
	return addr, uint16(port), nil
}

func GetAuthInfoFromUrl(url *url.URL) *auth.User {
	if url.User != nil {
		username := url.User.Username()
		password, set := url.User.Password()
		if !set {
			password = ""
		}
		return &auth.User{
			Username: username,
			Password: password,
		}
	}

	return nil
}

func parseInboundMixed(url *url.URL, index int) (option.Inbound, error) {
	var user []auth.User
	auth := GetAuthInfoFromUrl(url)
	if auth != nil {
		user = append(user, *auth)
	}

	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Inbound{}, err
	}
	return option.Inbound{
		Type: constant.TypeMixed,
		Tag:  constant.TypeMixed + strconv.Itoa(index),
		MixedOptions: option.HTTPMixedInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     option.NewListenAddress(addr),
				ListenPort: port,
			},
			Users: user,
		},
	}, nil
}

func parseInboundHttp(url *url.URL, index int, enableTLS bool) (option.Inbound, error) {
	var user []auth.User
	auth := GetAuthInfoFromUrl(url)
	if auth != nil {
		user = append(user, *auth)
	}

	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Inbound{}, err
	}

	var tls *option.InboundTLSOptions

	if enableTLS {
		tls = &option.InboundTLSOptions{
			Enabled:  true,
			Insecure: true,
		}
	}

	return option.Inbound{
		Type: constant.TypeMixed,
		Tag:  constant.TypeMixed + strconv.Itoa(index),
		HTTPOptions: option.HTTPMixedInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     option.NewListenAddress(addr),
				ListenPort: port,
			},
			Users:                      user,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: tls},
		},
	}, nil
}

func GetOutboundFromURL(url *url.URL, index int, detourName string) (option.Outbound, error) {
	switch strings.ToLower(url.Scheme) {
	case constant.TypeSOCKS, "socks5", "auto":
		return parseOutboundSocks(url, index, detourName, false)
	case "ssl":
		return parseOutboundSocks(url, index, detourName, true)
	case constant.TypeHTTP:
		return parseOutboundHttp(url, index, detourName, false)
	case "https":
		return parseOutboundHttp(url, index, detourName, true)
	case "ssh", "sshd":
		return parseOutboundSSH(url, index, detourName)
	case "ss", "shadowsocks":
		return parseOutboundSS(url, index, detourName)
	default:
		return option.Outbound{}, exceptions.New("unknown outbound type ", url.Scheme)
	}
}

func parseOutboundSocks(url *url.URL, index int, detourName string, enableTLS bool) (option.Outbound, error) {
	auth := GetAuthInfoFromUrl(url)

	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Outbound{}, err
	}

	var tls *option.OutboundTLSOptions
	if enableTLS {
		tls = &option.OutboundTLSOptions{
			Enabled:  true,
			Insecure: true,
		}
	}

	c := option.Outbound{
		Type: constant.TypeSOCKS,
		Tag:  "jump-" + strconv.Itoa(index),
		SocksOptions: option.SocksOutboundOptions{
			DialerOptions: option.DialerOptions{
				Detour: detourName,
			},
			ServerOptions: option.ServerOptions{
				Server:     addr.String(),
				ServerPort: port,
			},
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
		},
	}
	if auth != nil {
		c.SocksOptions.Username = auth.Username
		c.SocksOptions.Password = auth.Password
	}
	return c, nil
}

func parseOutboundSSH(url *url.URL, index int, detourName string) (option.Outbound, error) {
	auth := GetAuthInfoFromUrl(url)

	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Outbound{}, err
	}

	c := option.Outbound{
		Type: constant.TypeSSH,
		Tag:  "jump-" + strconv.Itoa(index),
		SSHOptions: option.SSHOutboundOptions{
			DialerOptions: option.DialerOptions{
				Detour: detourName,
			},
			ServerOptions: option.ServerOptions{
				Server:     addr.String(),
				ServerPort: port,
			},
		},
	}
	if auth != nil {
		c.SSHOptions.User = auth.Username
		c.SSHOptions.Password = auth.Password
	}

	return c, nil
}

func parseOutboundSS(url *url.URL, index int, detourName string) (option.Outbound, error) {
	auth := GetAuthInfoFromUrl(url)
	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Outbound{}, err
	}

	c := option.Outbound{
		Type: constant.TypeShadowsocks,
		Tag:  "jump-" + strconv.Itoa(index),
		ShadowsocksOptions: option.ShadowsocksOutboundOptions{
			DialerOptions: option.DialerOptions{
				Detour: detourName,
			},
			ServerOptions: option.ServerOptions{
				Server:     addr.String(),
				ServerPort: port,
			},
		},
	}
	if auth != nil {
		c.ShadowsocksOptions.Method = auth.Username
		c.ShadowsocksOptions.Password = auth.Password
	}
	t := url.Query().Get("tolerance")
	if t != "" {
		tolerance, err := strconv.Atoi(t)
		if err != nil {
			return option.Outbound{}, err
		}
		if tolerance > 0 {
			c.ShadowsocksOptions.Tolerance = tolerance
		}
	}
	return c, nil
}

func parseOutboundHttp(url *url.URL, index int, detourName string, enableTLS bool) (option.Outbound, error) {
	auth := GetAuthInfoFromUrl(url)

	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Outbound{}, err
	}

	var tls *option.OutboundTLSOptions
	if enableTLS {
		tls = &option.OutboundTLSOptions{
			Enabled:  true,
			Insecure: true,
		}
	}

	c := option.Outbound{
		Type: constant.TypeHTTP,
		Tag:  "jump-" + strconv.Itoa(index),
		HTTPOptions: option.HTTPOutboundOptions{
			DialerOptions: option.DialerOptions{
				Detour: detourName,
			},
			ServerOptions: option.ServerOptions{
				Server:     addr.String(),
				ServerPort: port,
			},
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
		},
	}
	if auth != nil {
		c.HTTPOptions.Username = auth.Username
		c.HTTPOptions.Password = auth.Password
	}
	return c, nil
}
