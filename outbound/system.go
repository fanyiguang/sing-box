package outbound

import (
	"context"
	"errors"
	"fmt"
	"github.com/darren/gpac"
	"github.com/mattn/go-ieproxy"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/json"
	"github.com/sagernet/sing-box/common/parser"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/idna"
	"golang.org/x/sync/singleflight"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var _ adapter.Outbound = (*System)(nil)

type System struct {
	myOutboundAdapter
	rmt            sync.RWMutex
	sysProxyConf   ieproxy.ProxyConf
	outbounds      sync.Map
	dialerOptions  option.DialerOptions
	singleFlight   singleflight.Group
	gpacParser     *gpac.Parser
	doneCh         chan struct{}
	pacEngine      string // javascript or system, default: javascript
	reloadInterval int
	pacEnable      bool
	enable         bool
}

func NewSystem(router adapter.Router, logger log.ContextLogger, tag string, options option.SystemOutboundOptions) (*System, error) {
	return &System{
		myOutboundAdapter: myOutboundAdapter{
			protocol: C.TypeSystem,
			network:  []string{N.NetworkTCP},
			router:   router,
			logger:   logger,
			tag:      tag,
		},
		dialerOptions:  options.DialerOptions,
		doneCh:         make(chan struct{}),
		pacEngine:      options.PacEngine,
		reloadInterval: options.ReloadInterval,
	}, nil
}

func (s *System) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !s.enable {
		return nil, E.New("system proxy is disable")
	}
	sysConf := s.loadConf()

	var (
		err  = E.New("system proxy error")
		conn net.Conn
	)
	if s.pacEnable { // pac模式
		conn, err = s.pacDialContext(ctx, network, destination, sysConf)
		if err == nil {
			return conn, nil
		}
	}

	if sysConf.Static.Active { // 静态模式
		return s.staticDialContext(ctx, network, destination, sysConf)
	}

	return nil, err
}

func (s *System) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (s *System) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, s, conn, metadata)
}

func (s *System) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return os.ErrInvalid
}

func (s *System) storeConf(conf ieproxy.ProxyConf) {
	s.rmt.Lock()
	defer s.rmt.Unlock()
	s.sysProxyConf = conf
}

func (s *System) loadConf() ieproxy.ProxyConf {
	s.rmt.RLock()
	defer s.rmt.RUnlock()
	return s.sysProxyConf
}

func (s *System) storeGpacParser(parser *gpac.Parser) {
	s.rmt.Lock()
	defer s.rmt.Unlock()
	s.gpacParser = parser
}

func (s *System) loadGpacParser() *gpac.Parser {
	s.rmt.RLock()
	defer s.rmt.RUnlock()
	return s.gpacParser
}

func (s *System) isJavascriptEngine() bool {
	return s.pacEngine == C.PacEngineJavascript || s.pacEngine == "" // default: javascript engine
}

func (s *System) loadSystemProxy() (err error) {
	sysProxyConf := ieproxy.ReloadConf()
	if sysProxyConf.Automatic.Active && s.isJavascriptEngine() {
		parser, err := gpac.FromURL(sysProxyConf.Automatic.PreConfiguredURL)
		if err != nil {
			s.pacEnable = false
			s.logger.Warn("gpac parser pac file from url error: ", err)
		} else {
			s.pacEnable = true
			s.storeGpacParser(parser)
		}
	}

	if reflect.DeepEqual(sysProxyConf, s.loadConf()) {
		return
	}

	sysConf, _ := json.Marshal(sysProxyConf)
	s.logger.Info("load system config: ", string(sysConf))
	s.storeConf(sysProxyConf)
	if sysProxyConf.Automatic.Active { // pac模式
		s.pacEnable = true
		s.setEnable(true)
		s.logger.Info("switch to pac mode")
		return
	} else {
		s.pacEnable = false
	}

	if sysProxyConf.Static.Active { // 静态模式
		for t := range sysProxyConf.Static.Protocols {
			switch strings.ToLower(t) {
			case "https":
				s.setEnable(true)
				s.logger.Info("switch to HTTPS static mode")
				return
			case C.TypeHTTP, "":
				s.setEnable(true)
				s.logger.Info("switch to HTTP static mode")
				return
			case C.TypeSocks:
				s.setEnable(true)
				s.logger.Info("switch to SOCKS static mode")
				return
			default:
				s.logger.Info("unsupported type: ", t)
				s.setEnable(false)
			}
		}
	}

	s.logger.Info("closed system proxy")
	s.setEnable(false)
	return
}

func (s *System) setEnable(b bool) {
	s.enable = b
}

func (s *System) Start() error {
	err := s.loadSystemProxy()
	if err != nil {
		return err
	}
	go s.reloadLoop()
	return nil
}

func (s *System) Close() error {
	select {
	case <-s.doneCh:
		return E.New("closed")
	default:
		close(s.doneCh)
	}
	return nil
}

func (s *System) reloadLoop() {
	if s.reloadInterval <= 0 {
		s.reloadInterval = 2
	}
	ticker := time.NewTicker(time.Duration(s.reloadInterval) * time.Second)
	for true {
		select {
		case <-ticker.C:
			err := s.loadSystemProxy()
			if err != nil {
				s.logger.Error("load system proxy error:", err)
				continue
			}
			//s.logger.Debug("execute reload loop")
		case <-s.doneCh:
			s.logger.Info("reload loop end")
			return
		}
	}
}

func (s *System) pacDialContext(ctx context.Context, network string, destination M.Socksaddr, conf ieproxy.ProxyConf) (net.Conn, error) {
	URLs, err := s.findProxyForURL(destination, conf)
	if err != nil {
		return nil, err
	}
	for _, URL := range URLs {
		URLParse, err := url.Parse(URL)
		if err != nil {
			s.logger.WarnContext(ctx, "url parse error: ", err)
			continue
		}

		if outbound, ok := s.outbounds.Load(URL); !ok {
			var (
				err      error
				outbound interface{}
			)
			switch URLParse.Scheme {
			case C.TypeHTTP:
				outbound, err, _ = s.singleFlight.Do(URL, func() (interface{}, error) {
					httpOption, err := parser.GetOutboundFromURL(URLParse, 1, "")
					if err != nil {
						return nil, err
					}
					httpOption.HTTPOptions.DialerOptions = s.dialerOptions
					http, err := NewHTTP(s.router, s.logger, httpOption.Tag, httpOption.HTTPOptions)
					if err != nil {
						return nil, err
					}
					s.outbounds.Store(URL, http)
					return http, nil
				})
			case "https":
				outbound, err, _ = s.singleFlight.Do(URL, func() (interface{}, error) {
					httpOption, err := parser.GetOutboundFromURL(URLParse, 1, "")
					if err != nil {
						return nil, err
					}
					httpOption.HTTPOptions.DialerOptions = s.dialerOptions
					http, err := NewHTTP(s.router, s.logger, httpOption.Tag, httpOption.HTTPOptions)
					if err != nil {
						return nil, err
					}
					s.outbounds.Store(URL, http)
					return http, nil
				})
			case C.TypeSocks, "socks5":
				outbound, err, _ = s.singleFlight.Do(URL, func() (interface{}, error) {
					socksOption, err := parser.GetOutboundFromURL(URLParse, 1, "")
					if err != nil {
						return nil, err
					}
					socksOption.SocksOptions.DialerOptions = s.dialerOptions
					socks, err := NewSocks(s.router, s.logger, socksOption.Tag, socksOption.SocksOptions)
					if err != nil {
						return nil, err
					}
					s.outbounds.Store(URL, socks)
					return socks, nil
				})
			case C.TypeDirect:
				outbound, err, _ = s.singleFlight.Do(URL, func() (interface{}, error) {
					directOption, err := parser.GetOutboundFromURL(URLParse, 1, "")
					if err != nil {
						return nil, err
					}
					directOption.DirectOptions.DialerOptions = s.dialerOptions
					direct, err := NewDirect(s.router, s.logger, directOption.Tag, directOption.DirectOptions)
					if err != nil {
						return nil, err
					}
					s.outbounds.Store(URL, direct)
					return direct, nil
				})
			default:
				err = E.New("unknown protocol type: ", URLParse.Scheme)
			}
			if err != nil {
				s.logger.WarnContext(ctx, err)
				continue
			}
			if aOutbound, okk := outbound.(adapter.Outbound); okk {
				conn, err := aOutbound.DialContext(ctx, network, destination)
				if err == nil {
					return conn, nil
				}
				s.logger.WarnContext(ctx, "outbound: ", aOutbound.Tag(), " dialContext error: ", err)
			}
		} else {
			if aOutbound, okk := outbound.(adapter.Outbound); okk {
				conn, err := aOutbound.DialContext(ctx, network, destination)
				if err == nil {
					return conn, nil
				}
				s.logger.WarnContext(ctx, "outbound: ", aOutbound.Tag(), " dialContext error: ", err)
			}
		}
	}
	return nil, E.New("no available outbound")
}

func (s *System) staticDialContext(ctx context.Context, network string, destination M.Socksaddr, conf ieproxy.ProxyConf) (conn net.Conn, err error) {
	if !s.useProxy(destination.String()) {
		return nil, E.New("filtered by blacklist")
	}

	for t, proxy := range conf.Static.Protocols {
		switch strings.ToLower(t) {
		case "https":
			proxyKey := fmt.Sprintf("%v://%v", t, proxy)
			if outbounds, ok := s.outbounds.Load(proxyKey); !ok {
				_outbounds, err, _ := s.singleFlight.Do(proxyKey, func() (interface{}, error) {
					if index := strings.Index(proxy, "://"); index != -1 {
						proxy = proxy[index+len("://"):]
					}
					httpsOutbound, err := s.createOutbound(fmt.Sprintf("https://%v", proxy))
					if err != nil {
						return nil, err
					}
					httpOutbound, err := s.createOutbound(fmt.Sprintf("http://%v", proxy))
					if err != nil {
						return nil, err
					}
					socks5Outbound, err := s.createOutbound(fmt.Sprintf("socks5://%v", proxy))
					if err != nil {
						return nil, err
					}

					jng := []adapter.Outbound{httpsOutbound, httpOutbound, socks5Outbound}
					s.outbounds.Store(proxyKey, jng)
					return jng, nil
				})
				if err != nil {
					s.logger.WarnContext(ctx, "instantiation HTTPS error: ", err)
					continue
				}
				return s.dialContext(ctx, _outbounds, network, destination)
			} else {
				return s.dialContext(ctx, outbounds, network, destination)
			}
		case C.TypeHTTP, "":
			proxyKey := fmt.Sprintf("%v://%v", t, proxy)
			if outbounds, ok := s.outbounds.Load(proxyKey); !ok {
				_outbounds, err, _ := s.singleFlight.Do(proxyKey, func() (interface{}, error) {
					if index := strings.Index(proxy, "://"); index != -1 {
						proxy = proxy[index+len("://"):]
					}
					httpOutbound, err := s.createOutbound(fmt.Sprintf("http://%v", proxy))
					if err != nil {
						return nil, err
					}
					socks5Outbound, err := s.createOutbound(fmt.Sprintf("socks5://%v", proxy))
					if err != nil {
						return nil, err
					}

					pkq := []adapter.Outbound{httpOutbound, socks5Outbound}
					s.outbounds.Store(proxyKey, pkq)
					return pkq, nil
				})
				if err != nil {
					s.logger.WarnContext(ctx, "instantiation HTTP error: ", err)
					continue
				}
				return s.dialContext(ctx, _outbounds, network, destination)
			} else {
				return s.dialContext(ctx, outbounds, network, destination)
			}
		case C.TypeSocks:
			proxyKey := fmt.Sprintf("%v://%v", t, proxy)
			if outbounds, ok := s.outbounds.Load(proxyKey); !ok {
				_outbounds, err, _ := s.singleFlight.Do(proxyKey, func() (interface{}, error) {
					if index := strings.Index(proxy, "://"); index != -1 {
						proxy = proxy[index+len("://"):]
					}
					socks5Outbound, err := s.createOutbound(fmt.Sprintf("socks5://%v", proxy))
					if err != nil {
						return nil, err
					}
					httpOutbound, err := s.createOutbound(fmt.Sprintf("http://%v", proxy))
					if err != nil {
						return nil, err
					}
					mwzz := []adapter.Outbound{socks5Outbound, httpOutbound}
					s.outbounds.Store(proxyKey, mwzz)
					return mwzz, nil
				})
				if err != nil {
					s.logger.WarnContext(ctx, "instantiation SOCKS error: ", err)
					continue
				}
				return s.dialContext(ctx, _outbounds, network, destination)
			} else {
				return s.dialContext(ctx, outbounds, network, destination)
			}
		default:
			s.logger.InfoContext(ctx, "unsupported type: ", t)
			continue
		}
	}
	return nil, E.New("static proxy parser error")
}

func (s *System) useProxy(addr string) bool {
	if len(addr) == 0 {
		return true
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() {
			return false
		}
	}

	ipMatchers, domainMatchers := parseIgnore(s.sysProxyConf.Static.NoProxy)
	addr = strings.ToLower(strings.TrimSpace(host))

	if ip != nil {
		for _, m := range ipMatchers {
			if m.match(addr, port, ip) {
				return false
			}
		}
	}
	for _, m := range domainMatchers {
		if m.match("."+addr, port, ip) {
			return false
		}
	}
	return true
}

func (s *System) findProxyForURL(destination M.Socksaddr, conf ieproxy.ProxyConf) ([]string, error) {
	var proxies []*gpac.Proxy
	matchingURL := url.URL{Host: destination.String(), Scheme: "http"}
	switch strings.ToLower(s.pacEngine) {
	case C.PacEngineSystem:
		URL := conf.Automatic.FindProxyForURL(matchingURL.String())
		if URL == "" {
			return nil, errors.New("proxy not matched")
		}
		proxies = gpac.ParseProxy(URL)
	case C.PacEngineJavascript:
		fallthrough
	default:
		var err error
		gpacParser := s.loadGpacParser()
		if gpacParser == nil {
			return nil, errors.New("gpacParser is nil")
		}
		proxies, err = gpacParser.FindProxy(matchingURL.String())
		if err != nil {
			return nil, err
		}
	}

	var URLs []string
	for _, proxy := range proxies {
		URL := s.getURL(proxy)
		if URL != "" {
			URLs = append(URLs, URL)
		}
	}
	if len(URLs) == 0 {
		return nil, errors.New("proxy not matched")
	}
	return URLs, nil
}

func (s *System) getURL(p *gpac.Proxy) (ustr string) {
	switch p.Type {
	case "DIRECT":
		ustr = fmt.Sprintf("%v://", strings.ToLower(p.Type))
	case "PROXY":
		if p.Username != "" && p.Password != "" {
			ustr = fmt.Sprintf("http://%s:%s@%s", p.Username, p.Password, p.Address)
		} else {
			ustr = fmt.Sprintf("http://%s", p.Address)
		}
	default:
		if p.Username != "" && p.Password != "" {
			ustr = fmt.Sprintf("%s://%s:%s@%s", strings.ToLower(p.Type), p.Username, p.Password, p.Address)
		} else {
			ustr = fmt.Sprintf("%s://%s", strings.ToLower(p.Type), p.Address)
		}
	}
	return
}

func (s *System) dialContext(ctx context.Context, obj any, network string, destination M.Socksaddr) (conn net.Conn, err error) {
	if outbounds, ok := obj.([]adapter.Outbound); ok {
		for _, outbound := range outbounds {
			conn, err = outbound.(adapter.Outbound).DialContext(ctx, network, destination)
			if err != nil {
				s.logger.WarnContext(ctx, outbound.Tag(), "(outbound) dial context error: ", err)
				continue
			}
			return conn, err
		}
	} else {
		err = E.New("unknown types")
	}
	return
}

func (s *System) createOutbound(proxyURL string) (adapter.Outbound, error) {
	URLParse, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	if URLParse.Hostname() == "localhost" {
		URLParse.Host = net.JoinHostPort("127.0.0.1", URLParse.Port())
	}
	outOption, err := parser.GetOutboundFromURL(URLParse, 1, "")
	if err != nil {
		return nil, err
	}
	var out adapter.Outbound
	switch URLParse.Scheme {
	case "http", "https":
		outOption.HTTPOptions.DialerOptions = s.dialerOptions
		out, err = NewHTTP(s.router, s.logger, outOption.Tag, outOption.HTTPOptions)
		if err != nil {
			return nil, err
		}
	case "socks", "socks5":
		outOption.SocksOptions.DialerOptions = s.dialerOptions
		out, err = NewSocks(s.router, s.logger, outOption.Tag, outOption.SocksOptions)
		if err != nil {
			return nil, err
		}
	default:
		return nil, E.New("unknown scheme!")
	}
	return out, nil
}

func parseIgnore(noProxy string) ([]matcher, []matcher) {
	ipMatchers := []matcher{}
	domainMatchers := []matcher{}
	for _, p := range strings.Split(noProxy, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if len(p) == 0 {
			continue
		}

		if p == "*" {
			ipMatchers = []matcher{allMatch{}}
			domainMatchers = []matcher{allMatch{}}
			return ipMatchers, domainMatchers
		}

		// IPv4/CIDR, IPv6/CIDR
		if _, pnet, err := net.ParseCIDR(p); err == nil {
			ipMatchers = append(ipMatchers, cidrMatch{cidr: pnet})
			continue
		}

		// IPv4:port, [IPv6]:port
		phost, pport, err := net.SplitHostPort(p)
		if err == nil {
			if len(phost) == 0 {
				// There is no host part, likely the entry is malformed; ignore.
				continue
			}
			if phost[0] == '[' && phost[len(phost)-1] == ']' {
				phost = phost[1 : len(phost)-1]
			}
		} else {
			phost = p
		}
		// IPv4, IPv6
		if pip := net.ParseIP(phost); pip != nil {
			ipMatchers = append(ipMatchers, ipMatch{ip: pip, port: pport})
			continue
		}

		if len(phost) == 0 {
			// There is no host part, likely the entry is malformed; ignore.
			continue
		}

		// domain.com or domain.com:80
		// foo.com matches bar.foo.com
		// .domain.com or .domain.com:port
		// *.domain.com or *.domain.com:port
		if strings.HasPrefix(phost, "*.") {
			phost = phost[1:]
		}
		matchHost := false
		if phost[0] != '.' {
			matchHost = true
			phost = "." + phost
		}
		if v, err := idnaASCII(phost); err == nil {
			phost = v
		}
		if strings.HasSuffix(phost, "*") {
			phost = phost[:len(phost)-1]
		}
		domainMatchers = append(domainMatchers, domainMatch{host: phost, port: pport, matchHost: matchHost})
	}

	return ipMatchers, domainMatchers
}

// matcher represents the matching rule for a given value in the NO_PROXY list
type matcher interface {
	// match returns true if the host and optional port or ip and optional port
	// are allowed
	match(host, port string, ip net.IP) bool
}

// allMatch matches on all possible inputs
type allMatch struct{}

func (a allMatch) match(host, port string, ip net.IP) bool {
	return true
}

type cidrMatch struct {
	cidr *net.IPNet
}

func (m cidrMatch) match(host, port string, ip net.IP) bool {
	return m.cidr.Contains(ip)
}

type ipMatch struct {
	ip   net.IP
	port string
}

func (m ipMatch) match(host, port string, ip net.IP) bool {
	if m.ip.Equal(ip) {
		return m.port == "" || m.port == port
	}
	return false
}

type domainMatch struct {
	host string
	port string

	matchHost bool
}

func (m domainMatch) match(host, port string, ip net.IP) bool {
	if strings.HasSuffix(host, m.host) || (m.matchHost && host == m.host[1:]) {
		return m.port == "" || m.port == port
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func idnaASCII(v string) (string, error) {
	// TODO: Consider removing this check after verifying performance is okay.
	// Right now punycode verification, length checks, context checks, and the
	// permissible character tests are all omitted. It also prevents the ToASCII
	// call from salvaging an invalid IDN, when possible. As a result it may be
	// possible to have two IDNs that appear identical to the user where the
	// ASCII-only version causes an error downstream whereas the non-ASCII
	// version does not.
	// Note that for correct ASCII IDNs ToASCII will only do considerably more
	// work, but it will not cause an allocation.
	if isASCII(v) {
		return v, nil
	}
	return idna.Lookup.ToASCII(v)
}
