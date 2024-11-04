package box

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"
	"github.com/sagernet/sing-box/inbound"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing-box/route"
	F "github.com/sagernet/sing/common/format"
)

func (s *Box) AddInbound(inboundOption option.Inbound, replace bool) error {
	s.mt.Lock()
	defer s.mt.Unlock()
	var tag string
	if inboundOption.Tag != "" {
		tag = inboundOption.Tag
	} else {
		tag = F.ToString(0)
	}
	in, err := inbound.New(
		s.ctx,
		s.router,
		s.logFactory.NewLogger(F.ToString("inbound/", inboundOption.Type, "[", tag, "]")),
		inboundOption,
		nil,
	)
	if err != nil {
		s.logger.Warn("parse inbound error: ", err)
		return err
	}
	err = s.router.AddInbound(in, replace)
	if err != nil {
		s.logger.Warn("add inbound error: ", err)
		return err
	}
	s.inbounds = append(s.inbounds, in)
	return nil
}

func (s *Box) DelInbound(tag string) {
	s.mt.Lock()
	defer s.mt.Unlock()
	s.router.DelInbound(tag)
	for i, inb := range s.inbounds {
		if inb.Tag() == tag {
			s.inbounds = append(s.inbounds[:i], s.inbounds[i+1:]...)
			break
		}
	}
}

func (s *Box) AddOutbounds(outboundOptions []option.Outbound, replace bool) error {
	s.mt.Lock()
	defer s.mt.Unlock()
	var outbounds []adapter.Outbound
	for i, outboundOption := range outboundOptions {
		var tag string
		if outboundOption.Tag != "" {
			tag = outboundOption.Tag
		} else {
			tag = F.ToString(i)
		}
		out, err := outbound.New(
			s.ctx,
			s.router,
			s.logFactory.NewLogger(F.ToString("outbound/", outboundOption.Type, "[", tag, "]")),
			tag,
			outboundOption)
		if err != nil {
			s.logger.Warn("new outbound error: ", err)
			return err
		}
		outbounds = append(outbounds, out)
	}
	err := s.router.AddOutbounds(outbounds, replace)
	if err != nil {
		s.logger.Warn("add outbound error: ", err)
		return err
	}
	s.outbounds = append(s.outbounds, outbounds...)
	return nil
}

func (s *Box) Outbound(name string) (adapter.Outbound, bool) {
	return s.router.Outbound(name)
}

func (s *Box) DelOutbound(name string) {
	s.mt.Lock()
	defer s.mt.Unlock()
	s.router.DelOutbound(name)
	for i, out := range s.outbounds {
		if out.Tag() == name {
			s.outbounds = append(s.outbounds[:i], s.outbounds[i+1:]...)
			break
		}
	}
}

func (s *Box) AddRules(ruleOptions []option.Rule) error {
	var rules []adapter.Rule
	for i, ruleOption := range ruleOptions {
		rule, err := route.NewRule(s.router, s.logFactory.NewLogger("router"), ruleOption, true)
		if err != nil {
			s.logger.Warn("new rule error: ", err, " [ ", i, " ] ")
			continue
		}
		rules = append(rules, rule)
	}
	s.router.AddRules(rules)
	return nil
}

func (s *Box) UpdateRule(tag string, ruleOption option.Rule) error {
	rule, err := route.NewRule(s.router, s.logFactory.NewLogger("router"), ruleOption, true)
	if err != nil {
		s.logger.Warn("new rule error: ", err)
		return err
	}
	s.router.UpdateRule(tag, rule)
	return nil
}

func (s *Box) Rules() []adapter.Rule {
	return s.router.Rules()
}

func (s *Box) DelRule(tag string) {
	s.logger.Info("delete rule: ", tag)
	s.router.DelRules(tag)
}

func (s *Box) AddDNSServer(servers []option.DNSServerOptions) error {
	return s.router.AddDNSServer(servers)
}

func (s *Box) DelDNSServer(tag string) bool {
	return s.router.DelDNSServer(tag)
}

func (s *Box) CloseAllConnections() error {
	trafficManager := trafficontrol.NewManager()
	for _, c := range trafficManager.Snapshot().Connections {
		c.Close()
	}
	return s.router.ResetNetwork()
}
