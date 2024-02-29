package box

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing-box/route"
	F "github.com/sagernet/sing/common/format"
)

func (s *Box) AddOutbounds(outboundOptions []option.Outbound, replace bool) error {
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
	return s.router.AddOutbounds(outbounds, replace)
}

func (s *Box) Outbound(name string) (adapter.Outbound, bool) {
	return s.router.Outbound(name)
}

func (s *Box) DelOutbound(name string) {
	s.router.DelOutbound(name)
}

func (s *Box) AddRules(ruleOptions []option.Rule) error {
	var rules []adapter.Rule
	for i, ruleOption := range ruleOptions {
		rule, err := route.NewRule(s.router, s.logFactory.NewLogger("router"), ruleOption)
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
	rule, err := route.NewRule(s.router, s.logFactory.NewLogger("router"), ruleOption)
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