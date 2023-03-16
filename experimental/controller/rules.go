package controller

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
)

func (s *Server) AddRules(ruleOptions []option.Rule) error {
	var rules []adapter.Rule
	for i, ruleOption := range ruleOptions {
		rule, err := route.NewRule(s.router, s.router.Logger(), ruleOption)
		if err != nil {
			s.logger.Warn("new rule error: ", err, " [ ", i, " ] ")
			continue
		}
		rules = append(rules, rule)
	}
	s.router.AddRules(rules)
	return nil
}

func (s *Server) DelRule(tag string) {
	s.logger.Info("delete rule: ", tag)
	s.router.DelRules(tag)
}

func (s *Server) ClearRules() {
}
