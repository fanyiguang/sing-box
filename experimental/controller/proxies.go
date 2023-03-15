package controller

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	F "github.com/sagernet/sing/common/format"
)

func (s *Server) AddProxies(outboundOptions []option.Outbound, replace bool) error {
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
			outboundOption)
		if err != nil {
			s.logger.Warn("new outbound error: ", err)
			continue
		}
		outbounds = append(outbounds, out)
	}
	return s.router.AddOutbounds(outbounds, replace)
}

func (s *Server) StartURLTest(name string, t int) error {
	return nil
}
