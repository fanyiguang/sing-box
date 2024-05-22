package inbound

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox/platform"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, options option.Inbound, platformInterface platform.Interface) (adapter.Inbound, error) {
	if options.Type == "" {
		return nil, E.New("missing inbound type")
	}
	switch options.Type {
	case C.TypeTun:
		return NewTun(ctx, router, logger, options.Tag, options.IP, options.TunOptions, platformInterface)
	case C.TypeRedirect:
		return NewRedirect(ctx, router, logger, options.Tag, options.IP, options.RedirectOptions), nil
	case C.TypeTProxy:
		return NewTProxy(ctx, router, logger, options.Tag, options.IP, options.TProxyOptions), nil
	case C.TypeDirect:
		return NewDirect(ctx, router, logger, options.Tag, options.IP, options.DirectOptions), nil
	case C.TypeSOCKS:
		return NewSocks(ctx, router, logger, options.Tag, options.IP, options.SocksOptions)
	case C.TypeHTTP:
		return NewHTTP(ctx, router, logger, options.Tag, options.IP, options.HTTPOptions)
	case C.TypeMixed:
		return NewMixed(ctx, router, logger, options.Tag, options.IP, options.MixedOptions), nil
	case C.TypeShadowsocks:
		return NewShadowsocks(ctx, router, logger, options.Tag, options.IP, options.ShadowsocksOptions)
	case C.TypeVMess:
		return NewVMess(ctx, router, logger, options.Tag, options.IP, options.VMessOptions)
	case C.TypeTrojan:
		return NewTrojan(ctx, router, logger, options.Tag, options.IP, options.TrojanOptions)
	case C.TypeNaive:
		return NewNaive(ctx, router, logger, options.Tag, options.IP, options.NaiveOptions)
	case C.TypeHysteria:
		return NewHysteria(ctx, router, logger, options.Tag, options.HysteriaOptions)
	case C.TypeShadowTLS:
		return NewShadowTLS(ctx, router, logger, options.Tag, options.IP, options.ShadowTLSOptions)
	case C.TypeVLESS:
		return NewVLESS(ctx, router, logger, options.Tag, options.IP, options.VLESSOptions)
	case C.TypeTUIC:
		return NewTUIC(ctx, router, logger, options.Tag, options.TUICOptions)
	case C.TypeHysteria2:
		return NewHysteria2(ctx, router, logger, options.Tag, options.Hysteria2Options)
	default:
		return nil, E.New("unknown inbound type: ", options.Type)
	}
}
