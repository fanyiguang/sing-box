package outbound

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ adapter.Outbound      = (*AutoSelector)(nil)
	_ adapter.OutboundGroup = (*AutoSelector)(nil)
)

type AutoSelector struct {
	myOutboundAdapter
	tags  []string
	group *AutoSelectorGroup
}

func NewAutoSelector(router adapter.Router, logger log.ContextLogger, tag string, options option.AutoSelectorOutboundOptions) (*AutoSelector, error) {
	outbound := &AutoSelector{
		myOutboundAdapter: myOutboundAdapter{
			protocol: C.TypeAutoSelector,
			router:   router,
			logger:   logger,
			tag:      tag,
		},
		tags: options.Outbounds,
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	return outbound, nil
}

func (d *AutoSelector) Network() []string {
	if d.group == nil {
		return []string{}
	}
	outbound, ok := d.group.Select(N.NetworkTCP)
	if !ok {
		return []string{}
	}
	return outbound.Network()
}

func (d *AutoSelector) Now() string {
	outbound, ok := d.group.Select(N.NetworkTCP)
	if !ok {
		return ""
	}
	return outbound.Tag()
}

func (d *AutoSelector) All() []string {
	return d.tags
}

func (d *AutoSelector) Start() error {
	outbounds := make([]adapter.Outbound, 0, len(d.tags))
	for i, tag := range d.tags {
		detour, loaded := d.router.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	d.group = NewAutoSelectorGroup(d.router, d.logger, outbounds)
	return d.group.Start()
}

func (d *AutoSelector) Close() error {
	return common.Close(
		common.PtrOrNil(d.group),
	)
}

func (d *AutoSelector) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	outbound, ok := d.group.Select(network)
	if !ok {
		return nil, E.New("outbound not found")
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		return conn, nil
	}
	d.logger.ErrorContext(ctx, err)
	outbounds := d.group.Fallback(outbound, network)
	for _, fallback := range outbounds {
		conn, err = fallback.DialContext(ctx, network, destination)
		if err == nil {
			// d.group.SetFirstOutbound(fallback.Tag())
			return conn, nil
		} else {
			d.logger.ErrorContext(ctx, err)
		}
	}
	return nil, err
}

func (d *AutoSelector) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	outbound, ok := d.group.Select(N.NetworkUDP)
	if !ok {
		return nil, E.New("outbound not found")
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		return conn, nil
	}
	d.logger.ErrorContext(ctx, err)
	outbounds := d.group.Fallback(outbound, N.NetworkUDP)
	for _, fallback := range outbounds {
		conn, err = fallback.ListenPacket(ctx, destination)
		if err == nil {
			// d.group.SetFirstOutbound(fallback.Tag())
			return conn, nil
		}
	}
	return nil, err
}

func (d *AutoSelector) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, d, conn, metadata)
}

func (d *AutoSelector) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewPacketConnection(ctx, d, conn, metadata)
}

type AutoSelectorGroup struct {
	logger    log.Logger
	outbounds []adapter.Outbound
	stop      chan struct{}
	mt        sync.RWMutex
	closeOnce sync.Once
}

func NewAutoSelectorGroup(router adapter.Router, logger log.Logger, outbounds []adapter.Outbound) *AutoSelectorGroup {
	return &AutoSelectorGroup{
		logger:    logger,
		outbounds: outbounds,
		stop:      make(chan struct{}),
	}
}

func (d *AutoSelectorGroup) Start() error {
	return nil
}

func (d *AutoSelectorGroup) Select(network string) (adapter.Outbound, bool) {
	d.mt.RLock()
	defer d.mt.RUnlock()
	if len(d.outbounds) == 0 {
		return nil, false
	}
	return d.outbounds[0], true
}

// 从outbounds中移除used，返回剩余的outbounds
// 如果outbounds剩余最后一个则不再删除
func (d *AutoSelectorGroup) Fallback(used adapter.Outbound, network string) []adapter.Outbound {
	d.mt.Lock()
	defer d.mt.Unlock()
	if len(d.outbounds) == 1 {
		return d.outbounds
	}
	for i, outbound := range d.outbounds {
		if outbound.Tag() == used.Tag() {
			d.outbounds = append(d.outbounds[:i], d.outbounds[i+1:]...)
			break
		}
	}
	return d.outbounds
}

func (d *AutoSelectorGroup) SetFirstOutbound(tag string) {
	d.mt.Lock()
	defer d.mt.Unlock()
	for i, outbound := range d.outbounds {
		if outbound.Tag() == tag {
			d.outbounds = append(d.outbounds[:i], d.outbounds[i+1:]...)
			d.outbounds = append([]adapter.Outbound{outbound}, d.outbounds...)
			break
		}
	}
}

func (d *AutoSelectorGroup) Close() error {
	d.closeOnce.Do(func() {
		close(d.stop)
	})
	return nil
}
