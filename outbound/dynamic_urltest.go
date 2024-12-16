package outbound

import (
	"context"
	"github.com/fanyiguang/brick/channel"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ adapter.Outbound      = (*DynamicURLTest)(nil)
	_ adapter.OutboundGroup = (*DynamicURLTest)(nil)
)

type DynamicURLTest struct {
	myOutboundAdapter
	context   context.Context
	tags      []string
	link      string
	interval  time.Duration
	tolerance uint16
	group     *DynamicURLTestGroup
}

func NewDynamicURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DynamicURLTestOutboundOptions) (*DynamicURLTest, error) {
	outbound := &DynamicURLTest{
		myOutboundAdapter: myOutboundAdapter{
			protocol: C.TypeDynamicURLTest,
			router:   router,
			logger:   logger,
			tag:      tag,
		},
		context:   ctx,
		tags:      options.Outbounds,
		link:      options.URL,
		interval:  time.Duration(options.Interval),
		tolerance: options.Tolerance,
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	return outbound, nil
}

func (d *DynamicURLTest) Network() []string {
	if d.group == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return d.group.Select(N.NetworkTCP).Network()
}

func (d *DynamicURLTest) Start() error {
	outbounds := make([]adapter.Outbound, 0, len(d.tags))
	for i, tag := range d.tags {
		detour, loaded := d.router.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	d.group = NewDynamicURLTestGroup(d.router, d.logger, outbounds, d.link, d.interval, d.tolerance)
	return d.group.Start()
}

func (d DynamicURLTest) Close() error {
	return common.Close(
		common.PtrOrNil(d.group),
	)
}

func (d *DynamicURLTest) Now() string {
	return d.group.Select(N.NetworkTCP).Tag()
}

func (d *DynamicURLTest) NowOutbound() adapter.Outbound {
	return d.group.Select(N.NetworkTCP)
}

func (d *DynamicURLTest) All() []string {
	return d.tags
}

func (d *DynamicURLTest) StartUELTest(t int) {
	d.group.startURLTest(t)
}

func (d *DynamicURLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	outbound := d.group.Select(network)
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		return conn, nil
	}
	d.logger.ErrorContext(ctx, err)
	go d.group.CheckOutbounds()
	outbounds := d.group.Fallback(outbound, network)
	for _, fallback := range outbounds {
		conn, err = fallback.DialContext(ctx, network, destination)
		if err == nil {
			return conn, nil
		} else {
			d.logger.ErrorContext(ctx, err)
		}
	}
	return nil, err
}

func (d *DynamicURLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	outbound := d.group.Select(N.NetworkUDP)
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		return conn, nil
	}
	d.logger.ErrorContext(ctx, err)
	go d.group.CheckOutbounds()
	outbounds := d.group.Fallback(outbound, N.NetworkUDP)
	for _, fallback := range outbounds {
		conn, err = fallback.ListenPacket(ctx, destination)
		if err == nil {
			return conn, nil
		}
	}
	return nil, err
}

func (d *DynamicURLTest) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, d, conn, metadata)
}

func (d *DynamicURLTest) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewPacketConnection(ctx, d, conn, metadata)
}

type DynamicURLTestGroup struct {
	router    adapter.Router
	logger    log.Logger
	outbounds []adapter.Outbound
	link      string
	interval  time.Duration
	tolerance uint16
	history   *urltest.HistoryStorage

	urlTestTicker    *time.Ticker
	testingStopTimer *time.Timer
	testingStarted   chan struct{}
	stop             chan struct{}
	mt               sync.Mutex
}

func NewDynamicURLTestGroup(router adapter.Router, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, tolerance uint16) *DynamicURLTestGroup {
	if link == "" {
		//goland:noinspection HttpUrlsUsage
		link = "http://www.gstatic.com/generate_204"
	}
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	var history *urltest.HistoryStorage
	if clashServer := router.ClashServer(); clashServer != nil {
		history = clashServer.HistoryStorage()
	} else {
		history = urltest.NewHistoryStorage()
	}
	return &DynamicURLTestGroup{
		router:         router,
		logger:         logger,
		outbounds:      outbounds,
		link:           link,
		interval:       interval,
		tolerance:      tolerance,
		history:        history,
		testingStarted: make(chan struct{}),
		stop:           make(chan struct{}),
	}
}

func (d *DynamicURLTestGroup) Start() error {
	d.urlTestTicker = time.NewTicker(d.interval)
	return nil
}

func (d *DynamicURLTestGroup) startURLTest(t int) {
	d.mt.Lock()
	defer d.mt.Unlock()
	select {
	case <-d.testingStarted:
		d.testingStopTimer.Reset(time.Duration(t) * time.Second)
		d.logger.Info("testingStopTimer reset: ", t, "s")
	default:
		d.logger.Info("start loop check")
		channel.Close(d.testingStarted)
		go d.loopCheck(t)
	}
}

func (d *DynamicURLTestGroup) Close() error {
	d.mt.Lock()
	defer d.mt.Unlock()
	d.urlTestTicker.Stop()
	if d.testingStopTimer != nil {
		d.testingStopTimer.Stop()
	}
	channel.Close(d.stop)
	return nil
}

func (d *DynamicURLTestGroup) Select(network string) adapter.Outbound {
	var minDelay uint16
	var minTime time.Time
	var minOutbound adapter.Outbound
	for _, detour := range d.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		history := d.history.LoadURLTestHistory(RealTag(detour))
		if history == nil {
			continue
		}
		if minDelay == 0 || minDelay > history.Delay+d.tolerance || minDelay > history.Delay-d.tolerance && minTime.Before(history.Time) {
			minDelay = history.Delay
			minTime = history.Time
			minOutbound = detour
		}
	}
	if minOutbound == nil {
		for _, detour := range d.outbounds {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			minOutbound = detour
			break
		}
	}
	return minOutbound
}

func (d *DynamicURLTestGroup) Fallback(used adapter.Outbound, network string) []adapter.Outbound {
	outbounds := make([]adapter.Outbound, 0, len(d.outbounds)-1)
	for _, detour := range d.outbounds {
		if detour != used && common.Contains(detour.Network(), network) {
			outbounds = append(outbounds, detour)
		}
	}
	sort.Slice(outbounds, func(i, j int) bool {
		oi := outbounds[i]
		oj := outbounds[j]
		hi := d.history.LoadURLTestHistory(RealTag(oi))
		if hi == nil {
			return false
		}
		hj := d.history.LoadURLTestHistory(RealTag(oj))
		if hj == nil {
			return false
		}
		return hi.Delay < hj.Delay
	})
	return outbounds
}

func (d *DynamicURLTestGroup) loopCheck(t int) {
	go d.checkOutbounds()
	if d.testingStopTimer != nil && !d.testingStopTimer.Stop() {
		select {
		case <-d.testingStopTimer.C:
		default:
		}
	}
	d.testingStopTimer = time.NewTimer(time.Duration(t) * time.Second)
	for {
		select {
		case <-d.stop:
			d.logger.Info("dynamic url test group stop")
			return
		case <-d.testingStopTimer.C:
			d.mt.Lock()
			d.testingStarted = make(chan struct{})
			d.mt.Unlock()

			d.logger.Info("dynamic url test group expire")
			return
		case <-d.urlTestTicker.C:
			d.logger.Debug("start url test")
			d.checkOutbounds()
		}
	}
}

func (d *DynamicURLTestGroup) CheckOutbounds() {
	d.mt.Lock()
	defer d.mt.Unlock()
	select {
	case <-d.testingStarted:
		d.checkOutbounds()
	default:
	}
}

func (d *DynamicURLTestGroup) checkOutbounds() {
	b, _ := batch.New(context.Background(), batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	for _, detour := range d.outbounds {
		tag := detour.Tag()
		realTag := RealTag(detour)
		if checked[realTag] {
			continue
		}
		history := d.history.LoadURLTestHistory(realTag)
		if history != nil && time.Now().Sub(history.Time) < d.interval {
			continue
		}
		checked[realTag] = true
		p, loaded := d.router.Outbound(realTag)
		if !loaded {
			continue
		}
		b.Go(realTag, func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), C.TCPTimeout)
			defer cancel()
			t, err := urltest.URLTest(ctx, d.link, p)
			if err != nil {
				d.logger.Debug("outbound ", tag, " unavailable: ", err)
				d.history.DeleteURLTestHistory(realTag)
			} else {
				d.logger.Debug("outbound ", tag, " available: ", t, "ms")
				d.history.StoreURLTestHistory(realTag, &urltest.History{
					Time:  time.Now(),
					Delay: t,
				})
			}
			return nil, nil
		})
	}
	b.Wait()
}
