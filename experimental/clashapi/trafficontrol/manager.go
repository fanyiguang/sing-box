package trafficontrol

import (
	"fmt"
	"github.com/sagernet/sing-box/common/log"
	"github.com/sagernet/sing-box/option"
	"gopkg.in/natefinch/lumberjack.v2"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/sing-box/experimental/clashapi/compatible"
	"github.com/sagernet/sing/common/atomic"
)

type Manager struct {
	uploadTemp    atomic.Int64
	downloadTemp  atomic.Int64
	uploadBlip    atomic.Int64
	downloadBlip  atomic.Int64
	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64

	connections compatible.Map[string, tracker]
	ticker      *time.Ticker
	done        chan struct{}
	// process     *process.Process
	memory uint64

	InboundTrafficStatistics
}

type InboundTrafficStatistics struct {
	tcpUploadTemp   *TrafficStatistics
	tcpDownloadTemp *TrafficStatistics
	udpUploadTemp   *TrafficStatistics
	udpDownloadTemp *TrafficStatistics
	ticker          *time.Ticker
	logger          *lumberjack.Logger
	done            chan struct{}
	interval        int
	enable          bool
}

type TrafficStatistics struct {
	sync.Mutex
	statistics map[string]int64
}

func (i *TrafficStatistics) add(ip string, size int64) {
	i.Lock()
	defer i.Unlock()
	if d, ok := i.statistics[ip]; ok {
		i.statistics[ip] = d + size
	} else {
		i.statistics[ip] = size
	}
}

func (i *TrafficStatistics) getAndClear() map[string]int64 {
	i.Lock()
	defer i.Unlock()
	a := i.statistics
	i.statistics = make(map[string]int64)
	for ip, _ := range a {
		i.statistics[ip] = 0
	}
	return a
}

func (i *TrafficStatistics) delete(ip string) {
	i.Lock()
	defer i.Unlock()
	delete(i.statistics, ip)
}

func (i *InboundTrafficStatistics) handle() {
	var tcpUp, tcpDown, udpUp, udpDown map[string]int64
	if !i.enable {
		return
	}
	for {
		select {
		case <-i.done:
			return
		case <-i.ticker.C:
			tcpUp = i.tcpUploadTemp.getAndClear()
			tcpDown = i.tcpDownloadTemp.getAndClear()

			udpUp = i.udpUploadTemp.getAndClear()
			udpDown = i.udpDownloadTemp.getAndClear()

			timestamp := time.Now().Unix()
			i.printLog(tcpUp, tcpDown, timestamp, "t")
			i.printLog(udpUp, udpDown, timestamp, "u")
		}
	}
}

func (i *InboundTrafficStatistics) printLog(aMap, bMap map[string]int64, timestamp int64, network string) {
	// format: 1716277052|t|116.177.242.196|300|1100
	for ip, size := range aMap {
		_, _ = i.logger.Write([]byte(fmt.Sprintf("%v|%v|%v|%v|%v|%v\n", timestamp, network, ip, size, bMap[ip], i.interval)))
		delete(bMap, ip)
	}

	for ip, size := range bMap {
		_, _ = i.logger.Write([]byte(fmt.Sprintf("%v|%v|%v|%v|%v|%v\n", timestamp, network, ip, aMap[ip], size, i.interval)))
	}
}

func (i *InboundTrafficStatistics) PushInboundTcpUploaded(ip string, size int64) {
	if !i.enable {
		return
	}
	i.tcpUploadTemp.add(ip, size)
}

func (i *InboundTrafficStatistics) PushInboundTcpDownloaded(ip string, size int64) {
	if !i.enable {
		return
	}
	i.tcpDownloadTemp.add(ip, size)
}

func (i *InboundTrafficStatistics) PushInboundUdpUploaded(ip string, size int64) {
	if !i.enable {
		return
	}
	i.udpUploadTemp.add(ip, size)
}

func (i *InboundTrafficStatistics) PushInboundUdpDownloaded(ip string, size int64) {
	if !i.enable {
		return
	}
	i.udpDownloadTemp.add(ip, size)
}

func NewManager(trafficStatistics option.TrafficStatistics) *Manager {
	manager := &Manager{
		ticker: time.NewTicker(time.Second),
		done:   make(chan struct{}),
		// process: &process.Process{Pid: int32(os.Getpid())},
		InboundTrafficStatistics: InboundTrafficStatistics{
			tcpUploadTemp: &TrafficStatistics{
				statistics: make(map[string]int64),
			},
			tcpDownloadTemp: &TrafficStatistics{
				statistics: make(map[string]int64),
			},
			udpUploadTemp: &TrafficStatistics{
				statistics: make(map[string]int64),
			},
			udpDownloadTemp: &TrafficStatistics{
				statistics: make(map[string]int64),
			},
			ticker:   time.NewTicker(time.Duration(trafficStatistics.Interval) * time.Second),
			logger:   log.New(trafficStatistics.Output),
			done:     make(chan struct{}),
			interval: trafficStatistics.Interval,
			enable:   trafficStatistics.Enable,
		},
	}
	go manager.handle()
	return manager
}

func (m *Manager) Join(c tracker) {
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c tracker) {
	m.connections.Delete(c.ID())
}

func (m *Manager) PushUploaded(size int64) {
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
}

func (m *Manager) PushDownloaded(size int64) {
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
}

func (m *Manager) Now() (up int64, down int64) {
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

func (m *Manager) Total() (up int64, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) Connections() int {
	return m.connections.Len()
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []tracker
	m.connections.Range(func(_ string, value tracker) bool {
		connections = append(connections, value)
		return true
	})

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.memory = memStats.StackInuse + memStats.HeapInuse + memStats.HeapIdle - memStats.HeapReleased

	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
		Memory:        m.memory,
	}
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
}

func (m *Manager) handle() {
	var uploadTemp int64
	var downloadTemp int64
	go m.InboundTrafficStatistics.handle()
	for {
		select {
		case <-m.done:
			return
		case <-m.ticker.C:
		}
		uploadTemp = m.uploadTemp.Swap(0)
		downloadTemp = m.downloadTemp.Swap(0)
		m.uploadBlip.Store(uploadTemp)
		m.downloadBlip.Store(downloadTemp)
	}
}

func (m *Manager) Close() error {
	m.ticker.Stop()
	close(m.done)
	close(m.InboundTrafficStatistics.done)
	return nil
}

type Snapshot struct {
	DownloadTotal int64     `json:"downloadTotal"`
	UploadTotal   int64     `json:"uploadTotal"`
	Connections   []tracker `json:"connections"`
	Memory        uint64    `json:"memory"`
}
