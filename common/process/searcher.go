package process

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/shirou/gopsutil/process"
)

type Searcher interface {
	FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*Info, error)
}

var ErrNotFound = E.New("process not found")

type Config struct {
	Logger         log.ContextLogger
	PackageManager tun.PackageManager
}

type Info struct {
	ProcessPath string
	PackageName string
	User        string
	UserId      int32
	PID         uint32
}

type processInfo struct {
	Name string
	PID  uint32
}

func FindProcessInfo(searcher Searcher, ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*Info, error) {
	return findProcessInfo(searcher, ctx, network, source, destination)
}

func GetAllParentID(PID uint32) ([]int32, error) {
	var ids []int32
	proc, err := process.NewProcess(int32(PID))
	if err != nil {
		return nil, err
	}
	for true {
		ids = append(ids, proc.Pid)
		proc, err = proc.Parent()
		if err != nil {
			break
		}
	}
	return ids, nil
}
