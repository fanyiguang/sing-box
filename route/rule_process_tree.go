package route

import (
	"fmt"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing/common"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/warning"
	C "github.com/sagernet/sing-box/constant"
	goproc "github.com/shirou/gopsutil/process"
)

var warnProcessTreeOnNonSupportedPlatform = warning.New(
	func() bool { return !(C.IsWindows || C.IsDarwin) },
	"rule item `process_tree` is only supported on, Windows and macOS",
)

var _ RuleItem = (*ProcessTreeItem)(nil)

type ProcessTreeItem struct {
	processIds  []int32
	processes   []*goproc.Process
	childrenMap sync.Map // pid:*process.Process
}

func NewProcessTreeItem(processIds []int32) *ProcessTreeItem {
	warnProcessTreeOnNonSupportedPlatform.Check()
	rule := &ProcessTreeItem{
		processIds: processIds,
	}
	for _, pid := range processIds {
		proc, err := goproc.NewProcess(pid)
		if err == nil {
			rule.processes = append(rule.processes, proc)
		}
	}
	return rule
}

func (r *ProcessTreeItem) Match(metadata *adapter.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.ProcessPath == "" {
		return false
	}

	if load, ok := r.childrenMap.Load(metadata.ProcessInfo.PID); ok {
		if running, _ := load.(*goproc.Process).IsRunning(); running {
			return true
		}
	}

	if metadata.ProcessParentIds == nil {
		ids, err := process.GetAllParentID(metadata.ProcessInfo.PID)
		if err != nil {
			return false
		}
		metadata.ProcessParentIds = ids
	}

	ppids := metadata.ProcessParentIds

	for _, process := range r.processes {
		if running, _ := process.IsRunning(); !running {
			continue
		}
		find := common.Find(ppids, func(pid int32) bool {
			if process.Pid == pid {
				return true
			}
			return false
		})
		if find != 0 {
			proc, err := goproc.NewProcess(int32(metadata.ProcessInfo.PID))
			if err == nil {
				r.childrenMap.Store(metadata.ProcessInfo.PID, proc)
			}
			return true
		}
	}

	return false
}

func (r *ProcessTreeItem) String() string {
	var description string
	pLen := len(r.processIds)
	if pLen == 1 {
		description = "process_tree=" + strconv.Itoa(int(r.processIds[0]))
	} else {
		var builder strings.Builder
		builder.WriteString("process_tree=[ ")
		for _, pid := range r.processIds {
			builder.WriteString(fmt.Sprintf("%v ", pid))
		}
		builder.WriteString("]")
		description = builder.String()
	}
	return description
}
