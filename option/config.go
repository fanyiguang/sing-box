package option

import (
	"bytes"
	"strings"

	"github.com/sagernet/sing-box/common/json"
	E "github.com/sagernet/sing/common/exceptions"
)

type _Options struct {
	Log          *LogOptions          `json:"log,omitempty"`
	DNS          *DNSOptions          `json:"dns,omitempty"`
	Inbounds     []Inbound            `json:"inbounds,omitempty"`
	Outbounds    []Outbound           `json:"outbounds,omitempty"`
	Route        *RouteOptions        `json:"route,omitempty"`
	Experimental *ExperimentalOptions `json:"experimental,omitempty"`
}

type Options _Options

func (o *Options) UnmarshalJSON(content []byte) error {
	decoder := json.NewDecoder(json.NewCommentFilter(bytes.NewReader(content)))
	decoder.DisallowUnknownFields()
	err := decoder.Decode((*_Options)(o))
	if err == nil {
		return nil
	}
	if syntaxError, isSyntaxError := err.(*json.SyntaxError); isSyntaxError {
		prefix := string(content[:syntaxError.Offset])
		row := strings.Count(prefix, "\n") + 1
		column := len(prefix) - strings.LastIndex(prefix, "\n") - 1
		return E.Extend(syntaxError, "row ", row, ", column ", column)
	}
	return err
}

type LogOptions struct {
	Disabled     bool   `json:"disabled,omitempty"`
	Level        string `json:"level,omitempty"`
	Output       string `json:"output,omitempty"`
	Timestamp    bool   `json:"timestamp,omitempty"`
	DisableColor bool   `json:"-"`
	Rotate
}

type Rotate struct {
	MaxSize    int  `json:"max_size,omitempty"`    // 一个文件的大小
	MaxBackups int  `json:"max_backups,omitempty"` // 最多同时保存几个份文件
	MaxAge     int  `json:"max_age,omitempty"`     // 一个文件最多同时存在几天天
	Disabled   bool `json:"rotate,omitempty"`      // 日志倒换开关，开启后io.writer引用：lumberjack.Logger
}
