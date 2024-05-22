package log

import (
	"gopkg.in/natefinch/lumberjack.v2"
)

var Logger *lumberjack.Logger

func Init(path string) {
	Logger = &lumberjack.Logger{
		LocalTime: true,
		Filename:  path,
		MaxSize:   20, // 一个文件最大为20M
		MaxAge:    10, // 一个文件最多同时存在10天
		Compress:  false,
	}
}

func New(path string) *lumberjack.Logger {
	return &lumberjack.Logger{
		LocalTime: true,
		Filename:  path,
		MaxSize:   20, // 一个文件最大为20M
		MaxAge:    10, // 一个文件最多同时存在10天
		Compress:  false,
	}
}
