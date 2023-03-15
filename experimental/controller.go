package experimental

import (
	"context"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"os"
)

type ControllerConstructor = func(ctx context.Context, router adapter.Router, logFactory log.ObservableFactory, options option.ControllerOptions) (adapter.Controller, error)

var controllerConstructor ControllerConstructor

func RegisterControllerConstructor(constructor ControllerConstructor) {
	controllerConstructor = constructor
}

func NewController(ctx context.Context, router adapter.Router, logFactory log.ObservableFactory, options option.ControllerOptions) (adapter.Controller, error) {
	if controllerConstructor == nil {
		return nil, os.ErrInvalid
	}
	return controllerConstructor(ctx, router, logFactory, options)
}
