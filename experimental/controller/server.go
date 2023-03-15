package controller

import (
	"context"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func init() {
	experimental.RegisterControllerConstructor(NewServer)
}

var _ adapter.Controller = (*Server)(nil)

type Server struct {
	ctx        context.Context
	router     adapter.Router
	logFactory log.Factory
	logger     log.Logger
}

func NewServer(ctx context.Context, router adapter.Router, logFactory log.ObservableFactory, options option.ControllerOptions) (adapter.Controller, error) {
	return &Server{
		ctx:        ctx,
		router:     router,
		logFactory: logFactory,
		logger:     logFactory.NewLogger("Controller"),
	}, nil
}

func (s *Server) Start() error {
	return nil
}

func (s *Server) Close() error {
	return nil
}
