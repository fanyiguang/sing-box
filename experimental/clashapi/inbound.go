package clashapi

import (
	"net/http"

	"github.com/sagernet/sing-box/adapter"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func inbound(server *Server, router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getInbounds(server))
	return r
}

func getInbounds(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		inbounds := server.inbounds
		var result []map[string]interface{}
		for _, inbound := range inbounds {
			result = append(result, map[string]interface{}{
				"name": inbound.Tag(),
				"type": inbound.Type(),
			})
		}
		render.JSON(w, r, result)
	}
}
