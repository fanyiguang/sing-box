package clashapi

import (
	"bytes"
	"embed"
	"github.com/sagernet/sing-box/log"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/go-chi/chi/v5"
)

//go:embed web-ui
var uiFS embed.FS

var indexTemplate *template.Template

var logger log.Logger

func UICallBack(log log.Logger) func(router chi.Router) {
	logger = log
	return UI
}

func UI(r chi.Router) {
	sub, err := fs.Sub(uiFS, "web-ui")
	if err != nil {
		logger.Warn("Failed to load web-ui: %s", err)
		return
	}

	fs := http.StripPrefix("/ui", http.FileServer(http.FS(sub)))

	// 初始化模板
	if t, err := template.ParseFS(sub, "index_tmpl.html"); err == nil {
		indexTemplate = t
	} else {
		logger.Warn("Failed to load web-ui template: %s", err)
	}

	r.Get("/ui", http.RedirectHandler("/ui/", http.StatusTemporaryRedirect).ServeHTTP)
	r.Get("/ui/", func(w http.ResponseWriter, r *http.Request) {
		if indexTemplate != nil {

			type params struct {
				Host   string
				Secret string
			}

			buff := &bytes.Buffer{}
			err := indexTemplate.Execute(buff, params{
				Host:   r.Host,
				Secret: "",
			})
			if err == nil {
				w.Header().Add("Cache-Control", "no-store")
				w.Write(buff.Bytes())

				return
			}
			logger.Warn("Failed to render web-ui template: %s", err)
		}

		fs.ServeHTTP(w, r)
	})
	r.Get("/ui/*", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
}
