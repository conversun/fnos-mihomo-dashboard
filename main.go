package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/conversun/fnos-mihomo-dashboard/internal/handlers"
)

//go:embed web/dist
var webFS embed.FS

func main() {
	listen := flag.String("listen", ":9097", "listen address")
	mihomoAPI := flag.String("mihomo-api", "http://127.0.0.1:9090", "mihomo internal API")
	configFile := flag.String("config", "/etc/mihomo/config.yaml", "mihomo config.yaml path")
	logFile := flag.String("log", "/var/log/mihomo.log", "mihomo log file path")
	metacubexdDir := flag.String("metacubexd", "", "optional metacubexd static dir to serve at /ui/")
	flag.Parse()

	mihomoURL, err := url.Parse(*mihomoAPI)
	if err != nil {
		log.Fatalf("invalid mihomo-api: %v", err)
	}

	mux := http.NewServeMux()

	// Our API
	h := handlers.New(*configFile, *logFile, mihomoURL)
	mux.HandleFunc("/api/subscription", h.Subscription)
	mux.HandleFunc("/api/status", h.Status)
	mux.HandleFunc("/api/logs", h.Logs)
	mux.HandleFunc("/api/proxies", h.Proxies)
	mux.HandleFunc("/api/proxies/select", h.SelectProxy)
	mux.HandleFunc("/api/reload", h.Reload)

	// Reverse proxy to mihomo RESTful API (for clients that need raw mihomo API)
	mihomoProxy := httputil.NewSingleHostReverseProxy(mihomoURL)
	mux.Handle("/mihomo/", http.StripPrefix("/mihomo", mihomoProxy))

	// Serve metacubexd at /ui/ if provided (escape hatch for advanced users)
	if *metacubexdDir != "" {
		fileSrv := http.FileServer(http.Dir(*metacubexdDir))
		mux.Handle("/ui/", http.StripPrefix("/ui/", fileSrv))
	}

	// Serve our embedded UI at /
	dist, err := fs.Sub(webFS, "web/dist")
	if err != nil {
		log.Fatalf("embed.FS sub failed: %v", err)
	}
	uiSrv := http.FileServer(http.FS(dist))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// SPA fallback: serve index.html for unknown paths (no extension)
		if !strings.Contains(r.URL.Path, ".") && r.URL.Path != "/" {
			r.URL.Path = "/"
		}
		uiSrv.ServeHTTP(w, r)
	})

	log.Printf("fnos-mihomo-dashboard listening on %s", *listen)
	log.Printf("  mihomo-api : %s", *mihomoAPI)
	log.Printf("  config     : %s", *configFile)
	log.Printf("  log        : %s", *logFile)
	if *metacubexdDir != "" {
		log.Printf("  metacubexd : %s (mounted at /ui/)", *metacubexdDir)
	}

	srv := &http.Server{
		Addr:    *listen,
		Handler: mux,
	}
	log.Fatal(srv.ListenAndServe())
}
