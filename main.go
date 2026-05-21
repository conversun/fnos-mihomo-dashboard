package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/conversun/fnos-mihomo-dashboard/internal/config"
	"github.com/conversun/fnos-mihomo-dashboard/internal/handlers"
	"github.com/conversun/fnos-mihomo-dashboard/internal/supervisor"
	_ "github.com/breml/rootcerts" // embed Mozilla CA bundle so HTTPS works even without system ca-certificates
)

//go:embed web/dist
var webFS embed.FS

func main() {
	listen := flag.String("listen", ":9097", "listen address")
	mihomoAPI := flag.String("mihomo-api", "http://127.0.0.1:9090", "mihomo internal API")
	configFile := flag.String("config", "/etc/mihomo/config.yaml", "mihomo config.yaml path")
	logFile := flag.String("log", "/var/log/mihomo.log", "mihomo log file path")
	metacubexdDir := flag.String("metacubexd", "", "optional metacubexd static dir to serve at /clash/")
	mihomoBin := flag.String("mihomo-bin", "", "path to the mihomo executable (enables ON/OFF supervisor)")
	mihomoConfigDir := flag.String("mihomo-config-dir", "", "directory passed to `mihomo -d <dir>` (defaults to dirname of -config)")
	subRefreshHours := flag.Int("sub-refresh-hours", 12, "auto-refresh subscription every N hours (0 = off)")
	flag.Parse()

	cfgMgr := config.New(*configFile)
	if !cfgMgr.Exists() {
		if werr := cfgMgr.WriteMinimalConfig(); werr != nil {
			log.Fatalf("write minimal config: %v", werr)
		}
		log.Printf("wrote minimal config.yaml")
	}

	var sup *supervisor.Supervisor
	if *mihomoBin != "" {
		confDir := *mihomoConfigDir
		if confDir == "" { confDir = filepath.Dir(*configFile) }
		sup = supervisor.New(*mihomoBin, confDir, *logFile)
		if err := sup.Start(); err != nil {
			log.Printf("warn: initial mihomo start failed: %v", err)
		} else {
			log.Printf("mihomo supervised, pid=%d, config-dir=%s", sup.PID(), confDir)
		}
	}

	mihomoURL, err := url.Parse(*mihomoAPI)
	if err != nil {
		log.Fatalf("invalid mihomo-api: %v", err)
	}

	mux := http.NewServeMux()

	// Our API
	h := handlers.New(*configFile, *logFile, mihomoURL, sup)
	mux.HandleFunc("/api/subscription", h.Subscription)
	mux.HandleFunc("/api/status", h.Status)
	mux.HandleFunc("/api/logs", h.Logs)
	mux.HandleFunc("/api/reload", h.Reload)
	mux.HandleFunc("/api/overrides", h.Overrides)
	mux.HandleFunc("/api/config", h.Config)
	mux.HandleFunc("/api/subscription/info", h.SubscriptionInfo)
	mux.HandleFunc("/api/subscription/refresh", h.SubscriptionRefresh)
	mux.HandleFunc("/api/mihomo/start", h.MihomoStart)
	mux.HandleFunc("/api/mihomo/stop", h.MihomoStop)
	mux.HandleFunc("/api/mihomo/restart", h.MihomoRestart)

	// Reverse proxy to mihomo RESTful API (for clients that need raw mihomo API)
	mihomoProxy := httputil.NewSingleHostReverseProxy(mihomoURL)
	mux.Handle("/mihomo/", http.StripPrefix("/mihomo", mihomoProxy))

	// Serve metacubexd's config.js dynamically so it auto-connects through our reverse proxy.
	// Browser side: defaultBackendURL = '<origin>/mihomo' → dashboard /mihomo/* → mihomo 127.0.0.1
	mux.HandleFunc("/clash/config.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("window.__METACUBEXD_CONFIG__ = { defaultBackendURL: window.location.origin + '/mihomo' };\n"))
	})

	// Serve metacubexd at /clash/ if provided (escape hatch for advanced users)
	if *metacubexdDir != "" {
		fileSrv := http.FileServer(http.Dir(*metacubexdDir))
		mux.Handle("/clash/", http.StripPrefix("/clash/", fileSrv))
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
		log.Printf("  metacubexd : %s (mounted at /clash/)", *metacubexdDir)
	}

	// Auto-refresh subscription every N hours (mihomo's own proxy-providers.interval
	// already does this, but we re-trigger to be sure + refresh subscription-userinfo)
	if *subRefreshHours > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(*subRefreshHours) * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				log.Println("auto-refresh subscription tick")
				req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1"+*listen+"/api/subscription/refresh", nil)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					log.Printf("auto-refresh failed: %v", err)
					continue
				}
				resp.Body.Close()
			}
		}()
	}

	srv := &http.Server{
		Addr:    *listen,
		Handler: mux,
	}
	log.Fatal(srv.ListenAndServe())
}
