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

	_ "github.com/breml/rootcerts" // embed Mozilla CA bundle so HTTPS works even without system ca-certificates
	"github.com/conversun/fnos-mihomo-dashboard/internal/auth"
	"github.com/conversun/fnos-mihomo-dashboard/internal/config"
	"github.com/conversun/fnos-mihomo-dashboard/internal/handlers"
	"github.com/conversun/fnos-mihomo-dashboard/internal/supervisor"
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
	// Older builds wrote these world-readable; they hold node passwords and
	// the controller secret.
	cfgMgr.TightenExistingPerms()
	if !cfgMgr.Exists() {
		if werr := cfgMgr.WriteMinimalConfig(); werr != nil {
			log.Fatalf("write minimal config: %v", werr)
		}
		log.Printf("wrote minimal config.yaml")
	}

	var sup *supervisor.Supervisor
	if *mihomoBin != "" {
		confDir := *mihomoConfigDir
		if confDir == "" {
			confDir = filepath.Dir(*configFile)
		}
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

	// Management auth. mihomo's controller is bound to 127.0.0.1 so it is not
	// network-reachable; our /mihomo/* proxy undoes that, so the whole surface
	// must be authenticated. Loopback stays open so the local UI, the CLI and
	// the auto-refresh ticker keep working without configuration.
	confDirForToken := *mihomoConfigDir
	if confDirForToken == "" {
		confDirForToken = filepath.Dir(*configFile)
	}
	adminToken, err := auth.LoadOrCreateToken(confDirForToken)
	if err != nil {
		log.Fatalf("admin token: %v", err)
	}
	guard := auth.New(adminToken, true)

	mux := http.NewServeMux()

	// Our API
	h := handlers.New(*configFile, *logFile, mihomoURL, sup)
	mux.Handle("/api/subscription", guard.ProtectFunc(h.Subscription))
	mux.Handle("/api/status", guard.ProtectFunc(h.Status))
	mux.Handle("/api/logs", guard.ProtectFunc(h.Logs))
	mux.Handle("/api/reload", guard.ProtectFunc(h.Reload))
	mux.Handle("/api/overrides", guard.ProtectFunc(h.Overrides))
	mux.Handle("/api/config", guard.ProtectFunc(h.Config))
	mux.Handle("/api/subscription/info", guard.ProtectFunc(h.SubscriptionInfo))
	mux.Handle("/api/subscription/refresh", guard.ProtectFunc(h.SubscriptionRefresh))
	mux.Handle("/api/mihomo/start", guard.ProtectFunc(h.MihomoStart))
	mux.Handle("/api/mihomo/stop", guard.ProtectFunc(h.MihomoStop))
	mux.Handle("/api/mihomo/restart", guard.ProtectFunc(h.MihomoRestart))

	// Reverse proxy to mihomo RESTful API (for clients that need raw mihomo API)
	mihomoProxy := httputil.NewSingleHostReverseProxy(mihomoURL)
	// THE critical one: this forwards every method/path to mihomo's controller,
	// which the generated config leaves with an empty secret.
	mux.Handle("/mihomo/", guard.Protect(http.StripPrefix("/mihomo", mihomoProxy)))

	// Serve metacubexd's config.js dynamically so it auto-connects through our reverse proxy.
	// Browser side: defaultBackendURL = '<origin>/mihomo' → dashboard /mihomo/* → mihomo 127.0.0.1
	mux.Handle("/clash/config.js", guard.ProtectFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("window.__METACUBEXD_CONFIG__ = { defaultBackendURL: window.location.origin + '/mihomo' };\n"))
	}))

	// Serve metacubexd at /clash/ if provided (escape hatch for advanced users)
	if *metacubexdDir != "" {
		fileSrv := http.FileServer(http.Dir(*metacubexdDir))
		mux.Handle("/clash/", guard.Protect(http.StripPrefix("/clash/", fileSrv)))
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
	log.Printf("  admin token: %s (loopback exempt)", filepath.Join(confDirForToken, auth.TokenFileName))
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

	// Timeouts: the service is root-run and unauthenticated callers can still
	// open sockets, so a slowloris must not be able to exhaust it.
	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       3 * time.Minute,
	}
	log.Fatal(srv.ListenAndServe())
}
