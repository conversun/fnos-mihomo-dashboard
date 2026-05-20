# fnos-mihomo-dashboard

Lightweight management dashboard for [mihomo](https://github.com/MetaCubeX/mihomo)
(Clash.Meta) when packaged as a [fnOS](https://www.fnnas.com/) third-party app.

## Why?

Direct integration of mihomo's official dashboard ([MetaCubeXD](https://github.com/MetaCubeX/metacubexd))
into fnOS hit several friction points:

- mihomo's `SAFE_PATHS` check rejects `external-ui` outside the home dir
- Loading a user's subscription yaml via dashboard rewrites `external-controller`,
  causing mihomo to switch ports and breaking the dashboard connection
- metacubexd's ky-based fetch is hard to intercept transparently

This dashboard is a thin Go binary that **fronts mihomo on port 9097**, exposes a
minimal subscription/status UI for daily use, and reverse-proxies mihomo's full
RESTful API + (optionally) embeds metacubexd at `/ui/` for advanced users.

## Architecture

```
:9097 (fnos-mihomo-dashboard)
  ├─ /          → Our minimal UI (subscription + status + logs)
  ├─ /api/*     → Our HTTP API
  ├─ /mihomo/*  → Reverse proxy to mihomo RESTful API (127.0.0.1:9090)
  └─ /ui/*      → MetaCubeXD static dashboard (advanced)
```

mihomo itself binds to `127.0.0.1:9090` and is fully controlled by this dashboard
via its config file. The user never edits `external-controller` directly.

## Build

```bash
go build -o fnos-mihomo-dashboard .
```

Cross-compile:
```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/fnos-mihomo-dashboard-linux-amd64 .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/fnos-mihomo-dashboard-linux-arm64 .
```

## Run

```bash
./fnos-mihomo-dashboard \
  -listen :9097 \
  -mihomo-api http://127.0.0.1:9090 \
  -config /etc/mihomo/config.yaml \
  -log /var/log/mihomo.log \
  -metacubexd /opt/metacubexd
```

## API

- `GET  /api/subscription` → `{"url": "..."}`
- `POST /api/subscription` body `{"url": "..."}` — sets fnos-subscription provider, triggers reload
- `GET  /api/status` → mihomo version + current proxy
- `GET  /api/logs` → last 100 lines of mihomo.log
- `GET  /api/proxies` → mihomo /proxies (raw)
- `POST /api/proxies/select` body `{"group":"PROXY","name":"..."}`
- `POST /api/reload` → force mihomo to reload config.yaml

## License

MIT
