package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

// Options are the parts of the Caddy config that come from where the worker
// runs rather than from the user's config.
type Options struct {
	// LogDir is the absolute folder the worker writes its logs to. It is the
	// only folder the worker writes to.
	LogDir string
}

// Log file names inside Options.LogDir.
const (
	AccessLogName = "access.log"
	WorkerLogName = "worker.log"
)

// Log rotation (S-18): each log is capped at about logRollMB * (logRollKeep+1).
const (
	logRollMB   = 10
	logRollKeep = 5
	logRollDays = 30
)

// serverName is the key of the single HTTP server in the Caddy config.
const serverName = "soireehost"

// BuildCaddyJSON turns a validated config into the Caddy JSON config the web
// worker loads. Only enabled sites with at least one hostname are served;
// every other request gets a 404 (S-06).
func BuildCaddyJSON(cfg config.Config, opts Options) ([]byte, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if !filepath.IsAbs(opts.LogDir) {
		return nil, errors.New("log folder must be an absolute path")
	}
	s := cfg.Server

	var routes, errRoutes []any
	var filesystems []any
	for _, site := range cfg.Sites {
		if !site.Enabled || len(site.Hostnames) == 0 {
			continue
		}
		match := []any{obj{"host": site.Hostnames}}
		headers := headerHandlers(site.EffectiveHeaders())

		chain := append([]any{}, headers...)
		chain = append(chain,
			obj{"handler": "soireehost_ratelimit", "per_minute": site.RateLimitPerMinute},
			obj{"handler": "soireehost_guard", "mode": site.Type, "allow_well_known": site.AllowWellKnown},
			obj{"handler": "request_body", "max_size": site.MaxBodyBytes},
		)
		switch site.Type {
		case config.TypeStatic:
			fsName := "site-" + site.ID
			filesystems = append(filesystems, obj{
				"name":        fsName,
				"file_system": obj{"backend": "soireehost_root", "root": site.Static.Root, "allow_well_known": site.AllowWellKnown},
			})
			fileServer := obj{
				"handler":     "file_server",
				"fs":          fsName,
				"root":        ".",
				"index_names": []string{"index.html", "index.htm"},
			}
			if site.Static.DirectoryListing {
				fileServer["browse"] = obj{}
			}
			chain = append(chain, fileServer)
		case config.TypeProxy:
			chain = append(chain, obj{
				"handler":   "reverse_proxy",
				"upstreams": []any{obj{"dial": site.Proxy.Target}},
				"headers": obj{"request": obj{
					// after StripForwarded removed any forged values, tell the
					// app the real client address (S-05)
					"set": obj{
						"X-Forwarded-For":  []string{"{http.vars.client_ip}"},
						"X-Forwarded-Host": []string{"{http.request.host}"},
					},
					"delete": []string{"Via"},
				}},
			})
		}
		routes = append(routes, obj{
			"match":    match,
			"handle":   []any{obj{"handler": "subroute", "routes": []any{obj{"handle": chain}}}},
			"terminal": true,
		})
		errRoutes = append(errRoutes, obj{
			"match":    match,
			"handle":   append(append([]any{}, headers...), errorResponse()),
			"terminal": true,
		})
	}
	// S-06: anything that did not match a site hostname gets a 404.
	defaults := config.DefaultHeaders()
	routes = append(routes, obj{"handle": append(headerHandlers(defaults),
		obj{"handler": "static_response", "status_code": 404, "body": "404 Not Found\n",
			"headers": obj{"Content-Type": []string{"text/plain; charset=utf-8"}}})})
	errRoutes = append(errRoutes, obj{"handle": append(headerHandlers(defaults), errorResponse())})

	server := obj{
		"listen":    []string{cfg.Listen},
		"protocols": []string{"h1"}, // no HTTP/3, so no UDP socket; cloudflared speaks HTTP/1.1
		// TLS ends at Cloudflare's edge; the worker holds no certificates
		"automatic_https":     obj{"disable": true},
		"max_header_bytes":    s.MaxHeaderBytes,
		"read_header_timeout": seconds(s.ReadHeaderTimeoutSeconds),
		"read_timeout":        seconds(s.ReadTimeoutSeconds),
		"idle_timeout":        seconds(s.IdleTimeoutSeconds),
		// S-05: only cloudflared on loopback talks to the worker, and the
		// client address it vouches for is CF-Connecting-IP
		"trusted_proxies":   obj{"source": "static", "ranges": []string{"127.0.0.1/32", "::1/128"}},
		"client_ip_headers": []string{"Cf-Connecting-Ip"},
		"routes":            routes,
		"errors":            obj{"routes": errRoutes},
		"logs":              obj{"default_logger_name": "access"},
	}

	apps := obj{
		"http": obj{"servers": obj{serverName: server}},
		// the TLS app is always loaded by the HTTP app; stop it writing
		// instance.uuid and lock files to the service profile
		"tls": obj{"disable_storage_clean": true, "disable_storage_check": true},
	}
	if len(filesystems) > 0 {
		apps["caddy.filesystems"] = obj{"filesystems": filesystems}
	}

	root := obj{
		// S-04: no admin endpoint, and never autosave the config to disk
		"admin": obj{"disabled": true, "config": obj{"persist": false}},
		"logging": obj{"logs": obj{
			// Caddy opens each log file once and keeps it for the life of
			// the process, sharing it across config reloads.
			"default": obj{
				"writer":  logWriter(filepath.Join(opts.LogDir, WorkerLogName)),
				"encoder": logEncoder(),
				"level":   "INFO",
				"exclude": []string{"http.log.access"},
			},
			"access": obj{
				"writer":  logWriter(filepath.Join(opts.LogDir, AccessLogName)),
				"encoder": logEncoder(),
				"level":   "INFO",
				"include": []string{"http.log.access.access"},
			},
		}},
		"apps": apps,
	}
	return json.Marshal(root)
}

type obj = map[string]any

func seconds(n int) string { return strconv.Itoa(n) + "s" }

// headerHandlers sets each security header only if the response does not
// already carry it, so a proxied app's own stricter policy is kept, and always
// removes the Server header (S-16).
func headerHandlers(h map[string]string) []any {
	out := []any{obj{"handler": "headers", "response": obj{"delete": []string{"Server"}, "deferred": true}}}
	for _, name := range config.ManagedHeaders() {
		v, ok := h[name]
		if !ok {
			continue
		}
		out = append(out, obj{"handler": "headers", "response": obj{
			"set":     obj{name: []string{v}},
			"require": obj{"headers": obj{name: nil}},
		}})
	}
	return out
}

func errorResponse() obj {
	return obj{
		"handler":     "static_response",
		"status_code": "{http.error.status_code}",
		"body":        "{http.error.status_code} {http.error.status_text}\n",
		"headers":     obj{"Content-Type": []string{"text/plain; charset=utf-8"}},
	}
}

func logWriter(file string) obj {
	return obj{
		"output":         "file",
		"filename":       file,
		"roll_size_mb":   logRollMB,
		"roll_keep":      logRollKeep,
		"roll_keep_days": logRollDays,
	}
}

// logEncoder wraps JSON with the S-18 filters.
func logEncoder() obj {
	return obj{
		"format": "filter",
		"wrap":   obj{"format": "json"},
		"fields": obj{
			"request>headers": obj{"filter": "soireehost_headers"},
			"resp_headers":    obj{"filter": "soireehost_headers"},
			"request>uri":     obj{"filter": "soireehost_query"},
		},
	}
}
