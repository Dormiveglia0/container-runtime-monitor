package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"container-runtime-monitor/internal/storage"
)

type pageData struct {
	Title  string
	Active string
	Stats  storage.DashboardStats
	Events []storage.EventRecord
	Alerts []storage.AlertRecord
}

var page = template.Must(template.New("page").Funcs(template.FuncMap{
	"shortID": shortID,
	"sev":     severityClass,
	"etype":   eventTypeClass,
	"hex":     hexFlags,
}).Parse(pageHTML))

func main() {
	addr := flag.String("addr", ":8080", "web listen address")
	dbPath := flag.String("db", "data/monitor.db", "sqlite database path")
	flag.Parse()

	store, err := storage.Open(*dbPath)
	if err != nil {
		log.Fatalf("open sqlite database: %v", err)
	}
	defer store.Close()

	mux := http.NewServeMux()

	mux.HandleFunc("/", render(store, "Dashboard", "home", 20))
	mux.HandleFunc("/events", render(store, "Events", "events", 200))
	mux.HandleFunc("/alerts", render(store, "Alerts", "alerts", 200))

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		stats, err := store.Stats()
		writeJSON(w, stats, err)
	})

	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		events, err := store.ListEvents(200)
		writeJSON(w, events, err)
	})

	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		alerts, err := store.ListAlerts(200)
		writeJSON(w, alerts, err)
	})

	fmt.Printf("web console started: http://127.0.0.1%s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func render(store *storage.Store, title, active string, limit int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := store.Stats()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		events, err := store.ListEvents(limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		alerts, err := store.ListAlerts(limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := pageData{Title: title, Active: active, Stats: stats, Events: events, Alerts: alerts}
		if err := page.Execute(w, data); err != nil {
			log.Printf("render page: %v", err)
		}
	}
}

func writeJSON(w http.ResponseWriter, value any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}

func shortID(id string) string {
	if len(id) > 12 { return id[:12] }
	return id
}

func severityClass(severity string) string {
	switch severity {
	case "critical": return "sev-critical"
	case "high": return "sev-high"
	case "medium": return "sev-medium"
	case "low": return "sev-low"
	default: return "sev-info"
	}
}

func eventTypeClass(eventType string) string { return "event-" + strings.ReplaceAll(eventType, "_", "-") }

func hexFlags(flags int64) string {
	if flags == 0 { return "-" }
	return fmt.Sprintf("0x%x", flags)
}

const pageHTML = `
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} - Container Runtime Monitor</title>
<style>
:root { color-scheme: light; --bg:#f6f7f9; --panel:#fff; --line:#d9dee7; --text:#1f2937; --muted:#6b7280; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
header { height:56px; display:flex; align-items:center; justify-content:space-between; padding:0 24px; background:#111827; color:white; }
header strong { font-size:16px; }
nav { display:flex; gap:8px; }
nav a { color:#d1d5db; text-decoration:none; padding:6px 10px; border-radius:6px; }
nav a.active { background:#374151; color:white; }
main { padding:24px; max-width:1440px; margin:0 auto; }
.stats { display:grid; grid-template-columns:repeat(5,minmax(140px,1fr)); gap:12px; margin-bottom:20px; }
.stat { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; }
.stat .label { color:var(--muted); font-size:12px; }
.stat .value { font-size:26px; font-weight:700; margin-top:2px; }
.section { margin-top:22px; }
.section h2 { margin:0 0 10px; font-size:18px; }
table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
th,td { border-bottom:1px solid var(--line); padding:9px 10px; text-align:left; vertical-align:top; }
th { background:#eef1f5; font-size:12px; color:#4b5563; }
tr:last-child td { border-bottom:0; }
.code { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12px; overflow-wrap:anywhere; }
.muted { color:var(--muted); }
.badge { display:inline-block; padding:2px 7px; border-radius:999px; font-size:12px; font-weight:700; }
.event-execve { background:#e0f2fe; color:#075985; }
.event-file-open { background:#ede9fe; color:#5b21b6; }
.sev-critical { background:#fee2e2; color:#991b1b; }
.sev-high { background:#ffedd5; color:#9a3412; }
.sev-medium { background:#fef3c7; color:#92400e; }
.sev-low { background:#dcfce7; color:#166534; }
.empty { padding:24px; background:var(--panel); border:1px solid var(--line); border-radius:8px; color:var(--muted); }
@media (max-width:900px) { header{height:auto;align-items:flex-start;gap:10px;flex-direction:column;padding:14px;} main{padding:14px;} .stats{grid-template-columns:repeat(2,minmax(130px,1fr));} table{display:block;overflow-x:auto;} }
</style>
</head>
<body>
<header><strong>Container Runtime Monitor</strong><nav><a href="/" class="{{if eq .Active "home"}}active{{end}}">Dashboard</a><a href="/events" class="{{if eq .Active "events"}}active{{end}}">Events</a><a href="/alerts" class="{{if eq .Active "alerts"}}active{{end}}">Alerts</a></nav></header>
<main>
<section class="stats"><div class="stat"><div class="label">Events</div><div class="value">{{.Stats.TotalEvents}}</div></div><div class="stat"><div class="label">Alerts</div><div class="value">{{.Stats.TotalAlerts}}</div></div><div class="stat"><div class="label">Critical</div><div class="value">{{.Stats.CriticalAlerts}}</div></div><div class="stat"><div class="label">High</div><div class="value">{{.Stats.HighAlerts}}</div></div><div class="stat"><div class="label">Containers</div><div class="value">{{.Stats.Containers}}</div></div></section>
{{if ne .Active "alerts"}}<section class="section"><h2>{{if eq .Active "events"}}Events{{else}}Recent Events{{end}}</h2>{{if .Events}}<table><thead><tr><th>ID</th><th>Time</th><th>Type</th><th>Container</th><th>Image</th><th>PID</th><th>Comm</th><th>Target</th><th>Args / Flags</th></tr></thead><tbody>{{range .Events}}<tr><td>{{.ID}}</td><td class="muted">{{.TSText}}</td><td><span class="badge {{etype .EventType}}">{{.EventType}}</span></td><td>{{.ContainerName}}<div class="muted code">{{shortID .ContainerID}}</div></td><td>{{.ImageName}}</td><td>{{.PID}}</td><td class="code">{{.Comm}}</td><td class="code">{{.Filename}}</td><td class="code">{{if eq .EventType "file_open"}}{{hex .FileFlags}}{{else}}{{.ArgsJSON}}{{end}}</td></tr>{{end}}</tbody></table>{{else}}<div class="empty">No events recorded.</div>{{end}}</section>{{end}}
{{if ne .Active "events"}}<section class="section"><h2>{{if eq .Active "alerts"}}Alerts{{else}}Recent Alerts{{end}}</h2>{{if .Alerts}}<table><thead><tr><th>ID</th><th>Time</th><th>Severity</th><th>Rule</th><th>Container</th><th>Image</th><th>PID</th><th>Message</th></tr></thead><tbody>{{range .Alerts}}<tr><td>{{.ID}}</td><td class="muted">{{.TSText}}</td><td><span class="badge {{sev .Severity}}">{{.Severity}}</span></td><td class="code">{{.RuleID}}</td><td>{{.ContainerName}}<div class="muted code">{{shortID .ContainerID}}</div></td><td>{{.ImageName}}</td><td>{{.PID}}</td><td>{{.Message}}</td></tr>{{end}}</tbody></table>{{else}}<div class="empty">No alerts recorded.</div>{{end}}</section>{{end}}
</main></body></html>
`
