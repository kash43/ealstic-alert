package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	cfgPath := flag.String("config", "alerts.properties", "path to the configuration file")
	once := flag.Bool("once", false, "run a single check and exit (useful for a Kubernetes CronJob)")
	flag.Parse()

	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}
	es, err := NewESClient(cfg.ES)
	if err != nil {
		log.Fatalf("elasticsearch client: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("loaded %d alert(s); interval=%s window=%s", len(cfg.Alerts), cfg.Interval, cfg.Window)

	runCheck(ctx, cfg, es)
	if *once {
		return
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			return
		case <-ticker.C:
			runCheck(ctx, cfg, es)
		}
	}
}

type emailGroup struct {
	to    []string
	items []Triggered
}

// emailSubject builds "<prefix> <alert subject>, <alert subject>, ...".
// Each alert contributes its alerts.<name>.subject, or its name if none is set.
// Long lists are shortened to the first three plus a "+N more" suffix.
func emailSubject(prefix string, items []Triggered) string {
	const maxShown = 3
	var subjects []string
	seen := map[string]bool{}
	for _, t := range items {
		s := t.Alert.Subject
		if s == "" {
			s = t.Alert.Name
		}
		if !seen[s] {
			seen[s] = true
			subjects = append(subjects, s)
		}
	}
	more := ""
	if len(subjects) > maxShown {
		more = fmt.Sprintf(" +%d more", len(subjects)-maxShown)
		subjects = subjects[:maxShown]
	}
	return strings.TrimSpace(prefix + " " + strings.Join(subjects, ", ") + more)
}

// runCheck evaluates every alert, then sends one email per distinct recipient list.
func runCheck(ctx context.Context, cfg *Config, es *ESClient) {
	// One time range for every alert, so the email can state it exactly.
	to := time.Now()
	from := to.Add(-cfg.Window)
	rng := formatRange(from, to)

	var triggered []Triggered

	for _, a := range cfg.Alerts {
		res, err := es.Search(ctx, a.Index, a.Log, from, to)
		if err != nil {
			log.Printf("alert %q (index %s): search failed: %v", a.Name, a.Index, err)
			continue
		}
		log.Printf("alert %q (index %s): %d match(es), %s", a.Name, a.Index, res.Count, rng)

		// Zero matches are never reported.
		if res.Count == 0 {
			continue
		}
		fire := (a.CountType == "below" && res.Count < int64(a.Count)) ||
			(a.CountType == "higher" && res.Count > int64(a.Count))
		if fire {
			triggered = append(triggered, Triggered{Alert: a, Result: res})
		}
	}

	if len(triggered) == 0 {
		log.Println("no alerts triggered")
		return
	}

	// Alerts that share the same recipient list go into the same email.
	groups := map[string]*emailGroup{}
	for _, t := range triggered {
		key := strings.Join(t.Alert.Emails, ",")
		g, ok := groups[key]
		if !ok {
			g = &emailGroup{to: t.Alert.Emails}
			groups[key] = g
		}
		g.items = append(g.items, t)
	}

	for _, g := range groups {
		// Email disabled: just write one log line per recipient group.
		if !cfg.SMTP.Enabled {
			parts := make([]string, 0, len(g.items))
			for _, t := range g.items {
				parts = append(parts, fmt.Sprintf("%s=%d [%s] (%s)", t.Alert.Name, t.Result.Count, t.Severity(), t.Condition()))
			}
			log.Printf("email disabled (smtp.enabled=false), not sending to %v: %d alert(s) triggered, %s: %s",
				g.to, len(g.items), rng, strings.Join(parts, "; "))
			continue
		}

		em, err := buildEmail(g.items, from, to)
		if err != nil {
			log.Printf("building email for %v: %v", g.to, err)
			continue
		}
		subject := emailSubject(cfg.SMTP.SubjectPrefix, g.items)

		if err := sendMail(cfg.SMTP, g.to, subject, em); err != nil {
			log.Printf("sending email to %v failed: %v", g.to, err)
			continue
		}
		log.Printf("email sent to %v with %d alert(s), %d attachment(s): %s", g.to, len(g.items), len(em.Attachments), subject)
	}
}