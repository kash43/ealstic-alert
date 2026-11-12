package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// LogLine is one matching log entry.
type LogLine struct {
	Time    string
	Message string
}

// SearchResult is the outcome of one alert query.
type SearchResult struct {
	Count int64 // exact number of matches in the window
	Lines []LogLine
}

// ESClient talks to Elasticsearch over HTTPS or plain HTTP.
type ESClient struct {
	cfg  ESConfig
	http *http.Client
}

// NewESClient builds an HTTP client. TLS settings (es.ca_cert,
// es.insecure_skip_verify) only apply when es.url starts with https://.
func NewESClient(cfg ESConfig) (*ESClient, error) {
	transport := &http.Transport{}

	if strings.HasPrefix(cfg.URL, "https://") {
		tlsCfg := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // opt-in via es.insecure_skip_verify
		}
		if cfg.CACert != "" {
			pem, err := os.ReadFile(cfg.CACert)
			if err != nil {
				return nil, fmt.Errorf("reading es.ca_cert: %w", err)
			}
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("es.ca_cert %s contains no valid PEM certificates", cfg.CACert)
			}
			tlsCfg.RootCAs = pool
		}
		transport.TLSClientConfig = tlsCfg
	} else {
		if cfg.CACert != "" || cfg.InsecureSkipVerify {
			log.Printf("warning: es.url uses http://, so es.ca_cert / es.insecure_skip_verify are ignored")
		}
		if cfg.APIKey != "" || cfg.Username != "" {
			log.Printf("warning: es.url uses http://, so credentials are sent unencrypted")
		}
	}
	if cfg.APIKey == "" && cfg.Username == "" {
		log.Printf("warning: no es.api_key or es.username configured, connecting to Elasticsearch without authentication")
	}

	return &ESClient{
		cfg:  cfg,
		http: &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}, nil
}

// searchURL builds <es.url>/<index>/_search. The index may be a comma-separated
// list and may contain wildcards (for example "fluent-bit-*,app-logs").
func (c *ESClient) searchURL(index string) string {
	parts := strings.Split(index, ",")
	escaped := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// '*' is valid in an index path; keep it readable.
		escaped = append(escaped, strings.ReplaceAll(url.PathEscape(part), "%2A", "*"))
	}
	return c.cfg.URL + "/" + strings.Join(escaped, ",") + "/_search"
}

type searchResponse struct {
	Hits struct {
		Total struct {
			Value int64 `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source map[string]any `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// esTime formats t for an Elasticsearch date range (UTC, millisecond precision).
func esTime(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

// Search counts log lines in `index` containing phrase in the time range
// [from, to) and returns up to MaxLogLines of the most recent ones. Using the
// exact same range for every alert means the email can state it precisely.
func (c *ESClient) Search(ctx context.Context, index, phrase string, from, to time.Time) (*SearchResult, error) {
	tsField, msgField := c.cfg.TimestampField, c.cfg.MessageField

	body := map[string]any{
		"size":             c.cfg.MaxLogLines,
		"track_total_hits": true, // exact count, not capped at 10,000
		"sort":             []any{map[string]any{tsField: map[string]any{"order": "desc"}}},
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					map[string]any{"range": map[string]any{tsField: map[string]any{
						"gte":    esTime(from),
						"lt":     esTime(to),
						"format": "strict_date_optional_time",
					}}},
					map[string]any{"match_phrase": map[string]any{msgField: phrase}},
				},
			},
		},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.searchURL(index), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	switch {
	case c.cfg.APIKey != "":
		req.Header.Set("Authorization", "ApiKey "+c.cfg.APIKey)
	case c.cfg.Username != "":
		req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("elasticsearch returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}

	var sr searchResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	res := &SearchResult{Count: sr.Hits.Total.Value}
	for _, h := range sr.Hits.Hits {
		res.Lines = append(res.Lines, LogLine{
			Time:    fieldString(h.Source, tsField),
			Message: fieldString(h.Source, msgField),
		})
	}
	return res, nil
}

// fieldString reads a field from _source, supporting both flat keys
// ("kubernetes.pod_name") and nested objects.
func fieldString(src map[string]any, path string) string {
	if v, ok := src[path]; ok {
		return toString(v)
	}
	var cur any = src
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = m[part]
		if !ok {
			return ""
		}
	}
	return toString(cur)
}

func toString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}