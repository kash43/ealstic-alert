package main

import (
	"bufio"
	"fmt"
	"net/mail"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ESConfig holds the Elasticsearch connection settings.
type ESConfig struct {
	URL                string
	Username           string
	Password           string
	APIKey             string
	CACert             string
	InsecureSkipVerify bool
	TimestampField     string
	MessageField       string
	MaxLogLines        int
}

// SMTPConfig holds the email settings.
type SMTPConfig struct {
	Enabled       bool // false: triggered alerts are only written to the log
	Host          string
	Port          int
	Username      string
	Password      string
	From          string
	FromAddress   string // bare address used for the SMTP envelope
	Security      string // starttls | ssl | none
	SubjectPrefix string
}

// Alert is a single log-line alert definition.
type Alert struct {
	Name      string
	Subject   string // optional email subject for this alert; defaults to Name
	Index     string // Elasticsearch index, alias, data stream or pattern (comma-separated for several)
	Log       string
	CountType string // "below" or "higher"
	Count     int
	Emails    []string

	hasCount bool
}

// Config is the full application configuration.
type Config struct {
	ES       ESConfig
	SMTP     SMTPConfig
	Interval time.Duration
	Window   time.Duration
	Alerts   []Alert
}

type props map[string]string

var envRe = regexp.MustCompile(`\$\{ENV\.([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces ${ENV.NAME} with the value of the environment variable NAME.
func expandEnv(s string) (string, error) {
	var missing []string
	out := envRe.ReplaceAllStringFunc(s, func(m string) string {
		name := envRe.FindStringSubmatch(m)[1]
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("environment variable(s) not set: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// loadProps reads a key=value file. Lines starting with # or ! are comments.
// Only the first '=' splits key from value, so log lines may contain '='.
func loadProps(path string) (props, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	p := props{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		i := strings.Index(line, "=")
		if i < 0 {
			return nil, fmt.Errorf("%s:%d: expected key=value", path, lineNo)
		}
		key := strings.TrimSpace(line[:i])
		val, err := expandEnv(strings.TrimSpace(line[i+1:]))
		if err != nil {
			return nil, fmt.Errorf("%s:%d (%s): %w", path, lineNo, key, err)
		}
		p[key] = val
	}
	return p, sc.Err()
}

func (p props) str(key, def string) string {
	if v, ok := p[key]; ok && v != "" {
		return v
	}
	return def
}

func (p props) integer(key string, def int) (int, error) {
	v, ok := p[key]
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not an integer", key, v)
	}
	return n, nil
}

func (p props) boolean(key string, def bool) (bool, error) {
	v, ok := p[key]
	if !ok || v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %q is not a boolean", key, v)
	}
	return b, nil
}

func (p props) duration(key string, def time.Duration) (time.Duration, error) {
	v, ok := p[key]
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: %q is not a valid positive duration (e.g. 5m, 1h)", key, v)
	}
	return d, nil
}

// LoadConfig reads and validates the configuration file.
func LoadConfig(path string) (*Config, error) {
	p, err := loadProps(path)
	if err != nil {
		return nil, err
	}

	var errs []string
	check := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}

	cfg := &Config{}

	// ---- Elasticsearch ----
	cfg.ES = ESConfig{
		URL:            strings.TrimRight(p.str("es.url", ""), "/"),
		Username:       p.str("es.username", ""),
		Password:       p.str("es.password", ""),
		APIKey:         p.str("es.api_key", ""),
		CACert:         p.str("es.ca_cert", ""),
		TimestampField: p.str("es.timestamp_field", "@timestamp"),
		MessageField:   p.str("es.message_field", "log"),
	}
	var e error
	cfg.ES.InsecureSkipVerify, e = p.boolean("es.insecure_skip_verify", false)
	check(e)
	cfg.ES.MaxLogLines, e = p.integer("es.max_log_lines", 1000)
	check(e)
	// 10000 is Elasticsearch's default index.max_result_window.
	if cfg.ES.MaxLogLines < 0 || cfg.ES.MaxLogLines > 10000 {
		check(fmt.Errorf("es.max_log_lines must be between 0 and 10000"))
	}
	if !strings.HasPrefix(cfg.ES.URL, "https://") && !strings.HasPrefix(cfg.ES.URL, "http://") {
		check(fmt.Errorf("es.url is required and must start with https:// or http://"))
	}

	// Authentication: API key, or username + password. Not both.
	hasUser := cfg.ES.Username != "" || cfg.ES.Password != ""
	switch {
	case cfg.ES.APIKey != "" && hasUser:
		check(fmt.Errorf("set either es.api_key or es.username/es.password, not both"))
	case hasUser && (cfg.ES.Username == "" || cfg.ES.Password == ""):
		check(fmt.Errorf("es.username and es.password must be set together"))
	}

	// ---- Schedule ----
	cfg.Interval, e = p.duration("check.interval", 5*time.Minute)
	check(e)
	cfg.Window, e = p.duration("check.window", cfg.Interval)
	check(e)

	// ---- SMTP ----
	cfg.SMTP = SMTPConfig{
		Host:          p.str("smtp.host", ""),
		Username:      p.str("smtp.username", ""),
		Password:      p.str("smtp.password", ""),
		From:          p.str("smtp.from", ""),
		Security:      strings.ToLower(p.str("smtp.security", "starttls")),
		SubjectPrefix: p.str("smtp.subject_prefix", "[Log Alerts]"),
	}
	cfg.SMTP.Enabled, e = p.boolean("smtp.enabled", true)
	check(e)
	cfg.SMTP.Port, e = p.integer("smtp.port", 587)
	check(e)
	// The mail server settings only matter when email is enabled.
	if cfg.SMTP.Enabled {
		if cfg.SMTP.Host == "" {
			check(fmt.Errorf("smtp.host is required (or set smtp.enabled=false)"))
		}
		switch cfg.SMTP.Security {
		case "starttls", "ssl", "none":
		default:
			check(fmt.Errorf("smtp.security must be starttls, ssl or none"))
		}
		if addr, err := mail.ParseAddress(cfg.SMTP.From); err != nil {
			check(fmt.Errorf("smtp.from is required and must be a valid address: %v", err))
		} else {
			cfg.SMTP.FromAddress = addr.Address
		}
	}

	// ---- Alerts ----
	alerts := map[string]*Alert{}
	get := func(name string) *Alert {
		a, ok := alerts[name]
		if !ok {
			a = &Alert{Name: name}
			alerts[name] = a
		}
		return a
	}
	for k, v := range p {
		if !strings.HasPrefix(k, "alerts.") {
			continue
		}
		rest := strings.TrimPrefix(k, "alerts.")
		switch {
		case strings.HasSuffix(rest, ".count.type"):
			get(strings.TrimSuffix(rest, ".count.type")).CountType = strings.ToLower(v)
		case strings.HasSuffix(rest, ".count.count"):
			a := get(strings.TrimSuffix(rest, ".count.count"))
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				check(fmt.Errorf("%s: %q is not a non-negative integer", k, v))
				continue
			}
			a.Count, a.hasCount = n, true
		case strings.HasSuffix(rest, ".log"):
			get(strings.TrimSuffix(rest, ".log")).Log = v
		case strings.HasSuffix(rest, ".index"):
			get(strings.TrimSuffix(rest, ".index")).Index = strings.TrimSpace(v)
		case strings.HasSuffix(rest, ".subject"):
			get(strings.TrimSuffix(rest, ".subject")).Subject = strings.TrimSpace(v)
		case strings.HasSuffix(rest, ".email"):
			a := get(strings.TrimSuffix(rest, ".email"))
			seen := map[string]bool{}
			for _, raw := range strings.FieldsFunc(v, func(r rune) bool {
				return r == ',' || r == ';' || unicode.IsSpace(r)
			}) {
				addr, err := mail.ParseAddress(raw)
				if err != nil {
					check(fmt.Errorf("%s: invalid address %q", k, raw))
					continue
				}
				lower := strings.ToLower(addr.Address)
				if !seen[lower] {
					seen[lower] = true
					a.Emails = append(a.Emails, lower)
				}
			}
			sort.Strings(a.Emails) // stable order so identical lists can be grouped
		default:
			check(fmt.Errorf("unknown key %q", k))
		}
	}

	names := make([]string, 0, len(alerts))
	for n := range alerts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a := alerts[n]
		switch {
		case a.Index == "":
			check(fmt.Errorf("alerts.%s.index is required", n))
		case a.Log == "":
			check(fmt.Errorf("alerts.%s.log is required", n))
		case a.CountType != "below" && a.CountType != "higher":
			check(fmt.Errorf("alerts.%s.count.type must be \"below\" or \"higher\"", n))
		case !a.hasCount:
			check(fmt.Errorf("alerts.%s.count.count is required", n))
		case len(a.Emails) == 0:
			check(fmt.Errorf("alerts.%s.email needs at least one address", n))
		default:
			cfg.Alerts = append(cfg.Alerts, *a)
		}
	}
	if len(alerts) == 0 {
		check(fmt.Errorf("no alerts defined (alerts.<name>.log ...)"))
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return cfg, nil
}