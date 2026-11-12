package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Severity classes, used as the tile colour.
const (
	sevYellow = "yellow" // the threshold was just crossed
	sevRed    = "red"    // the count is double the threshold or more
)

// Triggered is an alert whose threshold was crossed.
type Triggered struct {
	Alert  Alert
	Result *SearchResult
}

// Condition describes why the alert fired.
func (t Triggered) Condition() string {
	if t.Alert.CountType == "below" {
		return fmt.Sprintf("count %d is below the threshold of %d", t.Result.Count, t.Alert.Count)
	}
	return fmt.Sprintf("count %d is higher than the threshold of %d", t.Result.Count, t.Alert.Count)
}

// Severity decides the tile colour.
//
//	higher: yellow once count > threshold, red once count >= 2 x threshold
//	        (with a threshold of 0 every match is red)
//	below : yellow once count < threshold, red once count <= threshold / 2
func (t Triggered) Severity() string {
	count, threshold := t.Result.Count, int64(t.Alert.Count)
	if t.Alert.CountType == "below" {
		if count*2 <= threshold {
			return sevRed
		}
		return sevYellow
	}
	if count >= threshold*2 {
		return sevRed
	}
	return sevYellow
}

// formatRange renders the queried time range, e.g.
// "2026-10-13 17:55:00 → 18:00:00 IST", in the process's local time zone
// (set the TZ environment variable to change it).
func formatRange(from, to time.Time) string {
	from, to = from.Local(), to.Local()
	const day, clock = "2006-01-02", "15:04:05"
	if from.Format(day) == to.Format(day) {
		return from.Format(day+" "+clock) + " → " + to.Format(clock+" MST")
	}
	return from.Format(day+" "+clock) + " → " + to.Format(day+" "+clock+" MST")
}

// Attachment is a file attached to the email.
type Attachment struct {
	Name string
	Data []byte
}

// Email is a fully rendered message body plus its attachments.
type Email struct {
	Text        string
	HTML        string
	Attachments []Attachment
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// attachmentName turns an alert name into a safe, unique file name.
func attachmentName(alert string, used map[string]bool) string {
	base := strings.Trim(unsafeName.ReplaceAllString(alert, "_"), ".")
	if base == "" {
		base = "alert"
	}
	name := base + ".txt"
	for i := 2; used[name]; i++ {
		name = fmt.Sprintf("%s-%d.txt", base, i)
	}
	used[name] = true
	return name
}

// attachmentBody lists the matching log lines, oldest first.
func attachmentBody(t Triggered, from, to time.Time) []byte {
	var b strings.Builder
	n := len(t.Result.Lines)
	fmt.Fprintf(&b, "Alert:      %s\n", t.Alert.Name)
	fmt.Fprintf(&b, "Index:      %s\n", t.Alert.Index)
	fmt.Fprintf(&b, "Log line:   %s\n", t.Alert.Log)
	fmt.Fprintf(&b, "Time range: %s\n", formatRange(from, to))
	if int64(n) < t.Result.Count {
		fmt.Fprintf(&b, "Matches:    %d (the latest %d are listed below)\n", t.Result.Count, n)
	} else {
		fmt.Fprintf(&b, "Matches:    %d\n", t.Result.Count)
	}
	b.WriteString("\n")
	for i := n - 1; i >= 0; i-- { // Elasticsearch returned newest first
		l := t.Result.Lines[i]
		fmt.Fprintf(&b, "%s  %s\n", l.Time, strings.TrimRight(l.Message, "\r\n"))
	}
	return []byte(b.String())
}

type tileView struct {
	Name  string
	Count int64
	Class string
}

type pageView struct {
	Range string
	Tiles []tileView
	Files []string
}

const htmlTpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log alerts</title>
<style>
  body{margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#111827}
  .wrap{width:100%;max-width:640px;margin:0 auto;padding:16px;box-sizing:border-box}
  .range{background:#ffffff;border-radius:10px;padding:14px 16px;margin:0 0 14px}
  .range .label{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#6b7280}
  .range .value{font-size:16px;font-weight:600;margin-top:2px}
  .tiles{font-size:0;line-height:0;margin:0 -1.5%}
  .tile{display:inline-block;vertical-align:top;box-sizing:border-box;width:47%;margin:0 1.5% 12px;padding:16px;border-radius:10px;font-size:16px;line-height:1.3}
  .tile.yellow{background:#facc15;color:#422006}
  .tile.red{background:#dc2626;color:#ffffff}
  .tname{font-size:14px;font-weight:600;word-break:break-word}
  .tcount{font-size:34px;font-weight:700;margin-top:6px;line-height:1}
  .note{font-size:12px;color:#6b7280;margin:6px 4px 0;line-height:1.5}
  @media (max-width:480px){
    .wrap{padding:10px}
    .tiles{margin:0}
    .tile{width:100%;margin:0 0 12px}
  }
</style>
</head>
<body>
<div class="wrap">
  <div class="range">
    <div class="label">Time range</div>
    <div class="value">{{.Range}}</div>
  </div>
  <div class="tiles">
    {{range .Tiles}}<div class="tile {{.Class}}">
      <div class="tname">{{.Name}}</div>
      <div class="tcount">{{.Count}}</div>
    </div>{{end}}
  </div>
  {{if .Files}}<div class="note">Matching log lines are attached: {{range $i, $f := .Files}}{{if $i}}, {{end}}{{$f}}{{end}}</div>{{end}}
  <div class="note">Yellow: threshold just crossed. Red: double the threshold or more (half or less for &ldquo;below&rdquo; alerts).</div>
</div>
</body>
</html>`

var compiledTpl = template.Must(template.New("report").Parse(htmlTpl))

// buildEmail renders the HTML and plain-text bodies and the log-line attachments.
func buildEmail(items []Triggered, from, to time.Time) (*Email, error) {
	rng := formatRange(from, to)
	em := &Email{}
	used := map[string]bool{}
	view := pageView{Range: rng}

	var text strings.Builder
	fmt.Fprintf(&text, "Log alerts\nTime range: %s\n\n", rng)

	for _, t := range items {
		view.Tiles = append(view.Tiles, tileView{Name: t.Alert.Name, Count: t.Result.Count, Class: t.Severity()})
		fmt.Fprintf(&text, "%s: %d (%s)\n", t.Alert.Name, t.Result.Count, t.Severity())

		if len(t.Result.Lines) > 0 {
			name := attachmentName(t.Alert.Name, used)
			em.Attachments = append(em.Attachments, Attachment{Name: name, Data: attachmentBody(t, from, to)})
			view.Files = append(view.Files, name)
		}
	}
	if len(view.Files) > 0 {
		fmt.Fprintf(&text, "\nMatching log lines are attached: %s\n", strings.Join(view.Files, ", "))
	}
	em.Text = text.String()

	var buf bytes.Buffer
	if err := compiledTpl.Execute(&buf, view); err != nil {
		return nil, err
	}
	em.HTML = buf.String()
	return em, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// writeBase64 writes data base64-encoded in 76-character lines.
func writeBase64(w io.Writer, data []byte) error {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		if _, err := io.WriteString(w, enc[:76]+"\r\n"); err != nil {
			return err
		}
		enc = enc[76:]
	}
	_, err := io.WriteString(w, enc+"\r\n")
	return err
}

// buildMIME produces:
//
//	multipart/mixed
//	├── multipart/alternative
//	│   ├── text/plain
//	│   └── text/html      (preferred by mail clients, so it goes last)
//	└── one text/plain attachment per alert
func buildMIME(cfg SMTPConfig, to []string, subject string, em *Email) ([]byte, error) {
	domain := "localhost"
	if i := strings.LastIndex(cfg.FromAddress, "@"); i >= 0 {
		domain = cfg.FromAddress[i+1:]
	}

	// Inner multipart/alternative (text + html).
	var altBuf bytes.Buffer
	alt := multipart.NewWriter(&altBuf)
	addBody := func(ctype, body string) error {
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", ctype+"; charset=utf-8")
		h.Set("Content-Transfer-Encoding", "quoted-printable")
		w, err := alt.CreatePart(h)
		if err != nil {
			return err
		}
		qp := quotedprintable.NewWriter(w)
		if _, err := io.WriteString(qp, body); err != nil {
			return err
		}
		return qp.Close()
	}
	if err := addBody("text/plain", em.Text); err != nil {
		return nil, err
	}
	if err := addBody("text/html", em.HTML); err != nil {
		return nil, err
	}
	if err := alt.Close(); err != nil {
		return nil, err
	}

	// Outer multipart/mixed (body + attachments).
	var mixedBuf bytes.Buffer
	mixed := multipart.NewWriter(&mixedBuf)

	h := textproto.MIMEHeader{}
	h.Set("Content-Type", "multipart/alternative; boundary="+alt.Boundary())
	w, err := mixed.CreatePart(h)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(altBuf.Bytes()); err != nil {
		return nil, err
	}

	for _, a := range em.Attachments {
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", fmt.Sprintf(`text/plain; charset=utf-8; name="%s"`, a.Name))
		h.Set("Content-Transfer-Encoding", "base64")
		h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, a.Name))
		w, err := mixed.CreatePart(h)
		if err != nil {
			return nil, err
		}
		if err := writeBase64(w, a.Data); err != nil {
			return nil, err
		}
	}
	if err := mixed.Close(); err != nil {
		return nil, err
	}

	headers := []string{
		"From: " + cfg.From,
		"To: " + strings.Join(to, ", "),
		"Subject: " + mime.QEncoding.Encode("utf-8", subject),
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: <" + randHex(12) + "@" + domain + ">",
		"MIME-Version: 1.0",
		"Content-Type: multipart/mixed; boundary=" + mixed.Boundary(),
	}
	var out bytes.Buffer
	out.WriteString(strings.Join(headers, "\r\n") + "\r\n\r\n")
	out.Write(mixedBuf.Bytes())
	return out.Bytes(), nil
}

// sendMail delivers one message to all recipients using starttls, implicit TLS (ssl) or plain SMTP.
func sendMail(cfg SMTPConfig, to []string, subject string, em *Email) error {
	msg, err := buildMIME(cfg, to, subject, em)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Timeout: 20 * time.Second}
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}

	var conn net.Conn
	if cfg.Security == "ssl" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()

	if cfg.Security == "starttls" {
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(cfg.FromAddress); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("recipient %s: %w", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}