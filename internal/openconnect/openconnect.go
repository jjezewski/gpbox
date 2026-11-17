package openconnect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/jjezewski/gpbox/internal/config"
	"github.com/jjezewski/gpbox/internal/session"
)

type Client struct {
	OS  string
	HIP bool
}

func (c Client) args() []string {
	args := []string{"--protocol=gp", "--os=" + c.OS, "--non-inter"}
	if c.HIP {
		args = append(args, "--csd-wrapper=/usr/libexec/openconnect/hipreport.sh")
	}
	return args
}

var authVarRe = regexp.MustCompile(`^(COOKIE|HOST|CONNECT_URL|FINGERPRINT|RESOLVE)=(.*)$`)

func (c Client) Authenticate(ctx context.Context, server, mode, user, prelogin string) (*session.Session, error) {
	args := append(c.args(),
		"--authenticate",
		"--usergroup="+mode+":prelogin-cookie",
		"--user="+user,
		"--passwd-on-stdin",
		server)
	cmd := exec.CommandContext(ctx, "openconnect", args...)
	cmd.Stdin = strings.NewReader(prelogin + "\n")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()

	s := &session.Session{User: user}
	for _, line := range strings.Split(string(out), "\n") {
		m := authVarRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		v := ShellUnquote(m[2])
		switch m[1] {
		case "COOKIE":
			s.Cookie = v
		case "HOST":
			s.Host = v
		case "CONNECT_URL":
			s.ConnectURL = v
		case "FINGERPRINT":
			s.Fingerprint = v
		case "RESOLVE":
			s.Resolve = v
		}
	}
	if err != nil || s.Cookie == "" {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		return nil, fmt.Errorf("openconnect --authenticate failed: %v\n%s", err, msg)
	}
	return s, nil
}

func ShellUnquote(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], `'\''`, `'`)
	}
	return s
}

var (
	connectedRe = regexp.MustCompile(`Connected as |ESP tunnel connected|Configured as `)
	expiryRe    = regexp.MustCompile(`Session authentication will expire at (.+)`)
	authErrRe   = regexp.MustCompile(`(?i)cookie|unauthori[sz]ed|auth\S* fail|\b(401|403|512)\b|expired|invalid|rejected`)
)

type TunnelOptions struct {
	Session     *session.Session
	Server      string // used when the session has no connect URL
	SocksPort   int
	Forwards    []config.Forward
	OnConnected func()
	OnExpiry    func(when string)
}

type Tunnel struct {
	Client Client

	mu   sync.Mutex
	proc *os.Process
}

// Disconnect SIGHUP makes openconnect disconnect without logging out, so the saved cookie stays valid
func (t *Tunnel) Disconnect() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.proc == nil {
		return false
	}
	_ = t.proc.Signal(syscall.SIGHUP)
	return true
}

func (t *Tunnel) Run(o TunnelOptions) (connected, authError bool, err error) {
	script := fmt.Sprintf("ocproxy -g -D %d", o.SocksPort)
	for _, f := range o.Forwards {
		script += fmt.Sprintf(" -L %d:%s", f.Port, f.Target)
	}
	args := append(t.Client.args(), "--cookie-on-stdin", "--script-tun", "--script", script)
	s := o.Session
	if s.Fingerprint != "" {
		args = append(args, "--servercert="+s.Fingerprint)
	}
	if s.Resolve != "" {
		args = append(args, "--resolve="+s.Resolve)
	}
	server := firstNonEmpty(s.ConnectURL, s.Host, o.Server)
	args = append(args, server)

	cmd := exec.Command("openconnect", args...)
	cmd.Stdin = strings.NewReader(s.Cookie + "\n")
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return false, false, err
	}
	t.mu.Lock()
	t.proc = cmd.Process
	t.mu.Unlock()

	waitErr := make(chan error, 1)
	go func() {
		waitErr <- cmd.Wait()
		pw.Close()
	}()

	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		fmt.Println(line)
		if m := expiryRe.FindStringSubmatch(line); m != nil && o.OnExpiry != nil {
			o.OnExpiry(m[1])
		}
		switch {
		case !connected && connectedRe.MatchString(line):
			connected = true
			if o.OnConnected != nil {
				o.OnConnected()
			}
		case !connected && authErrRe.MatchString(line):
			authError = true
		}
	}
	_, _ = io.Copy(io.Discard, pr)
	err = <-waitErr

	t.mu.Lock()
	t.proc = nil
	t.mu.Unlock()
	return connected, authError, err
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
