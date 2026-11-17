package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/jjezewski/gpbox/internal/config"
	"github.com/jjezewski/gpbox/internal/loginui"
	"github.com/jjezewski/gpbox/internal/openconnect"
	"github.com/jjezewski/gpbox/internal/saml"
	"github.com/jjezewski/gpbox/internal/session"
)

const healthFile = "/tmp/gpbox-connected"

type app struct {
	cfg    *config.Config
	store  *session.Store
	ui     *loginui.UI
	tunnel *openconnect.Tunnel

	mu             sync.Mutex
	user           string
	cookieSaved    string
	expires        string
	connectedSince string
	lastError      string
}

func (a *app) set(f func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f()
}

func (a *app) info() []loginui.Row {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows := []loginui.Row{
		{Label: "Portal", Value: a.cfg.Portal},
		{Label: "Mode", Value: a.cfg.Mode},
		{Label: "Client OS", Value: a.cfg.OS + " (" + a.cfg.ClientOS + ")"},
		{Label: "VPN user", Value: a.user},
		{Label: "Cookie saved", Value: a.cookieSaved},
		{Label: "Session expires", Value: a.expires},
		{Label: "Connected since", Value: a.connectedSince},
		{Label: "SOCKS5 proxy", Value: "port " + strconv.Itoa(a.cfg.SocksPort)},
	}
	for _, f := range a.cfg.Forwards {
		rows = append(rows, loginui.Row{Label: "Forward", Value: "port " + strconv.Itoa(f.Port) + " -> " + f.Target})
	}
	if len(a.cfg.Forwards) == 0 {
		rows = append(rows, loginui.Row{Label: "Forward", Value: "none (GP_FORWARDS is empty)"})
	}
	rows = append(rows, loginui.Row{Label: "Last error", Value: a.lastError})
	return rows
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	log.SetPrefix("[gpbox] ")

	cfg, err := config.Load()
	if err != nil {
		log.Print(err)
		os.Exit(2)
	}
	log.Printf("Portal %s, mode %s.", cfg.Portal, cfg.Mode)
	if len(cfg.Forwards) == 0 {
		log.Print("No GP_FORWARDS set: only the SOCKS5 proxy will be available.")
	}
	if cfg.LoginPassword == "" {
		log.Print("No GP_LOGIN_PASSWORD set: anyone who can reach the login page port can use it.")
	}

	a := &app{
		cfg:    cfg,
		store:  session.NewStore(cfg.DataDir, cfg.Portal, cfg.Mode, cfg.SessionKey),
		ui:     loginui.New(cfg.NoVNCDir, cfg.LoginPassword),
		tunnel: &openconnect.Tunnel{Client: openconnect.Client{OS: cfg.OS, HIP: cfg.HIP}},
	}
	a.ui.Info = a.info
	a.ui.SetStatus("starting")

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go a.ui.Serve(ctx, cfg.LoginPort)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigs
		stop()
		if !a.tunnel.Disconnect() {
			a.ui.Stop()
			log.Print("Stopped.")
			os.Exit(0)
		}
	}()

	a.run(ctx)
	log.Print("Stopped (the saved cookie is still valid).")
}

func (a *app) run(ctx context.Context) {
	failures := 0
	for ctx.Err() == nil {
		s := a.store.Load()
		if s == nil {
			var err error
			if s, err = a.login(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("Login failed: %v", err)
				a.set(func() { a.lastError = "login failed: " + err.Error() })
				a.ui.SetStatus("login failed, retrying in 30 s")
				sleep(ctx, 30*time.Second)
				continue
			}
		} else {
			log.Printf("Using saved cookie from %s.", s.SavedAt)
		}
		a.set(func() { a.user, a.cookieSaved = s.User, s.SavedAt })

		a.ui.SetStatus("connecting")
		connected, authErr, err := a.tunnel.Run(openconnect.TunnelOptions{
			Session:     s,
			Server:      a.cfg.Portal,
			SocksPort:   a.cfg.SocksPort,
			Forwards:    a.cfg.Forwards,
			OnConnected: a.onConnected,
			OnExpiry:    func(when string) { a.set(func() { a.expires = when }) },
		})
		_ = os.Remove(healthFile)
		a.set(func() { a.connectedSince = "" })
		if ctx.Err() != nil {
			return
		}

		switch {
		case connected:
			failures = 0
			a.ui.SetStatus("reconnecting")
			log.Print("Tunnel dropped, reconnecting with the same cookie in 5 s.")
			sleep(ctx, 5*time.Second)
		case authErr || failures+1 >= 3:
			failures = 0
			log.Print("Saved cookie was rejected: a new login is needed.")
			a.set(func() { a.lastError, a.cookieSaved, a.expires = "saved cookie was rejected", "", "" })
			a.store.Clear()
		default:
			failures++
			log.Printf("Connection failed (%v), attempt %d/3, retrying in 10 s.", err, failures)
			a.set(func() { a.lastError = fmt.Sprintf("connection failed: %v", err) })
			a.ui.SetStatus("connection failed, retrying")
			sleep(ctx, 10*time.Second)
		}
	}
}

func (a *app) login(ctx context.Context) (*session.Session, error) {
	if err := a.ui.Start(); err != nil {
		return nil, err
	}
	a.ui.SetStatus("login required")
	log.Printf("LOGIN REQUIRED: open http://localhost:%d%s (publish port %d to reach it)",
		a.cfg.LoginPort, loginui.Path, a.cfg.LoginPort)
	r, err := saml.Login(ctx, saml.Options{
		Portal:       a.cfg.Portal,
		Mode:         a.cfg.Mode,
		ClientOS:     a.cfg.ClientOS,
		ChromiumPath: a.cfg.ChromiumPath,
		Display:      loginui.Display,
	})
	a.ui.Stop()
	if err != nil {
		return nil, err
	}

	user := r.User
	if user == "" {
		user = "?"
	}
	log.Printf("SAML login OK as %s, requesting gateway cookie...", user)
	s, err := a.tunnel.Client.Authenticate(ctx, a.cfg.Portal, a.cfg.Mode, r.User, r.PreloginCookie)
	if err != nil {
		return nil, err
	}
	if err := a.store.Save(s); err != nil {
		log.Printf("Cookie could not be saved (%v). The next start will need a new login.", err)
	} else {
		log.Print("Cookie saved.")
	}
	return s, nil
}

func (a *app) onConnected() {
	_ = os.WriteFile(healthFile, nil, 0o644)
	a.set(func() { a.connectedSince, a.lastError = time.Now().Format("2006-01-02 15:04:05"), "" })
	a.ui.SetStatus("connected")
	log.Print("VPN connected. Inside the container:")
	for _, f := range a.cfg.Forwards {
		log.Printf("  port %-6d -> %s", f.Port, f.Target)
	}
	log.Printf("  port %-6d -> SOCKS5 proxy", a.cfg.SocksPort)
	log.Print("Publish these ports with docker run -p (or compose ports) to use them.")
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
