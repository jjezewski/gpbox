package loginui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

const (
	Display = ":99"
	Path    = "/vnc.html?autoconnect=1&resize=scale"

	vncAddr    = "127.0.0.1:5900"
	cookieName = "gpbox_auth"
)

type UI struct {
	NoVNCDir string
	Password string
	Info     func() []Row

	token  string
	mu     sync.Mutex
	procs  []*exec.Cmd
	active atomic.Bool
	status atomic.Value
}

type Row struct {
	Label string
	Value string
}

//go:embed templates
var templates embed.FS

var pages = template.Must(template.ParseFS(templates, "templates/*.html"))

func New(novncDir, password string) *UI {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return &UI{NoVNCDir: novncDir, Password: password, token: hex.EncodeToString(b)}
}

func (u *UI) SetStatus(s string) { u.status.Store(s) }

func (u *UI) getStatus() string {
	if s, ok := u.status.Load().(string); ok {
		return s
	}
	return "starting"
}

func (u *UI) Start() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.active.Load() {
		return nil
	}
	_ = os.Remove("/tmp/.X99-lock")
	xvfb := exec.Command("Xvfb", Display, "-screen", "0", "1280x800x24", "-nolisten", "tcp")
	if err := xvfb.Start(); err != nil {
		return fmt.Errorf("cannot start Xvfb: %w", err)
	}
	u.procs = append(u.procs, xvfb)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat("/tmp/.X11-unix/X99"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	vnc := exec.Command("x11vnc", "-display", Display, "-localhost", "-rfbport", "5900",
		"-forever", "-shared", "-nopw", "-quiet")
	if err := vnc.Start(); err != nil {
		u.stopLocked()
		return fmt.Errorf("cannot start x11vnc: %w", err)
	}
	u.procs = append(u.procs, vnc)
	u.active.Store(true)
	return nil
}

func (u *UI) Stop() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopLocked()
}

func (u *UI) stopLocked() {
	for i := len(u.procs) - 1; i >= 0; i-- {
		_ = u.procs[i].Process.Kill()
		_, _ = u.procs[i].Process.Wait()
	}
	u.procs = nil
	u.active.Store(false)
}

func (u *UI) Serve(ctx context.Context, port int) {
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           u.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("Login page server stopped: %v", err)
	}
}

func (u *UI) Handler() http.Handler {
	mux := http.NewServeMux()
	static := http.FileServer(http.Dir(u.NoVNCDir))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			u.statusPage(w, r)
		case "/vnc.html":
			u.vncPage(w, r)
		default:
			static.ServeHTTP(w, r)
		}
	})
	mux.HandleFunc("/status", u.statusJSON)
	mux.HandleFunc("/gpbox/return.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, templates, "templates/return.js")
	})
	mux.HandleFunc("/websockify", u.bridge)
	mux.HandleFunc("/login", u.loginPage)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browsers must not mix cached files from another noVNC instance
		// this can happen when someone uses localhost for example
		w.Header().Set("Cache-Control", "no-cache")
		if r.URL.Path != "/login" && !u.authorized(r) {
			if r.URL.Path == "/websockify" || r.URL.Path == "/status" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (u *UI) authorized(r *http.Request) bool {
	if u.Password == "" {
		return true
	}
	c, err := r.Cookie(cookieName)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(u.token)) == 1
}

func (u *UI) loginPage(w http.ResponseWriter, r *http.Request) {
	if u.Password == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	wrong := false
	if r.Method == http.MethodPost {
		given := sha256.Sum256([]byte(r.PostFormValue("password")))
		want := sha256.Sum256([]byte(u.Password))
		if subtle.ConstantTimeCompare(given[:], want[:]) == 1 {
			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    u.token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		time.Sleep(time.Second)
		wrong = true
	}
	render(w, "login.html", struct{ WrongPassword bool }{wrong})
}

func (u *UI) statusJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": u.getStatus(), "login": u.active.Load()})
}

func (u *UI) statusPage(w http.ResponseWriter, r *http.Request) {
	if u.active.Load() {
		http.Redirect(w, r, Path, http.StatusFound)
		return
	}
	rows := []Row{{"Status", u.getStatus()}}
	if u.Info != nil {
		rows = append(rows, u.Info()...)
	}
	render(w, "status.html", rows)
}

func (u *UI) vncPage(w http.ResponseWriter, _ *http.Request) {
	page, err := os.ReadFile(filepath.Join(u.NoVNCDir, "vnc.html"))
	if err != nil {
		http.Error(w, "noVNC is missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, strings.Replace(string(page), "</body>", `<script src="/gpbox/return.js"></script></body>`, 1))
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("Rendering %s: %v", name, err)
	}
}

func (u *UI) bridge(w http.ResponseWriter, r *http.Request) {
	if !u.active.Load() {
		http.Error(w, "no login in progress", http.StatusServiceUnavailable)
		return
	}
	// The default origin check stops other websites from opening this socket in the user's browser
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"binary"}})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	vnc, err := net.DialTimeout("tcp", vncAddr, 5*time.Second)
	if err != nil {
		ws.Close(websocket.StatusInternalError, "VNC server not reachable")
		return
	}
	defer vnc.Close()
	conn := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(vnc, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, vnc); done <- struct{}{} }()
	<-done
}
