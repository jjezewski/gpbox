package config

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Forward struct {
	Port   int
	Target string
}

type Config struct {
	Portal        string
	Mode          string
	OS            string
	ClientOS      string
	HIP           bool
	SessionKey    string
	SocksPort     int
	LoginPort     int
	LoginPassword string
	Forwards      []Forward

	DataDir      string
	ChromiumPath string
	NoVNCDir     string
}

func Load() (*Config, error) {
	c := &Config{
		Portal:        env("GP_PORTAL", ""),
		Mode:          env("GP_MODE", "gateway"),
		OS:            env("GP_OS", "win"),
		HIP:           !slices.Contains([]string{"0", "false", "no", "off"}, strings.ToLower(env("GP_HIP", "1"))),
		SessionKey:    env("SESSION_KEY", "1"),
		LoginPassword: env("GP_LOGIN_PASSWORD", ""),
		DataDir:       env("GP_DATA_DIR", "/data"),
		ChromiumPath:  env("GP_CHROMIUM", "/usr/bin/chromium"),
		NoVNCDir:      env("GP_NOVNC_DIR", "/opt/novnc"),
	}
	if c.Portal == "" {
		return nil, fmt.Errorf("GP_PORTAL is not set. Example: docker run -e GP_PORTAL=vpn.example.com ...")
	}
	if c.Mode != "gateway" && c.Mode != "portal" {
		return nil, fmt.Errorf("GP_MODE must be 'gateway' or 'portal', not %q", c.Mode)
	}
	var ok bool
	if c.ClientOS, ok = clientOS[c.OS]; !ok {
		return nil, fmt.Errorf("GP_OS must be one of win, mac-intel, linux-64, linux, android, apple-ios, not %q", c.OS)
	}
	var err error
	if c.SocksPort, err = envPort("SOCKS_PORT", 1080); err != nil {
		return nil, err
	}
	if c.LoginPort, err = envPort("NOVNC_PORT", 6080); err != nil {
		return nil, err
	}
	c.Forwards = ParseForwards(env("GP_FORWARDS", ""), c.SocksPort, c.LoginPort)
	return c, nil
}

// clientOS maps openconnect's --os value to the clientos name used in the SAML prelogin,
// so both steps of the login claim the same system just in case
var clientOS = map[string]string{
	"win":       "Windows",
	"mac-intel": "Mac",
	"linux-64":  "Linux",
	"linux":     "Linux",
	"android":   "Android",
	"apple-ios": "iOS",
}

var (
	separatorRe = regexp.MustCompile(`[,\s]+`)
	forwardRe   = regexp.MustCompile(`^(\d{1,5}):(\[[^]]+]|[^:\s]+):(\d{1,5})$`)
)

// ParseForwards uses "local_port:host:port" format, entries are separated by commas, spaces or newlines
func ParseForwards(s string, reserved ...int) []Forward {
	var out []Forward
	seen := map[int]bool{}
	for _, item := range separatorRe.Split(s, -1) {
		if item == "" {
			continue
		}
		m := forwardRe.FindStringSubmatch(item)
		if m == nil {
			log.Printf("GP_FORWARDS entry ignored (expected local_port:host:port): %s", item)
			continue
		}
		local, _ := strconv.Atoi(m[1])
		remote, _ := strconv.Atoi(m[3])
		switch {
		case !validPort(local) || !validPort(remote):
			log.Printf("GP_FORWARDS entry ignored (port out of range): %s", item)
		case slices.Contains(reserved, local):
			log.Printf("GP_FORWARDS entry ignored: port %d is used by the SOCKS proxy or the login page", local)
		case seen[local]:
			log.Printf("GP_FORWARDS entry ignored: local port %d is used twice", local)
		default:
			seen[local] = true
			out = append(out, Forward{Port: local, Target: m[2] + ":" + m[3]})
		}
	}
	return out
}

func env(name, def string) string {
	// Also deletes the \r of .env files saved with CRLF
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func envPort(name string, def int) (int, error) {
	v := env(name, strconv.Itoa(def))
	n, err := strconv.Atoi(v)
	if err != nil || !validPort(n) {
		return 0, fmt.Errorf("%s must be a port number, not %q", name, v)
	}
	return n, nil
}

func validPort(n int) bool { return n >= 1 && n <= 65535 }
