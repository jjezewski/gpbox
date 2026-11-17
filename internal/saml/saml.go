package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

const userAgent = "PAN GlobalProtect"

var ErrRejected = errors.New("VPN server rejected the login (saml-auth-status -1)")

type Options struct {
	Portal       string
	Mode         string
	ClientOS     string
	ChromiumPath string
	Display      string
	Timeout      time.Duration // 10 minutes by default
}

type Result struct {
	User           string
	PreloginCookie string
}

type preloginResponse struct {
	Status      string `xml:"status"`
	Msg         string `xml:"msg"`
	SAMLMethod  string `xml:"saml-auth-method"`
	SAMLRequest string `xml:"saml-request"`
}

func StartURL(ctx context.Context, o Options) (string, error) {
	path := "global-protect"
	if o.Mode == "gateway" {
		path = "ssl-vpn"
	}
	q := url.Values{
		"tmp":              {"tmp"},
		"kerberos-support": {"yes"},
		"ipv6-support":     {"yes"},
		"clientVer":        {"4100"},
		"clientos":         {o.ClientOS},
		"default-browser":  {"1"},
		"cas-support":      {"yes"},
	}
	u := fmt.Sprintf("https://%s/%s/prelogin.esp?%s", o.Portal, path, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach %s: %w", o.Portal, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var pr preloginResponse
	if err := xml.Unmarshal(body, &pr); err != nil {
		return "", fmt.Errorf("unexpected prelogin answer from %s (HTTP %d)", o.Portal, resp.StatusCode)
	}
	if pr.SAMLRequest == "" {
		return "", fmt.Errorf("%s did not ask for a SAML login (status %q, message %q). Only SAML is supported",
			o.Portal, pr.Status, pr.Msg)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pr.SAMLRequest))
	if err != nil {
		return "", fmt.Errorf("cannot decode SAML request: %w", err)
	}
	if strings.EqualFold(pr.SAMLMethod, "POST") {
		// raw is an HTML page with a form that posts itself to the identity provider
		return "data:text/html;base64," + base64.StdEncoding.EncodeToString(raw), nil
	}
	return string(raw), nil
}

func Login(parent context.Context, o Options) (*Result, error) {
	start, err := StartURL(parent, o)
	if err != nil {
		return nil, err
	}
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Minute
	}

	profile, err := os.MkdirTemp("", "gpbox-chromium-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(profile)

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(parent,
		chromedp.ExecPath(o.ChromiumPath),
		chromedp.UserDataDir(profile),
		chromedp.Env("DISPLAY="+o.Display),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.WindowSize(1280, 800),
		chromedp.Flag("window-position", "0,0"),
		chromedp.Flag("no-sandbox", true), // runs as root inside the container
		chromedp.Flag("test-type", true),  // hides the "unsupported flag --no-sandbox" warning bar
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-features", "Translate,MediaRouter"),
		chromedp.Flag("password-store", "basic"),
	)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Listener runs in chromedp's read loop and only hands events over
	events := make(chan any, 1024)
	err = chromedp.Listen(ctx, func(ev any) {
		switch ev.(type) {
		case *network.EventResponseReceived, *network.EventLoadingFinished, *network.EventRequestWillBeSent:
			select {
			case events <- ev:
			default:
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("cannot start Chromium: %w", err)
	}
	if _, err := chromedp.Call(ctx, network.Enable, network.EnableParams{}); err != nil {
		return nil, fmt.Errorf("cannot start Chromium: %w", err)
	}
	closed, err := chromedp.Detached(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := chromedp.Call(ctx, page.Navigate, page.NavigateParams{URL: start}); err != nil {
		return nil, fmt.Errorf("cannot open the sign-in page: %w", err)
	}

	watched := map[network.RequestID]bool{}
	timeout := time.After(o.Timeout)
	for {
		select {
		case ev := <-events:
			switch e := ev.(type) {
			case *network.EventResponseReceived:
				h := lowerHeaders(e.Response.Headers)
				if ck := h["prelogin-cookie"]; ck != "" {
					return &Result{User: h["saml-username"], PreloginCookie: ck}, nil
				}
				isACS := strings.Contains(e.Response.URL, "/SAML20/SP/ACS")
				if isACS {
					log.Printf("Sign-in page answered: HTTP %d, saml-auth-status=%s", e.Response.Status, h["saml-auth-status"])
					if h["saml-auth-status"] == "-1" {
						return nil, ErrRejected
					}
				}
				if isACS || strings.Contains(e.Response.URL, o.Portal) {
					watched[e.RequestID] = true
				}
			case *network.EventLoadingFinished:
				if !watched[e.RequestID] {
					continue
				}
				delete(watched, e.RequestID)
				res, err := chromedp.Call(ctx, network.GetResponseBody,
					network.GetResponseBodyParams{RequestID: e.RequestID})
				if err == nil {
					if r := FindCookie(string(res.Body)); r != nil {
						return r, nil
					}
				}
			case *network.EventRequestWillBeSent:
				if strings.HasPrefix(e.Request.URL, "globalprotectcallback:") {
					if r := FindCookie(e.Request.URL); r != nil {
						return r, nil
					}
				}
			}
		case <-closed:
			return nil, errors.New("login window was closed")
		case <-timeout:
			return nil, fmt.Errorf("no login within %s", o.Timeout)
		case <-ctx.Done():
			return nil, errors.New("login window was closed")
		case <-parent.Done():
			return nil, parent.Err()
		}
	}
}

var (
	cookieRe   = regexp.MustCompile(`<prelogin-cookie>([^<]+)</prelogin-cookie>`)
	userRe     = regexp.MustCompile(`<saml-username>([^<]+)</saml-username>`)
	callbackRe = regexp.MustCompile(`globalprotectcallback:([A-Za-z0-9+/=_-]+)`)
)

func FindCookie(text string) *Result {
	texts := []string{text}
	for _, m := range callbackRe.FindAllStringSubmatch(text, -1) {
		s := strings.TrimRight(m[1], "=")
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(s); err == nil {
				texts = append(texts, string(b))
				break
			}
		}
	}
	for _, t := range texts {
		if m := cookieRe.FindStringSubmatch(t); m != nil {
			r := &Result{PreloginCookie: m[1]}
			if u := userRe.FindStringSubmatch(t); u != nil {
				r.User = u[1]
			}
			return r
		}
	}
	return nil
}

func lowerHeaders(h network.Headers) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = fmt.Sprint(v)
	}
	return out
}
