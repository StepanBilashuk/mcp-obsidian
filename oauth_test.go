package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testPassword = "correct horse battery"

func newOAuthTestEnv(t *testing.T) (*httptest.Server, *oauthServer, *http.Client) {
	t.Helper()
	v := newTestVault(t)
	o, err := newOAuthServer("https://vault.example.ts.net", testPassword, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(newHTTPHandler(v, strings.Repeat("s3cr3t", 6), o))
	t.Cleanup(ts.Close)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return ts, o, c
}

func register(t *testing.T, ts *httptest.Server, c *http.Client, redirect string) string {
	t.Helper()
	body := `{"client_name":"claude","redirect_uris":["` + redirect + `"]}`
	resp, err := c.Post(ts.URL+"/register", "application/json", strings.NewReader(body))
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("register: %v %v", resp, err)
	}
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return out["client_id"].(string)
}

func pkcePair() (verifier, challenge string) {
	verifier = strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorize runs GET + POST /authorize and returns the POST response.
func authorize(t *testing.T, ts *httptest.Server, c *http.Client, clientID, redirect, challenge, password string) *http.Response {
	t.Helper()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"xyz"},
		"resource": {"https://vault.example.ts.net/mcp"}}
	resp, err := c.Get(ts.URL + "/authorize?" + q.Encode())
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("authorize GET: %v %v", resp, err)
	}
	buf := new(strings.Builder)
	b := make([]byte, 8192)
	n, _ := resp.Body.Read(b)
	buf.Write(b[:n])
	html := buf.String()
	i := strings.Index(html, `name="id" value="`)
	if i < 0 {
		t.Fatalf("no id in form: %s", html)
	}
	id := html[i+len(`name="id" value="`):]
	id = id[:strings.Index(id, `"`)]
	resp, err = c.PostForm(ts.URL+"/authorize", url.Values{"id": {id}, "password": {password}, "decision": {"allow"}})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func codeFrom(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want redirect, got %d", resp.StatusCode)
	}
	u, _ := url.Parse(resp.Header.Get("Location"))
	if u.Query().Get("state") != "xyz" {
		t.Fatalf("state lost: %s", u)
	}
	return u.Query().Get("code")
}

func tokenReq(c *http.Client, ts *httptest.Server, v url.Values) (*http.Response, map[string]any) {
	resp, _ := c.PostForm(ts.URL+"/token", v)
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func TestOAuthDiscovery(t *testing.T) {
	ts, _, c := newOAuthTestEnv(t)
	resp, _ := c.Post(ts.URL+"/mcp", "application/json", strings.NewReader("{}"))
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `resource_metadata="https://vault.example.ts.net/.well-known/oauth-protected-resource"`) {
		t.Fatalf("401 challenge: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server"} {
		resp, err := c.Get(ts.URL + p)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", p, resp, err)
		}
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		if p == "/.well-known/oauth-authorization-server" && m["registration_endpoint"] != "https://vault.example.ts.net/register" {
			t.Fatalf("metadata: %v", m)
		}
	}
}

func TestOAuthFullFlow(t *testing.T) {
	ts, _, c := newOAuthTestEnv(t)
	redirect := "https://claude.ai/api/mcp/auth_callback"
	cid := register(t, ts, c, redirect)
	verifier, challenge := pkcePair()

	code := codeFrom(t, authorize(t, ts, c, cid, redirect, challenge, testPassword))
	resp, tok := tokenReq(c, ts, url.Values{"grant_type": {"authorization_code"}, "client_id": {cid},
		"code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}})
	if resp.StatusCode != 200 || tok["access_token"] == nil || tok["refresh_token"] == nil {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}

	// Access token opens /mcp.
	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	if r, _ := c.Do(req); r.StatusCode == 401 {
		t.Fatal("valid access token rejected")
	}

	// Code is single use.
	if r, _ := tokenReq(c, ts, url.Values{"grant_type": {"authorization_code"}, "client_id": {cid},
		"code": {code}, "code_verifier": {verifier}}); r.StatusCode != 400 {
		t.Fatalf("code reuse: %d", r.StatusCode)
	}

	// Refresh rotates.
	rt := tok["refresh_token"].(string)
	r, tok2 := tokenReq(c, ts, url.Values{"grant_type": {"refresh_token"}, "client_id": {cid}, "refresh_token": {rt}})
	if r.StatusCode != 200 || tok2["refresh_token"] == rt {
		t.Fatalf("refresh: %d %v", r.StatusCode, tok2)
	}
	if r, _ := tokenReq(c, ts, url.Values{"grant_type": {"refresh_token"}, "client_id": {cid}, "refresh_token": {rt}}); r.StatusCode != 400 {
		t.Fatalf("old refresh token must die: %d", r.StatusCode)
	}
}

func TestOAuthRejections(t *testing.T) {
	ts, o, c := newOAuthTestEnv(t)
	redirect := "https://claude.ai/api/mcp/auth_callback"
	cid := register(t, ts, c, redirect)
	verifier, challenge := pkcePair()

	// Wrong password gives no code.
	if r := authorize(t, ts, c, cid, redirect, challenge, "nope"); r.StatusCode != 401 {
		t.Fatalf("wrong password: %d", r.StatusCode)
	}

	// Wrong verifier fails PKCE.
	code := codeFrom(t, authorize(t, ts, c, cid, redirect, challenge, testPassword))
	if r, _ := tokenReq(c, ts, url.Values{"grant_type": {"authorization_code"}, "client_id": {cid},
		"code": {code}, "code_verifier": {strings.Repeat("x", 50)}}); r.StatusCode != 400 {
		t.Fatalf("bad verifier: %d", r.StatusCode)
	}

	// Unregistered redirect is refused without redirecting.
	q := url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {"https://evil.example/cb"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	if r, _ := c.Get(ts.URL + "/authorize?" + q.Encode()); r.StatusCode != 400 {
		t.Fatalf("redirect mismatch: %d", r.StatusCode)
	}

	// Plain PKCE is refused.
	q = url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {redirect},
		"code_challenge": {challenge}, "code_challenge_method": {"plain"}}
	if r, _ := c.Get(ts.URL + "/authorize?" + q.Encode()); r.StatusCode != http.StatusFound || !strings.Contains(r.Header.Get("Location"), "error=invalid_request") {
		t.Fatalf("plain pkce: %d %s", r.StatusCode, r.Header.Get("Location"))
	}

	// Insecure redirect URIs cannot be registered.
	resp, _ := c.Post(ts.URL+"/register", "application/json", strings.NewReader(`{"redirect_uris":["http://evil.example/cb"]}`))
	if resp.StatusCode != 400 {
		t.Fatalf("http redirect: %d", resp.StatusCode)
	}

	// Lockout after repeated failures, even with the right password.
	for i := 0; i < loginMaxFailures; i++ {
		authorize(t, ts, c, cid, redirect, challenge, "bad")
	}
	if r := authorize(t, ts, c, cid, redirect, challenge, testPassword); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("lockout: %d", r.StatusCode)
	}
	o.now = func() time.Time { return time.Now().Add(loginLockout + time.Minute) }
	_ = verifier
	if r := authorize(t, ts, c, cid, redirect, challenge, testPassword); r.StatusCode != http.StatusFound {
		t.Fatalf("after lockout: %d", r.StatusCode)
	}
}

func TestOAuthStatePersists(t *testing.T) {
	dir := t.TempDir()
	o, _ := newOAuthServer("https://x.example", testPassword, dir)
	o.mu.Lock()
	o.clients["c1"] = &oauthClient{ID: "c1", Name: "kept", RedirectURIs: []string{"https://x.example/cb"}, CreatedAt: time.Now()}
	o.issueLocked("c1")
	o.mu.Unlock()
	o2, err := newOAuthServer("https://x.example", testPassword, dir)
	if err != nil || len(o2.clientNames()) != 1 || len(o2.refresh) != 1 {
		t.Fatalf("reload: %v %v", err, o2)
	}
}
