package main

// A small OAuth 2.1 authorization server for a single owner, so that remote MCP
// clients such as a claude.ai custom connector can sign in.
//
// Implemented (the parts the MCP authorization spec relies on):
//   - RFC 9728 protected resource metadata
//   - RFC 8414 authorization server metadata
//   - RFC 7591 dynamic client registration (public clients only)
//   - authorization code grant with mandatory PKCE (S256)
//   - refresh tokens with rotation
//
// The owner proves who they are on the consent page with a password
// (VAULT_OWNER_PASSWORD). Anyone may register a client, but nobody can get a
// token without that password.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	accessTokenTTL   = time.Hour
	refreshTokenTTL  = 30 * 24 * time.Hour
	authCodeTTL      = 5 * time.Minute
	pendingAuthTTL   = 15 * time.Minute
	maxClients       = 50
	maxPending       = 200
	loginMaxFailures = 5
	loginLockout     = 10 * time.Minute
	scopeName        = "vault"
)

type oauthClient struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
}

type pendingAuth struct {
	ClientID    string
	RedirectURI string
	State       string
	Challenge   string
	Resource    string
	Expires     time.Time
}

type authCode struct {
	ClientID    string
	RedirectURI string
	Challenge   string
	Resource    string
	Expires     time.Time
}

type tokenRecord struct {
	ClientID string    `json:"client_id"`
	Expires  time.Time `json:"expires"`
}

type persistedState struct {
	Clients map[string]*oauthClient `json:"clients"`
	Refresh map[string]*tokenRecord `json:"refresh"` // key: sha256 of the token
}

type oauthServer struct {
	baseURL   string // public base URL without trailing slash
	password  string
	statePath string
	now       func() time.Time

	mu          sync.Mutex
	clients     map[string]*oauthClient
	pending     map[string]*pendingAuth
	codes       map[string]*authCode    // key: sha256 of the code
	access      map[string]*tokenRecord // key: sha256 of the token
	refresh     map[string]*tokenRecord // key: sha256 of the token
	failures    int
	lockedUntil time.Time
}

func newOAuthServer(baseURL, ownerPassword, stateDir string) (*oauthServer, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("VAULT_PUBLIC_URL %q is not a valid URL", baseURL)
	}
	if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return nil, errors.New("VAULT_PUBLIC_URL must use https")
	}
	if len(ownerPassword) < 12 {
		return nil, errors.New("VAULT_OWNER_PASSWORD must be at least 12 characters")
	}
	s := &oauthServer{
		baseURL:  strings.TrimRight(baseURL, "/"),
		password: ownerPassword,
		now:      time.Now,
		clients:  map[string]*oauthClient{},
		pending:  map[string]*pendingAuth{},
		codes:    map[string]*authCode{},
		access:   map[string]*tokenRecord{},
		refresh:  map[string]*tokenRecord{},
	}
	if stateDir != "" {
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return nil, err
		}
		s.statePath = filepath.Join(stateDir, "oauth-state.json")
		if err := s.load(); err != nil {
			return nil, fmt.Errorf("load oauth state: %w", err)
		}
	}
	return s, nil
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func (s *oauthServer) resourceURL() string { return s.baseURL + "/mcp" }

func (s *oauthServer) metadataURL() string {
	return s.baseURL + "/.well-known/oauth-protected-resource"
}

// ---- persistence ----

func (s *oauthServer) load() error {
	b, err := os.ReadFile(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st persistedState
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if st.Clients != nil {
		s.clients = st.Clients
	}
	if st.Refresh != nil {
		s.refresh = st.Refresh
	}
	return nil
}

// saveLocked writes clients and refresh tokens. Caller holds s.mu.
func (s *oauthServer) saveLocked() {
	if s.statePath == "" {
		return
	}
	b, err := json.Marshal(persistedState{Clients: s.clients, Refresh: s.refresh})
	if err != nil {
		return
	}
	tmp := s.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, s.statePath)
}

// ---- helpers ----

func randString(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func wellKnownCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, MCP-Protocol-Version")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

// sweepLocked drops expired entries. Caller holds s.mu.
func (s *oauthServer) sweepLocked() {
	now := s.now()
	for k, v := range s.pending {
		if now.After(v.Expires) {
			delete(s.pending, k)
		}
	}
	for k, v := range s.codes {
		if now.After(v.Expires) {
			delete(s.codes, k)
		}
	}
	for k, v := range s.access {
		if now.After(v.Expires) {
			delete(s.access, k)
		}
	}
	changed := false
	for k, v := range s.refresh {
		if now.After(v.Expires) {
			delete(s.refresh, k)
			changed = true
		}
	}
	if changed {
		s.saveLocked()
	}
}

// ---- discovery ----

func (s *oauthServer) handleProtectedResource(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resourceURL(),
		"authorization_servers":    []string{s.baseURL},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{scopeName},
	})
}

func (s *oauthServer) handleServerMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.baseURL,
		"authorization_endpoint":                s.baseURL + "/authorize",
		"token_endpoint":                        s.baseURL + "/token",
		"registration_endpoint":                 s.baseURL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{scopeName},
	})
}

// ---- dynamic client registration (RFC 7591) ----

type registerRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Host == "" || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return isLoopbackHost(u.Hostname())
	}
	return false
}

func (s *oauthServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req registerRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil || json.Unmarshal(body, &req) != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "body must be JSON")
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 5 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "1 to 5 redirect_uris are required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URIs must be https (or http on localhost)")
			return
		}
	}
	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		name = "MCP client"
	}
	if len(name) > 100 {
		name = name[:100]
	}
	c := &oauthClient{
		ID:           "mcp_" + randString(18),
		Name:         name,
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    s.now(),
	}
	s.mu.Lock()
	if len(s.clients) >= maxClients { // evict the oldest registration
		var oldest *oauthClient
		for _, x := range s.clients {
			if oldest == nil || x.CreatedAt.Before(oldest.CreatedAt) {
				oldest = x
			}
		}
		if oldest != nil {
			delete(s.clients, oldest.ID)
		}
	}
	s.clients[c.ID] = c
	s.saveLocked()
	s.mu.Unlock()

	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  c.ID,
		"client_name":                c.Name,
		"redirect_uris":              c.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"client_id_issued_at":        c.CreatedAt.Unix(),
	})
}

// ---- authorization endpoint ----

var consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vault access</title>
<style>
body{font-family:system-ui,sans-serif;max-width:26rem;margin:12vh auto;padding:0 1rem;color:#1c1c1e}
h1{font-size:1.25rem} p{line-height:1.5} input{width:100%;box-sizing:border-box;padding:.6rem;font-size:1rem;margin:.4rem 0 1rem}
button{padding:.6rem 1rem;font-size:1rem;margin-right:.5rem;cursor:pointer}
.err{color:#b00020}
</style></head><body>
<h1>Allow access to your notes?</h1>
<p><strong>{{.Client}}</strong> wants to read and write the markdown notes in your vault.</p>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="/authorize">
<input type="hidden" name="id" value="{{.ID}}">
<label for="pw">Owner password</label>
<input id="pw" type="password" name="password" autocomplete="current-password" autofocus required>
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny" formnovalidate>Deny</button>
</form></body></html>`))

func (s *oauthServer) renderConsent(w http.ResponseWriter, status int, id, client, msg string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	_ = consentTmpl.Execute(w, map[string]string{"ID": id, "Client": client, "Error": msg})
}

func plainError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintln(w, msg)
}

func redirectWith(w http.ResponseWriter, r *http.Request, base string, params map[string]string) {
	u, err := url.Parse(base)
	if err != nil {
		plainError(w, http.StatusBadRequest, "invalid redirect_uri")
		return
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (s *oauthServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.authorizeGet(w, r)
	case http.MethodPost:
		s.authorizePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *oauthServer) authorizeGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	s.sweepLocked()
	client := s.clients[q.Get("client_id")]
	s.mu.Unlock()

	// Problems with the client or redirect URI must never redirect.
	if client == nil {
		plainError(w, http.StatusBadRequest, "unknown client_id")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}
	if !containsString(client.RedirectURIs, redirectURI) {
		plainError(w, http.StatusBadRequest, "redirect_uri does not match a registered URI")
		return
	}
	state := q.Get("state")
	fail := func(code, desc string) {
		redirectWith(w, r, redirectURI, map[string]string{"error": code, "error_description": desc, "state": state})
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" || len(challenge) < 43 || len(challenge) > 128 {
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	resource := q.Get("resource")
	if resource != "" && resource != s.resourceURL() && resource != s.baseURL {
		fail("invalid_target", "unknown resource")
		return
	}

	id := randString(24)
	s.mu.Lock()
	if len(s.pending) >= maxPending {
		s.mu.Unlock()
		fail("temporarily_unavailable", "too many pending requests")
		return
	}
	s.pending[id] = &pendingAuth{
		ClientID: client.ID, RedirectURI: redirectURI, State: state,
		Challenge: challenge, Resource: resource, Expires: s.now().Add(pendingAuthTTL),
	}
	s.mu.Unlock()
	s.renderConsent(w, http.StatusOK, id, client.Name, "")
}

func (s *oauthServer) authorizePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		plainError(w, http.StatusBadRequest, "bad form")
		return
	}
	id := r.PostForm.Get("id")

	s.mu.Lock()
	s.sweepLocked()
	p := s.pending[id]
	var clientName string
	if p != nil {
		if c := s.clients[p.ClientID]; c != nil {
			clientName = c.Name
		}
	}
	if p == nil || clientName == "" {
		s.mu.Unlock()
		plainError(w, http.StatusBadRequest, "This sign-in request expired. Start again from the app.")
		return
	}
	if r.PostForm.Get("decision") == "deny" {
		delete(s.pending, id)
		s.mu.Unlock()
		redirectWith(w, r, p.RedirectURI, map[string]string{"error": "access_denied", "state": p.State})
		return
	}
	if s.now().Before(s.lockedUntil) {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "600")
		s.renderConsent(w, http.StatusTooManyRequests, id, clientName, "Too many failed attempts. Try again in a few minutes.")
		return
	}
	given := []byte(r.PostForm.Get("password"))
	if subtle.ConstantTimeCompare(given, []byte(s.password)) != 1 {
		s.failures++
		if s.failures >= loginMaxFailures {
			s.failures = 0
			s.lockedUntil = s.now().Add(loginLockout)
		}
		s.mu.Unlock()
		s.renderConsent(w, http.StatusUnauthorized, id, clientName, "Wrong password.")
		return
	}
	s.failures = 0
	delete(s.pending, id)
	code := randString(32)
	s.codes[hashToken(code)] = &authCode{
		ClientID: p.ClientID, RedirectURI: p.RedirectURI, Challenge: p.Challenge,
		Resource: p.Resource, Expires: s.now().Add(authCodeTTL),
	}
	s.mu.Unlock()
	redirectWith(w, r, p.RedirectURI, map[string]string{"code": code, "state": p.State, "iss": s.baseURL})
}

// ---- token endpoint ----

func pkceMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}

// issueLocked creates a new access and refresh token pair. Caller holds s.mu.
func (s *oauthServer) issueLocked(clientID string) map[string]any {
	at, rt := randString(32), randString(32)
	now := s.now()
	s.access[hashToken(at)] = &tokenRecord{ClientID: clientID, Expires: now.Add(accessTokenTTL)}
	s.refresh[hashToken(rt)] = &tokenRecord{ClientID: clientID, Expires: now.Add(refreshTokenTTL)}
	s.saveLocked()
	return map[string]any{
		"access_token":  at,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"refresh_token": rt,
		"scope":         scopeName,
	}
}

func (s *oauthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	clientID := r.PostForm.Get("client_id")

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if s.clients[clientID] == nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client_id")
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		key := hashToken(r.PostForm.Get("code"))
		ac := s.codes[key]
		delete(s.codes, key) // single use, even when the checks below fail
		if ac == nil || s.now().After(ac.Expires) || ac.ClientID != clientID {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "code is invalid or expired")
			return
		}
		if ru := r.PostForm.Get("redirect_uri"); ru != "" && ru != ac.RedirectURI {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
			return
		}
		if !pkceMatches(r.PostForm.Get("code_verifier"), ac.Challenge) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
		writeJSON(w, http.StatusOK, s.issueLocked(clientID))

	case "refresh_token":
		key := hashToken(r.PostForm.Get("refresh_token"))
		rec := s.refresh[key]
		if rec == nil || s.now().After(rec.Expires) || rec.ClientID != clientID {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or expired")
			return
		}
		delete(s.refresh, key) // rotation: the old refresh token dies here
		writeJSON(w, http.StatusOK, s.issueLocked(clientID))

	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

// validAccessToken reports whether tok is a live OAuth access token.
func (s *oauthServer) validAccessToken(tok string) bool {
	if tok == "" {
		return false
	}
	key := hashToken(tok)
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.access[key]
	if rec == nil {
		return false
	}
	if s.now().After(rec.Expires) {
		delete(s.access, key)
		return false
	}
	return true
}

// register mounts all OAuth routes on mux.
func (s *oauthServer) register(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-protected-resource", wellKnownCORS(s.handleProtectedResource))
	mux.HandleFunc("/.well-known/oauth-protected-resource/", wellKnownCORS(s.handleProtectedResource))
	mux.HandleFunc("/.well-known/oauth-authorization-server", wellKnownCORS(s.handleServerMetadata))
	mux.HandleFunc("/.well-known/oauth-authorization-server/", wellKnownCORS(s.handleServerMetadata))
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
}

// clientNames is used by tests and diagnostics.
func (s *oauthServer) clientNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.clients {
		out = append(out, c.Name)
	}
	sort.Strings(out)
	return out
}
