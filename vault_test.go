package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	v, err := NewVault(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestWriteReadRoundTrip(t *testing.T) {
	v := newTestVault(t)
	p, err := v.Write("Interviews/Bigbank", "# Bigbank\nSee [[IAM]]", false)
	if err != nil || p != "Interviews/Bigbank.md" {
		t.Fatalf("write: %q %v", p, err)
	}
	got, err := v.Read("Interviews/Bigbank.md")
	if err != nil || !strings.Contains(got, "[[IAM]]") {
		t.Fatalf("read: %q %v", got, err)
	}
	if _, err := v.Write("Interviews/Bigbank", "x", false); err != ErrExists {
		t.Fatalf("expected ErrExists, got %v", err)
	}
	if _, err := v.Write("Interviews/Bigbank", "new", true); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
}

func TestPathTraversalRejected(t *testing.T) {
	v := newTestVault(t)
	for _, bad := range []string{"../evil", "a/../../evil", "/etc/passwd", "..", ".obsidian/app", ".git/config", "a/.hidden/b", "", "x\x00y"} {
		if _, err := v.Write(bad, "x", true); err == nil {
			t.Errorf("write %q should fail", bad)
		}
		if _, err := v.Read(bad); err == nil {
			t.Errorf("read %q should fail", bad)
		}
	}
}

func TestSymlinkEscapeRejected(t *testing.T) {
	v := newTestVault(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.md"), []byte("top secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(v.root, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := v.Read("link/secret"); err != ErrOutside {
		t.Errorf("read through symlink dir: got %v, want ErrOutside", err)
	}
	if _, err := v.Write("link/new", "x", true); err != ErrOutside {
		t.Errorf("write through symlink dir: got %v, want ErrOutside", err)
	}
	// A symlinked file inside the vault pointing outside must be refused too.
	if err := os.Symlink(filepath.Join(outside, "secret.md"), filepath.Join(v.root, "leak.md")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := v.Read("leak"); err != ErrOutside {
		t.Errorf("read symlinked file: got %v, want ErrOutside", err)
	}
}

func TestSizeLimit(t *testing.T) {
	v := newTestVault(t)
	if _, err := v.Write("big", strings.Repeat("a", maxNoteBytes+1), true); err != ErrTooBig {
		t.Fatalf("got %v, want ErrTooBig", err)
	}
}

func TestAppendCreatesAndAppends(t *testing.T) {
	v := newTestVault(t)
	if _, err := v.Append("log", "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Append("log", "two"); err != nil {
		t.Fatal(err)
	}
	got, _ := v.Read("log")
	if got != "one\ntwo" {
		t.Fatalf("got %q", got)
	}
}

func TestListSkipsHidden(t *testing.T) {
	v := newTestVault(t)
	v.Write("a", "x", true)
	v.Write("dir/b", "x", true)
	os.MkdirAll(filepath.Join(v.root, ".obsidian"), 0o750)
	os.WriteFile(filepath.Join(v.root, ".obsidian", "c.md"), []byte("x"), 0o640)
	os.WriteFile(filepath.Join(v.root, "image.png"), []byte("x"), 0o640)
	all, _ := v.List("")
	if len(all) != 2 || all[0] != "a.md" || all[1] != "dir/b.md" {
		t.Fatalf("list: %v", all)
	}
	sub, _ := v.List("dir")
	if len(sub) != 1 || sub[0] != "dir/b.md" {
		t.Fatalf("sub: %v", sub)
	}
	if _, err := v.List("../"); err == nil {
		t.Fatal("expected error for ..")
	}
}

func TestSearch(t *testing.T) {
	v := newTestVault(t)
	v.Write("IAM", "OAuth2 and OIDC with PKCE\nTokens and sessions", true)
	v.Write("Mongo", "Notes about MongoDB", true)
	hits, err := v.Search("oauth2 pkce", 10)
	if err != nil || len(hits) != 1 || hits[0].Path != "IAM.md" || hits[0].Line != 1 {
		t.Fatalf("hits: %+v %v", hits, err)
	}
	if hits, _ := v.Search("oauth2 mongodb", 10); len(hits) != 0 {
		t.Fatalf("terms must all match: %+v", hits)
	}
	if hits, _ := v.Search("mongo", 10); len(hits) != 1 {
		t.Fatalf("name match: %+v", hits)
	}
	if _, err := v.Search("   ", 10); err == nil {
		t.Fatal("empty query must fail")
	}
}

func TestBacklinksAndBrokenLinks(t *testing.T) {
	v := newTestVault(t)
	v.Write("IAM", "# IAM", true)
	v.Write("Interviews/Bigbank", "Prep: [[IAM]] and [[iam#Tokens|tokens]] and [[Missing Note]] and ![[diagram.png]]", true)
	v.Write("Journal", "Today: [[Interviews/Bigbank]]", true)

	bl, err := v.Backlinks("IAM")
	if err != nil || len(bl) != 1 || bl[0] != "Interviews/Bigbank.md" {
		t.Fatalf("backlinks IAM: %v %v", bl, err)
	}
	bl, _ = v.Backlinks("Interviews/Bigbank")
	if len(bl) != 1 || bl[0] != "Journal.md" {
		t.Fatalf("backlinks Bigbank: %v", bl)
	}
	broken, _ := v.BrokenLinks()
	if len(broken) != 1 || broken[0].Target != "Missing Note" || broken[0].From != "Interviews/Bigbank.md" {
		t.Fatalf("broken: %+v", broken)
	}
}

func TestCreateMOC(t *testing.T) {
	v := newTestVault(t)
	p, err := v.CreateMOC("MOC/Interviews", "Interviews", []string{"Interviews/Bigbank.md", "Interviews/Messente"}, false)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := v.Read(p)
	if !strings.Contains(got, "# Interviews") || !strings.Contains(got, "- [[Interviews/Bigbank]]") || !strings.Contains(got, "- [[Interviews/Messente]]") {
		t.Fatalf("moc: %q", got)
	}
}

type headerRT struct{ token string }

func (h headerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if h.token != "" {
		r.Header.Set("Authorization", "Bearer "+h.token)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestHTTPAuthAndEndToEnd(t *testing.T) {
	v := newTestVault(t)
	token := strings.Repeat("s3cr3t", 6)
	ts := httptest.NewServer(newHTTPHandler(v, token))
	defer ts.Close()

	// Health is open, MCP endpoint is not.
	if resp, err := http.Get(ts.URL + "/healthz"); err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", resp, err)
	}
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token must be 401, got %v %v", resp, err)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer wrong")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token must be 401, got %v %v", resp, err)
	}

	// Full MCP session with the right token.
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   ts.URL + "/mcp",
		HTTPClient: &http.Client{Transport: headerRT{token}},
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tl := range tools.Tools {
		names[tl.Name] = true
	}
	for _, want := range []string{"list_notes", "read_note", "write_note", "append_note", "search_notes", "list_backlinks", "find_broken_links", "create_moc"} {
		if !names[want] {
			t.Errorf("missing tool %s", want)
		}
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "write_note", Arguments: map[string]any{"path": "Hello", "content": "hi [[World]]"}})
	if err != nil || res.IsError {
		t.Fatalf("write_note: %v %+v", err, res)
	}
	res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "read_note", Arguments: map[string]any{"path": "Hello.md"}})
	if err != nil || res.IsError || res.Content[0].(*mcp.TextContent).Text != "hi [[World]]" {
		t.Fatalf("read_note: %v %+v", err, res)
	}
	res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "read_note", Arguments: map[string]any{"path": "../../etc/passwd"}})
	if err != nil || !res.IsError {
		t.Fatalf("traversal must be a tool error: %v %+v", err, res)
	}
	res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "find_broken_links", Arguments: map[string]any{}})
	if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "World") {
		t.Fatalf("find_broken_links: %v %+v", err, res)
	}
}
