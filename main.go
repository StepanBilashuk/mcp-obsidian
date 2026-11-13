// vaultmcp is a small MCP server that exposes a folder of markdown notes
// (an Obsidian vault) to MCP clients such as Claude Code.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const version = "0.2.0"

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func errResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}
}

func jsonResult(v any) *mcp.CallToolResult {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errResult(err)
	}
	return textResult(string(b))
}

type (
	listArgs struct {
		Folder string `json:"folder,omitempty" jsonschema:"optional vault-relative folder to list, empty for the whole vault"`
	}
	pathArgs struct {
		Path string `json:"path" jsonschema:"vault-relative note path, for example Interviews/Bigbank.md (the .md extension is optional)"`
	}
	writeArgs struct {
		Path      string `json:"path" jsonschema:"vault-relative note path, folders are created automatically"`
		Content   string `json:"content" jsonschema:"full markdown content of the note, use [[wikilinks]] to link notes"`
		Overwrite bool   `json:"overwrite,omitempty" jsonschema:"set true to replace an existing note"`
	}
	appendArgs struct {
		Path    string `json:"path" jsonschema:"vault-relative note path, created if missing"`
		Content string `json:"content" jsonschema:"markdown to append at the end of the note"`
	}
	searchArgs struct {
		Query string `json:"query" jsonschema:"words to look for, all words must appear in the note (case-insensitive)"`
		Limit int    `json:"limit,omitempty" jsonschema:"maximum number of results, default 20, maximum 100"`
	}
	mocArgs struct {
		Path      string   `json:"path" jsonschema:"where to create the map note, for example MOC/Interviews.md"`
		Title     string   `json:"title" jsonschema:"heading of the map note"`
		Notes     []string `json:"notes" jsonschema:"vault-relative paths of notes to link from the map"`
		Overwrite bool     `json:"overwrite,omitempty" jsonschema:"set true to replace an existing note"`
	}
	noArgs struct{}
)

func buildServer(v *Vault) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "vaultmcp", Version: version}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_notes",
		Description: "List markdown notes in the vault, optionally inside one folder.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a listArgs) (*mcp.CallToolResult, any, error) {
		notes, err := v.List(a.Folder)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(notes), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "read_note",
		Description: "Read the full markdown content of a note.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a pathArgs) (*mcp.CallToolResult, any, error) {
		c, err := v.Read(a.Path)
		if err != nil {
			return errResult(err), nil, nil
		}
		return textResult(c), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "write_note",
		Description: "Create a note, or replace it when overwrite is true. Use [[wikilinks]] between notes so they appear in the Obsidian graph.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a writeArgs) (*mcp.CallToolResult, any, error) {
		p, err := v.Write(a.Path, a.Content, a.Overwrite)
		if err != nil {
			return errResult(err), nil, nil
		}
		return textResult("saved " + p), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "append_note",
		Description: "Append markdown to the end of a note, creating the note if it does not exist.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a appendArgs) (*mcp.CallToolResult, any, error) {
		p, err := v.Append(a.Path, a.Content)
		if err != nil {
			return errResult(err), nil, nil
		}
		return textResult("appended to " + p), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "search_notes",
		Description: "Full-text search over note names and content. All words must appear in a note.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a searchArgs) (*mcp.CallToolResult, any, error) {
		hits, err := v.Search(a.Query, a.Limit)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(hits), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_backlinks",
		Description: "List notes that link to the given note with a [[wikilink]].",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a pathArgs) (*mcp.CallToolResult, any, error) {
		b, err := v.Backlinks(a.Path)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(b), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "find_broken_links",
		Description: "Find [[wikilinks]] that point to notes that do not exist.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
		b, err := v.BrokenLinks()
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(b), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_moc",
		Description: "Create a Map of Content note that links to a list of notes (a hub node in the graph).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a mocArgs) (*mcp.CallToolResult, any, error) {
		p, err := v.CreateMOC(a.Path, a.Title, a.Notes, a.Overwrite)
		if err != nil {
			return errResult(err), nil, nil
		}
		return textResult("created " + p), nil, nil
	})

	return s
}

// bearerAuth accepts either the static owner token or, when oauth is not nil,
// a live OAuth access token. Anything else gets a 401 that points clients at
// the protected resource metadata so they can start the OAuth flow.
func bearerAuth(token string, oauth *oauthServer, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	challenge := `Bearer realm="vaultmcp"`
	if oauth != nil {
		challenge += `, resource_metadata="` + oauth.metadataURL() + `"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		ok := subtle.ConstantTimeCompare([]byte(hdr), want) == 1
		if !ok && oauth != nil {
			if t, found := strings.CutPrefix(hdr, "Bearer "); found {
				ok = oauth.validAccessToken(t)
			}
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", challenge)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		next.ServeHTTP(w, r)
	})
}

func newHTTPHandler(v *Vault, token string, oauth *oauthServer) http.Handler {
	server := buildServer(v)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	if oauth != nil {
		oauth.register(mux)
	}
	mux.Handle("/mcp", bearerAuth(token, oauth, mcpHandler))
	return mux
}

// oauthFromEnv enables OAuth when VAULT_PUBLIC_URL is set.
func oauthFromEnv() (*oauthServer, error) {
	base := strings.TrimSpace(os.Getenv("VAULT_PUBLIC_URL"))
	if base == "" {
		return nil, nil
	}
	pw := os.Getenv("VAULT_OWNER_PASSWORD")
	stateDir := os.Getenv("VAULT_STATE_DIR")
	if stateDir == "" {
		stateDir = os.Getenv("STATE_DIRECTORY")
	}
	return newOAuthServer(base, pw, stateDir)
}

func main() {
	var (
		vaultDir = flag.String("vault", envOr("VAULT_DIR", "./vault"), "path to the notes folder (env VAULT_DIR)")
		mode     = flag.String("mode", "stdio", "transport: stdio or http")
		addr     = flag.String("addr", envOr("VAULT_ADDR", "127.0.0.1:8787"), "listen address for http mode (env VAULT_ADDR)")
		showVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return
	}

	v, err := NewVault(*vaultDir)
	if err != nil {
		log.Fatalf("vault: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch *mode {
	case "stdio":
		if err := buildServer(v).Run(ctx, &mcp.StdioTransport{}); err != nil {
			log.Fatalf("server: %v", err)
		}
	case "http":
		token := strings.TrimSpace(os.Getenv("VAULT_MCP_TOKEN"))
		if len(token) < 24 {
			log.Fatal("set VAULT_MCP_TOKEN to a random secret of at least 24 characters (for example: openssl rand -hex 32)")
		}
		oauth, err := oauthFromEnv()
		if err != nil {
			log.Fatalf("oauth: %v", err)
		}
		srv := &http.Server{
			Addr:              *addr,
			Handler:           newHTTPHandler(v, token, oauth),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			<-ctx.Done()
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutCtx)
		}()
		if oauth != nil {
			log.Printf("oauth enabled, public URL %s", oauth.baseURL)
		}
		log.Printf("vaultmcp %s listening on http://%s/mcp (vault: %s)", version, *addr, v.root)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	default:
		log.Fatalf("unknown mode %q (use stdio or http)", *mode)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
