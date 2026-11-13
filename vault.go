package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const maxNoteBytes = 1 << 20 // 1 MiB

var (
	ErrOutside  = errors.New("path is outside the vault")
	ErrNotFound = errors.New("note not found")
	ErrExists   = errors.New("note already exists (set overwrite=true to replace)")
	ErrTooBig   = errors.New("note exceeds 1 MiB")
)

// Vault is a directory of markdown notes. All paths handed in by callers are
// vault-relative and are validated so they cannot escape the root.
type Vault struct {
	root string // absolute, symlinks resolved
}

func NewVault(root string) (*Vault, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o750); err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	return &Vault{root: real}, nil
}

func hiddenSegment(rel string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
		if strings.HasPrefix(seg, ".") && seg != "." {
			return true
		}
	}
	return false
}

// resolve validates a vault-relative note path and returns the absolute path.
// A missing ".md" extension is added. Hidden folders (.obsidian, .git) are refused.
func (v *Vault) resolve(rel string) (abs string, clean string, err error) {
	rel = strings.TrimSpace(rel)
	if rel == "" || strings.ContainsRune(rel, 0) {
		return "", "", fmt.Errorf("invalid path %q", rel)
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "\\") {
		return "", "", ErrOutside
	}
	if !strings.HasSuffix(strings.ToLower(rel), ".md") {
		rel += ".md"
	}
	clean = filepath.ToSlash(filepath.Clean(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", "", ErrOutside
	}
	if hiddenSegment(clean) {
		return "", "", errors.New("hidden folders and files are not accessible")
	}
	abs = filepath.Join(v.root, filepath.FromSlash(clean))
	// Resolve symlinks on the deepest existing ancestor and verify containment.
	probe := abs
	for {
		if _, statErr := os.Lstat(probe); statErr == nil {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}
	real, err := filepath.EvalSymlinks(probe)
	if err != nil {
		return "", "", err
	}
	if real != v.root && !strings.HasPrefix(real, v.root+string(filepath.Separator)) {
		return "", "", ErrOutside
	}
	return abs, clean, nil
}

func (v *Vault) Read(rel string) (string, error) {
	abs, _, err := v.resolve(rel)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", ErrNotFound
	}
	if info.Size() > maxNoteBytes {
		return "", ErrTooBig
	}
	b, err := os.ReadFile(abs)
	return string(b), err
}

func (v *Vault) Write(rel, content string, overwrite bool) (string, error) {
	if len(content) > maxNoteBytes {
		return "", ErrTooBig
	}
	abs, clean, err := v.resolve(rel)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(abs); err == nil && !overwrite {
		return "", ErrExists
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		return "", err
	}
	// Re-check containment after creating directories.
	if _, _, err := v.resolve(clean); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(abs), ".tmp-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	if err := os.Rename(tmpName, abs); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	return clean, nil
}

func (v *Vault) Append(rel, content string) (string, error) {
	existing, err := v.Read(rel)
	if errors.Is(err, ErrNotFound) {
		existing = ""
	} else if err != nil {
		return "", err
	}
	if existing != "" && !strings.HasSuffix(existing, "\n") {
		existing += "\n"
	}
	return v.Write(rel, existing+content, true)
}

// List returns vault-relative note paths under an optional folder prefix.
func (v *Vault) List(prefix string) ([]string, error) {
	var out []string
	prefix = strings.Trim(filepath.ToSlash(strings.TrimSpace(prefix)), "/")
	if strings.Contains(prefix, "..") {
		return nil, ErrOutside
	}
	err := filepath.WalkDir(v.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(v.root, p)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(rel), ".md") {
			return nil
		}
		if prefix != "" && rel != prefix && !strings.HasPrefix(rel, prefix+"/") {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	sort.Strings(out)
	return out, err
}

type SearchHit struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
	Matches int    `json:"matches"`
}

// Search finds notes that contain every whitespace-separated term
// (case-insensitive). Results are ordered by number of matches.
func (v *Vault) Search(query string, limit int) ([]SearchHit, error) {
	terms := strings.Fields(strings.ToLower(query))
	if len(terms) == 0 {
		return nil, errors.New("empty query")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	notes, err := v.List("")
	if err != nil {
		return nil, err
	}
	var hits []SearchHit
	for _, n := range notes {
		abs := filepath.Join(v.root, filepath.FromSlash(n))
		f, err := os.Open(abs)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), maxNoteBytes)
		found := make(map[string]bool)
		total, firstLine := 0, 0
		first := ""
		lineNo := 0
		// The file name counts as content too.
		nameLower := strings.ToLower(n)
		for _, t := range terms {
			if strings.Contains(nameLower, t) {
				found[t] = true
				total++
			}
		}
		for sc.Scan() {
			lineNo++
			low := strings.ToLower(sc.Text())
			lineHit := false
			for _, t := range terms {
				if c := strings.Count(low, t); c > 0 {
					found[t] = true
					total += c
					lineHit = true
				}
			}
			if lineHit && first == "" {
				first = strings.TrimSpace(sc.Text())
				firstLine = lineNo
			}
		}
		f.Close()
		if len(found) == len(terms) {
			if len(first) > 200 {
				first = first[:200] + "..."
			}
			hits = append(hits, SearchHit{Path: n, Line: firstLine, Snippet: first, Matches: total})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Matches > hits[j].Matches })
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits, nil
}

var wikilinkRe = regexp.MustCompile(`!?\[\[([^\[\]|#^]+)(?:[#^][^\[\]|]*)?(?:\|[^\[\]]*)?\]\]`)

// linkTargets extracts wikilink targets from text (without alias or heading).
func linkTargets(text string) []string {
	var out []string
	for _, m := range wikilinkRe.FindAllStringSubmatch(text, -1) {
		t := strings.TrimSpace(m[1])
		if t == "" {
			continue
		}
		// Embedded non-markdown files (images, pdfs) are not notes.
		if ext := strings.ToLower(filepath.Ext(t)); ext != "" && ext != ".md" {
			continue
		}
		out = append(out, t)
	}
	return out
}

func normTarget(t string) string {
	t = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(filepath.ToSlash(t))), ".md")
	return strings.Trim(t, "/")
}

// noteIndex maps normalized basenames and relative paths to a note path.
func (v *Vault) noteIndex() (map[string]string, []string, error) {
	notes, err := v.List("")
	if err != nil {
		return nil, nil, err
	}
	idx := make(map[string]string, len(notes)*2)
	for _, n := range notes {
		noExt := normTarget(n)
		idx[noExt] = n
		base := noExt
		if i := strings.LastIndex(noExt, "/"); i >= 0 {
			base = noExt[i+1:]
		}
		if _, taken := idx[base]; !taken {
			idx[base] = n
		}
	}
	return idx, notes, nil
}

// Backlinks returns the notes that link to the given note.
func (v *Vault) Backlinks(rel string) ([]string, error) {
	_, clean, err := v.resolve(rel)
	if err != nil {
		return nil, err
	}
	idx, notes, err := v.noteIndex()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range notes {
		if n == clean {
			continue
		}
		b, err := os.ReadFile(filepath.Join(v.root, filepath.FromSlash(n)))
		if err != nil {
			continue
		}
		for _, t := range linkTargets(string(b)) {
			if idx[normTarget(t)] == clean {
				out = append(out, n)
				break
			}
		}
	}
	return out, nil
}

type BrokenLink struct {
	From   string `json:"from"`
	Target string `json:"target"`
}

func (v *Vault) BrokenLinks() ([]BrokenLink, error) {
	idx, notes, err := v.noteIndex()
	if err != nil {
		return nil, err
	}
	var out []BrokenLink
	for _, n := range notes {
		b, err := os.ReadFile(filepath.Join(v.root, filepath.FromSlash(n)))
		if err != nil {
			continue
		}
		seen := map[string]bool{}
		for _, t := range linkTargets(string(b)) {
			k := normTarget(t)
			if _, ok := idx[k]; !ok && !seen[k] {
				seen[k] = true
				out = append(out, BrokenLink{From: n, Target: t})
			}
		}
	}
	return out, nil
}

// CreateMOC writes a Map of Content note linking to the given notes.
func (v *Vault) CreateMOC(rel, title string, notes []string, overwrite bool) (string, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# %s\n\n", strings.TrimSpace(title))
	for _, n := range notes {
		n = strings.TrimSuffix(strings.TrimSpace(filepath.ToSlash(n)), ".md")
		if n == "" {
			continue
		}
		fmt.Fprintf(&sb, "- [[%s]]\n", n)
	}
	return v.Write(rel, sb.String(), overwrite)
}
