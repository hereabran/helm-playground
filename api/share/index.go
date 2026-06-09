// Package share provides pluggable persistence for share payloads, selected at
// runtime via the SHARE_STORE environment variable. It keeps Charthouse
// vendor-neutral: the default works with zero configuration and no external
// service, while file and Supabase backends are opt-in.
package share

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// MaxPayloadBytes caps an accepted share payload.
	MaxPayloadBytes = 256 * 1024

	// idAlphabet excludes ambiguous characters (0/1/i/l/o) so ids are safe to
	// read aloud or transcribe. 31 symbols ^ 8 chars ≈ 8.5e11 keyspace.
	idAlphabet = "23456789abcdefghjkmnpqrstuvwxyz"
	idLength   = 8

	defaultShareDir = "./data/shares"

	sharesTable     = "charthouse_shares"
	upstreamTimeout = 8 * time.Second
)

// ErrNotFound is returned by Get when no share exists for the id.
var ErrNotFound = errors.New("share not found")

// IDPattern validates ids accepted from clients (also covers legacy 6–16 char ids).
var IDPattern = regexp.MustCompile(`^[a-z0-9]{6,16}$`)

// Store persists an opaque JSON share payload keyed by a short id.
type Store interface {
	Put(ctx context.Context, payload json.RawMessage) (id string, err error)
	Get(ctx context.Context, id string) (payload json.RawMessage, err error)
}

// newStore selects a Store from the environment:
//
//	SHARE_STORE=memory   (default) ephemeral in-process map — links die on restart
//	SHARE_STORE=file     JSON files under SHARE_DIR (default ./data/shares)
//	SHARE_STORE=supabase Supabase PostgREST (needs SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY)
//
// An error here is surfaced by the handler as 503 so the SPA falls back to
// self-contained hash URLs.
func newStore() (Store, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHARE_STORE"))) {
	case "", "memory":
		return newMemoryStore(), nil
	case "file":
		return newFileStore(os.Getenv("SHARE_DIR"))
	case "supabase":
		return newSupabaseStore()
	default:
		return nil, fmt.Errorf("unknown SHARE_STORE %q (want memory|file|supabase)", os.Getenv("SHARE_STORE"))
	}
}

// NewID returns a random short id from the unambiguous alphabet.
func NewID() (string, error) {
	buf := make([]byte, idLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, idLength)
	for i, b := range buf {
		out[i] = idAlphabet[int(b)%len(idAlphabet)]
	}
	return string(out), nil
}

// memoryStore is the default backend: ephemeral, process-local, zero-config.
// Short links survive only until the process restarts; use file or supabase for
// durability.
type memoryStore struct {
	mu sync.RWMutex
	m  map[string]json.RawMessage
}

func newMemoryStore() *memoryStore {
	return &memoryStore{m: make(map[string]json.RawMessage)}
}

func (s *memoryStore) Put(_ context.Context, payload json.RawMessage) (string, error) {
	cp := append(json.RawMessage(nil), payload...)
	s.mu.Lock()
	defer s.mu.Unlock()
	for range 8 {
		id, err := NewID()
		if err != nil {
			return "", err
		}
		if _, exists := s.m[id]; exists {
			continue
		}
		s.m[id] = cp
		return id, nil
	}
	return "", errors.New("could not allocate a unique share id")
}

func (s *memoryStore) Get(_ context.Context, id string) (json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[id]
	if !ok {
		return nil, ErrNotFound
	}
	return append(json.RawMessage(nil), v...), nil
}

// fileStore persists one JSON file per share under a directory. Durable across
// restarts; good for single-node self-hosting with a mounted volume.
type fileStore struct {
	dir string
}

type fileRecord struct {
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
}

func newFileStore(dir string) (*fileStore, error) {
	if dir == "" {
		dir = defaultShareDir
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("share dir %q: %w", dir, err)
	}
	return &fileStore{dir: dir}, nil
}

func (s *fileStore) path(id string) string {
	return filepath.Join(s.dir, id+".json")
}

func (s *fileStore) Put(_ context.Context, payload json.RawMessage) (string, error) {
	for range 8 {
		id, err := NewID()
		if err != nil {
			return "", err
		}
		dest := s.path(id)
		if _, err := os.Stat(dest); err == nil {
			continue // id collision, retry
		}
		rec, err := json.Marshal(fileRecord{ID: id, Payload: payload})
		if err != nil {
			return "", err
		}
		// Atomic publish: write to a temp file in the same dir, then rename.
		tmp, err := os.CreateTemp(s.dir, ".tmp-*")
		if err != nil {
			return "", err
		}
		tmpName := tmp.Name()
		if _, err := tmp.Write(rec); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return "", err
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmpName)
			return "", err
		}
		if err := os.Rename(tmpName, dest); err != nil {
			os.Remove(tmpName)
			return "", err
		}
		return id, nil
	}
	return "", errors.New("could not allocate a unique share id")
}

func (s *fileStore) Get(_ context.Context, id string) (json.RawMessage, error) {
	// Defense in depth: never let an unvalidated id touch the filesystem path.
	if !IDPattern.MatchString(id) {
		return nil, ErrNotFound
	}
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var rec fileRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return rec.Payload, nil
}

// supabaseStore persists shares in a Supabase (PostgREST) table using the
// service-role key. Opt-in via SHARE_STORE=supabase; the key is server-only.
type supabaseStore struct {
	baseURL string
	key     string
}

type supabaseRow struct {
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
}

func newSupabaseStore() (*supabaseStore, error) {
	base := strings.TrimRight(os.Getenv("SUPABASE_URL"), "/")
	key := os.Getenv("SUPABASE_SERVICE_ROLE_KEY")
	if base == "" || key == "" {
		return nil, fmt.Errorf("SHARE_STORE=supabase requires SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY")
	}
	return &supabaseStore{baseURL: base, key: key}, nil
}

func (s *supabaseStore) auth(req *http.Request) {
	req.Header.Set("apikey", s.key)
	req.Header.Set("Authorization", "Bearer "+s.key)
}

func (s *supabaseStore) Get(ctx context.Context, id string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()

	endpoint := fmt.Sprintf("%s/rest/v1/%s?id=eq.%s&select=payload&limit=1",
		s.baseURL, sharesTable, url.QueryEscape(id))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	s.auth(req)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("supabase unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("supabase %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rows []supabaseRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return rows[0].Payload, nil
}

func (s *supabaseStore) Put(ctx context.Context, payload json.RawMessage) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()

	id, err := NewID()
	if err != nil {
		return "", err
	}
	row, err := json.Marshal(supabaseRow{ID: id, Payload: payload})
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("%s/rest/v1/%s", s.baseURL, sharesTable)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(row))
	if err != nil {
		return "", err
	}
	s.auth(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=minimal")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("supabase unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("supabase %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return id, nil
}

var (
	sharedStore     Store
	sharedStoreErr  error
	sharedStoreOnce sync.Once
)

func getStore() (Store, error) {
	sharedStoreOnce.Do(func() {
		sharedStore, sharedStoreErr = newStore()
	})
	return sharedStore, sharedStoreErr
}

// Handler implements GET ?id=<short-id> and POST {payload}. The backing store
// is selected by SHARE_STORE (memory default; file; supabase) — see api/share/store.
//
// With the default in-memory store, sharing works out of the box, so 503 is
// returned only when an explicitly configured store fails to initialize (e.g.
// SHARE_STORE=supabase with missing credentials). The SPA treats that 503 as a
// signal to fall back to self-contained hash URLs.
func Handler(w http.ResponseWriter, r *http.Request) {
	s, err := getStore()
	if err != nil {
		sendJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "sharing not configured: " + err.Error(),
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleGet(w, r, s)
	case http.MethodPost:
		handlePost(w, r, s)
	default:
		w.Header().Set("allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func handleGet(w http.ResponseWriter, r *http.Request, s Store) {
	id := r.URL.Query().Get("id")
	if !IDPattern.MatchString(id) {
		sendJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid id"})
		return
	}

	payload, err := s.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			sendJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		sendJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}

	sendJSON(w, http.StatusOK, map[string]any{"id": id, "payload": payload})
}

func handlePost(w http.ResponseWriter, r *http.Request, s Store) {
	body := http.MaxBytesReader(w, r.Body, MaxPayloadBytes)
	var parsed struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(body).Decode(&parsed); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request: " + err.Error()})
		return
	}
	if len(parsed.Payload) == 0 || !looksLikeJSONObject(parsed.Payload) {
		sendJSON(w, http.StatusBadRequest, map[string]any{"error": "payload required"})
		return
	}

	id, err := s.Put(r.Context(), parsed.Payload)
	if err != nil {
		sendJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}

	sendJSON(w, http.StatusOK, map[string]any{"id": id})
}

func looksLikeJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func sendJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
