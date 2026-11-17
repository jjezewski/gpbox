package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"
)

type Session struct {
	ID          string `json:"id"`
	Cookie      string `json:"cookie"`
	Host        string `json:"host,omitempty"`
	ConnectURL  string `json:"connect_url,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Resolve     string `json:"resolve,omitempty"`
	User        string `json:"user,omitempty"`
	SavedAt     string `json:"saved_at,omitempty"`
}

type Store struct {
	Dir string
	ID  string
}

func NewStore(dir, portal, mode, key string) *Store {
	sum := sha256.Sum256([]byte(portal + "|" + mode + "|" + key))
	return &Store{Dir: dir, ID: hex.EncodeToString(sum[:])[:16]}
}

func (st *Store) path() string { return filepath.Join(st.Dir, "session.json") }

func (st *Store) Load() *Session {
	b, err := os.ReadFile(st.path())
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Printf("Cannot read saved session: %v", err)
		}
		return nil
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil || s.Cookie == "" {
		log.Printf("Saved session is not valid, ignoring it.")
		return nil
	}
	if s.ID != st.ID {
		log.Printf("SESSION_KEY, GP_PORTAL or GP_MODE changed: the saved cookie is not used.")
		return nil
	}
	return &s
}

func (st *Store) Save(s *Session) error {
	s.ID = st.ID
	s.SavedAt = time.Now().Format("2006-01-02 15:04:05")
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(st.Dir, 0o700); err != nil {
		return err
	}
	tmp := st.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path())
}

func (st *Store) Clear() {
	if err := os.Remove(st.path()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("Cannot remove saved session: %v", err)
	}
}
