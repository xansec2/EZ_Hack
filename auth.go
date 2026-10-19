package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Local account gate for the web view. This is a convenience lock for the
// localhost UI — one or more accounts, password-protected — not a hardened
// multi-tenant auth system. Credentials are stored salted and stretched with
// PBKDF2-HMAC-SHA256 (standard library only, no external crypto dependency),
// and a logged-in browser carries an opaque, HttpOnly session cookie.

const (
	sessionCookie  = "web_session"
	sessionTTL     = 7 * 24 * time.Hour
	pbkdf2Iter     = 100_000
	pbkdf2KeyLen   = 32
	saltLen        = 16
	minPasswordLen = 6
)

// User is one local account. Salt and Hash are hex-encoded; the plaintext
// password is never stored.
type User struct {
	Name    string `json:"name"`
	Salt    string `json:"salt"`
	Hash    string `json:"hash"`
	Created string `json:"created"`
}

// usersPath resolves the shared account file, kept alongside projects.json in
// the same per-user config directory.
func usersPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return sharedProjectsDir + "-users.json"
	}
	return filepath.Join(dir, sharedProjectsDir, "users.json")
}

func loadUsers() []User {
	data, err := os.ReadFile(usersPath())
	if err != nil {
		return nil
	}
	var us []User
	if json.Unmarshal(data, &us) != nil {
		return nil
	}
	return us
}

func saveUsers(us []User) error {
	path := usersPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(us, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func findUser(name string) (User, bool) {
	for _, u := range loadUsers() {
		if strings.EqualFold(u.Name, name) {
			return u, true
		}
	}
	return User{}, false
}

func anyUsers() bool { return len(loadUsers()) > 0 }

// pbkdf2SHA256 derives a key from password+salt. Implemented here so the gate
// needs no dependency beyond the standard library.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Write(buf)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// hashPassword returns the hex salt and hex derived key for a new password.
func hashPassword(password string) (saltHex, hashHex string, err error) {
	salt := make([]byte, saltLen)
	if _, err = rand.Read(salt); err != nil {
		return "", "", err
	}
	dk := pbkdf2SHA256([]byte(password), salt, pbkdf2Iter, pbkdf2KeyLen)
	return hex.EncodeToString(salt), hex.EncodeToString(dk), nil
}

// verifyPassword checks a password against a stored user in constant time.
func verifyPassword(u User, password string) bool {
	salt, err := hex.DecodeString(u.Salt)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(u.Hash)
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, pbkdf2Iter, pbkdf2KeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ── sessions ──────────────────────────────────────────────────────────────

type session struct {
	user    string
	expires time.Time
}

var (
	sessMu   sync.Mutex
	sessions = map[string]session{}
)

func newSession(user string) (string, error) {
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return "", err
	}
	id := hex.EncodeToString(tok)
	sessMu.Lock()
	sessions[id] = session{user: user, expires: time.Now().Add(sessionTTL)}
	sessMu.Unlock()
	return id, nil
}

// sessionUser returns the logged-in user for a request, or "" if none/expired.
func sessionUser(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	s, ok := sessions[c.Value]
	if !ok {
		return ""
	}
	if time.Now().After(s.expires) {
		delete(sessions, c.Value)
		return ""
	}
	return s.user
}

func dropSession(r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return
	}
	sessMu.Lock()
	delete(sessions, c.Value)
	sessMu.Unlock()
}

func setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionTTL),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// ── handlers ────────────────────────────────────────────────────────────────

type authReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// writeAuthErr sends a JSON error the login/register pages can show inline.
func writeAuthErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func decodeAuth(r *http.Request) (authReq, error) {
	var req authReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		return req, errors.New("bad request")
	}
	req.Username = strings.TrimSpace(req.Username)
	return req, nil
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeAuthErr(w, http.StatusForbidden, "forbidden")
		return
	}
	req, err := decodeAuth(r)
	if err != nil {
		writeAuthErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Username == "" {
		writeAuthErr(w, http.StatusBadRequest, "username is required")
		return
	}
	if len(req.Username) > 64 {
		writeAuthErr(w, http.StatusBadRequest, "username is too long")
		return
	}
	if len(req.Password) < minPasswordLen {
		writeAuthErr(w, http.StatusBadRequest, "password must be at least 6 characters")
		return
	}
	if _, exists := findUser(req.Username); exists {
		writeAuthErr(w, http.StatusConflict, "that username is already taken")
		return
	}
	salt, hash, err := hashPassword(req.Password)
	if err != nil {
		writeAuthErr(w, http.StatusInternalServerError, "could not create account")
		return
	}
	users := loadUsers()
	users = append(users, User{
		Name:    req.Username,
		Salt:    salt,
		Hash:    hash,
		Created: time.Now().UTC().Format(time.RFC3339),
	})
	if err := saveUsers(users); err != nil {
		writeAuthErr(w, http.StatusInternalServerError, "could not save account")
		return
	}
	id, err := newSession(req.Username)
	if err != nil {
		writeAuthErr(w, http.StatusInternalServerError, "could not start session")
		return
	}
	setSessionCookie(w, id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ok": "1"})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeAuthErr(w, http.StatusForbidden, "forbidden")
		return
	}
	req, err := decodeAuth(r)
	if err != nil {
		writeAuthErr(w, http.StatusBadRequest, "bad request")
		return
	}
	u, ok := findUser(req.Username)
	if !ok || !verifyPassword(u, req.Password) {
		writeAuthErr(w, http.StatusUnauthorized, "incorrect username or password")
		return
	}
	id, err := newSession(u.Name)
	if err != nil {
		writeAuthErr(w, http.StatusInternalServerError, "could not start session")
		return
	}
	setSessionCookie(w, id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ok": "1"})
}

// profileReq changes the signed-in operator's passphrase. Current is checked
// before New is accepted.
type profileReq struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeAuthErr(w, http.StatusForbidden, "forbidden")
		return
	}
	name := sessionUser(r)
	if name == "" {
		writeAuthErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	var req profileReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeAuthErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if len(req.New) < minPasswordLen {
		writeAuthErr(w, http.StatusBadRequest, "new passphrase must be at least 6 characters")
		return
	}
	users := loadUsers()
	idx := -1
	for i := range users {
		if strings.EqualFold(users[i].Name, name) {
			idx = i
			break
		}
	}
	if idx < 0 {
		writeAuthErr(w, http.StatusUnauthorized, "account not found")
		return
	}
	if !verifyPassword(users[idx], req.Current) {
		writeAuthErr(w, http.StatusUnauthorized, "current passphrase is incorrect")
		return
	}
	salt, hash, err := hashPassword(req.New)
	if err != nil {
		writeAuthErr(w, http.StatusInternalServerError, "could not update passphrase")
		return
	}
	users[idx].Salt = salt
	users[idx].Hash = hash
	if err := saveUsers(users); err != nil {
		writeAuthErr(w, http.StatusInternalServerError, "could not save account")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ok": "1"})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	dropSession(r)
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// requireAuth wraps a handler so unauthenticated requests are turned away: API
// paths get a 401, everything else is redirected to the login (or register)
// page.
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sessionUser(r) != "" {
			next(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeAuthErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		dest := "/login"
		if !anyUsers() {
			dest = "/register"
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
	}
}
