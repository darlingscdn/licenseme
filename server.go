package main

// more imports
import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

type reg struct {
	Username string `json:"username"`
	Key      string `json:"key"`
	Ts       int64  `json:"ts"`
	Nonce    string `json:"nonce"`
	Sig      string `json:"sig"`
}

type auth struct {
	Username string `json:"username"`
	HWID     string `json:"hwid"`
	Ts       int64  `json:"ts"`
	Nonce    string `json:"nonce"`
	Sig      string `json:"sig"`
}

type res struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Username  string `json:"username,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Sig       string `json:"sig,omitempty"`
}

type oklog struct {
	Time string `json:"time"`
	User string `json:"user"`
	Hwid string `json:"hwid"`
	New  bool   `json:"new_hwid"`
}

type badlog struct {
	Time string `json:"time"`
	User string `json:"user"`
	Hwid string `json:"hwid"`
	Why  string `json:"why"`
}

// uhhhhhhh wait uhhhhhhhhhh uhmm 
var tries = map[string][]time.Time{}

func main() {
	db := newDB("database/users.json")
	if err := db.ensure(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	ln, err := net.Listen("tcp", ":312")
	if err != nil {
		fmt.Println("\033[33mrunning already\033[0m")
		return
	}
	defer ln.Close()

	_ = os.WriteFile("server.pid", []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644)
	defer os.Remove("server.pid")

	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	mux := http.NewServeMux()
	sec := sig() // per start

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		write(w, http.StatusOK, res{Success: true, Message: "online"})
	})

	mux.HandleFunc("/sig", func(w http.ResponseWriter, r *http.Request) {
		// so because i dont want to set up https i can do this
		write(w, http.StatusOK, res{Success: true, Sig: sec})
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			write(w, http.StatusMethodNotAllowed, res{Success: false, Message: "method not allowed"})
			return
		}

		var req reg
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			bad("", "", "bad request")
			write(w, http.StatusBadRequest, res{Success: false, Message: "bad request"})
			return
		}

		req.Username = strings.TrimSpace(req.Username)
		req.Key = strings.TrimSpace(req.Key)

		if req.Username == "" || req.Key == "" {
			write(w, http.StatusBadRequest, res{Success: false, Message: "missing username or key"})
			return
		}
		if len(req.Username) > 16 {
			write(w, http.StatusBadRequest, res{Success: false, Message: "username too long"})
			return
		}
		if !nameok(req.Username) {
			write(w, http.StatusBadRequest, res{Success: false, Message: "username must only use letters and numbers"})
			return
		}
		if req.Ts == 0 || req.Nonce == "" || req.Sig == "" {
			write(w, http.StatusBadRequest, res{Success: false, Message: "missing signature"})
			return
		}
		if time.Now().Unix()-req.Ts > 300 || req.Ts-time.Now().Unix() > 300 {
			write(w, http.StatusBadRequest, res{Success: false, Message: "request expired"})
			return
		}
		if !ok(map[string]string{
			"key":      req.Key,
			"nonce":    req.Nonce,
			"ts":       fmt.Sprintf("%d", req.Ts),
			"username": req.Username,
		}, req.Sig, sec) {
			write(w, http.StatusForbidden, res{Success: false, Message: "bad signature"})
			return
		}

		u, err := db.reg(req.Key, req.Username)
		if err != nil {
			write(w, http.StatusBadRequest, res{Success: false, Message: err.Error()})
			return
		}

		write(w, http.StatusOK, res{Success: true, Message: "license registered", Username: u.Username})
	})

	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) { // tbh i dont remember making this 
		if r.Method != http.MethodPost {
			write(w, http.StatusMethodNotAllowed, res{Success: false, Message: "method not allowed"})
			return
		}

		var req auth
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			bad("", "", "bad request")
			write(w, http.StatusBadRequest, res{Success: false, Message: "bad request"})
			return
		}

		req.Username = strings.TrimSpace(req.Username)
		req.HWID = strings.TrimSpace(req.HWID)

		if req.Username == "" {
			bad(req.Username, req.HWID, "missing username")
			write(w, http.StatusBadRequest, res{Success: false, Message: "missing username"})
			return
		}
		if !allow(req.Username) {
			bad(req.Username, req.HWID, "rate limited")
			write(w, http.StatusTooManyRequests, res{Success: false, Message: "too many attempts"})
			return
		}
		if len(req.Username) > 16 {
			bad(req.Username, req.HWID, "username too long")
			write(w, http.StatusBadRequest, res{Success: false, Message: "username too long"})
			return
		}
		if !nameok(req.Username) {
			bad(req.Username, req.HWID, "username must only use letters and numbers")
			write(w, http.StatusBadRequest, res{Success: false, Message: "username must only use letters and numbers"})
			return
		}
		if req.Ts == 0 || req.Nonce == "" || req.Sig == "" {
			bad(req.Username, req.HWID, "missing signature")
			write(w, http.StatusBadRequest, res{Success: false, Message: "missing signature"})
			return
		}
		if time.Now().Unix()-req.Ts > 300 || req.Ts-time.Now().Unix() > 300 {
			bad(req.Username, req.HWID, "request expired")
			write(w, http.StatusBadRequest, res{Success: false, Message: "request expired"})
			return
		}
		if !ok(map[string]string{
			"hwid":     req.HWID,
			"nonce":    req.Nonce,
			"ts":       fmt.Sprintf("%d", req.Ts),
			"username": req.Username,
		}, req.Sig, sec) {
			bad(req.Username, req.HWID, "bad signature")
			write(w, http.StatusForbidden, res{Success: false, Message: "bad signature"})
			return
		}

		u, err := db.get(req.Username)
		if err != nil {
			bad(req.Username, req.HWID, "invalid username")
			write(w, http.StatusUnauthorized, res{Success: false, Message: "invalid username"})
			return
		}

		if u.Banned {
			msg := "user has been banned"
			if u.BanReason != "" {
				msg += ": " + u.BanReason
			}
			bad(req.Username, req.HWID, msg)
			write(w, http.StatusForbidden, res{Success: false, Message: msg, Username: u.Username})
			return
		}

		if time.Now().UTC().After(u.ExpiresAt) {
			bad(req.Username, req.HWID, "license has expired")
			write(w, http.StatusForbidden, res{
				Success:   false,
				Message:   "license has expired",
				Username:  u.Username,
				ExpiresAt: u.ExpiresAt.Format(time.RFC3339),
			})
			return
		}

		first := u.HWID == ""
		if req.HWID != "" {
			if u.HWID == "" {
				// hwid bindy
				u, err = db.bind(u.Key, req.HWID)
				if err != nil {
					bad(req.Username, req.HWID, "failed to bind hwid")
					write(w, http.StatusInternalServerError, res{Success: false, Message: "failed to bind hwid"})
					return
				}
			} else if u.HWID != req.HWID {
				bad(req.Username, req.HWID, "hwid mismatch")
				write(w, http.StatusForbidden, res{Success: false, Message: "hwid mismatch", Username: u.Username})
				return
			}
		}

		good(u.Username, req.HWID, first)
		write(w, http.StatusOK, res{
			Success:   true,
			Message:   "license authenticated",
			Username:  u.Username,
			ExpiresAt: u.ExpiresAt.Format(time.RFC3339),
		})
	})

	srv.Handler = mux
	fmt.Println(ipv4() + ":312")
	_ = srv.Serve(ln)
}

func write(w http.ResponseWriter, code int, out res) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(out)
}

func ipv4() string {
	c := http.Client{Timeout: 5 * time.Second}
	// it took like 15 min to find the new url fucking hell
	resp, err := c.Get("https://ipv4.icanhazip.com")
	if err == nil {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ip := strings.TrimSpace(string(data))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return "127.0.0.1"
}

func ok(m map[string]string, sig, sec string) bool {
	// sort keys out
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte('&')
	}

	h := hmac.New(sha256.New, []byte(sec))
	h.Write([]byte(b.String()))
	x := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(x), []byte(sig))
}

func sig() string {
	// fallback ai suggested 
	const letters = "abcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "fallbackx"
	}
	for i := range buf {
		buf[i] = letters[int(buf[i])%len(letters)]
	}
	return string(buf)
}

func good(user, hwid string, now bool) {
	add("database/logs/logins.json", oklog{
		Time: time.Now().UTC().Format(time.RFC3339),
		User: user,
		Hwid: hwid,
		New:  now,
	})
}

func bad(user, hwid, why string) {
	add("database/logs/failedlogin.json", badlog{
		Time: time.Now().UTC().Format(time.RFC3339),
		User: user,
		Hwid: hwid,
		Why:  why,
	})
}

func add(path string, v any) {
	// loggy loggy loggy
	_ = os.MkdirAll(filepath.Dir(path), 0o755)

	list := []json.RawMessage{}
	if data, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(data)) != "" {
		_ = json.Unmarshal(data, &list)
	}

	if data, err := json.Marshal(v); err == nil {
		list = append(list, json.RawMessage(data))
		if out, err := json.MarshalIndent(list, "", "  "); err == nil {
			_ = os.WriteFile(path, append(out, '\n'), 0o644)
		}
	}
}

func allow(name string) bool {
	// crashed my fucking vps 
	now := time.Now()
	list := tries[name]
	keep := list[:0]
	for _, t := range list {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= 3 {
		tries[name] = keep
		return false
	}
	keep = append(keep, now)
	tries[name] = keep
	return true
}

func nameok(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return s != ""
}

var (
	// ai made errors for me (and maybe did logging too)
	euser = errors.New("username already exists")
	emiss = errors.New("username not found")
	ekey  = errors.New("license key not found")
	etake = errors.New("license key already assigned to a different username")
	eused = errors.New("license key has already been registered")
)

type user struct {
	Username  string    `json:"username"`
	Key       string    `json:"key"`
	HWID      string    `json:"hwid"`
	Banned    bool      `json:"banned"`
	BanReason string    `json:"ban_reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// pasted db
type db struct {
	path string
}

func newDB(path string) *db {
	return &db{path: path}
}

func (d *db) ensure() error {
	if err := os.MkdirAll(filepath.Dir(d.path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(d.path); errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(d.path, []byte("[]\n"), 0o644)
	}
	return nil
}

func (d *db) reg(key, name string) (user, error) {
	list, err := d.load()
	if err != nil {
		return user{}, err
	}

	n := -1
	for i := range list {
		if list[i].Key == key {
			n = i
			continue
		}
		if list[i].Username == name {
			return user{}, euser
		}
	}

	if n == -1 {
		return user{}, ekey
	}
	if list[n].Username != "" {
		if list[n].Username == name {
			return user{}, eused
		}
		return user{}, etake
	}

	list[n].Username = name
	if err := d.save(list); err != nil {
		return user{}, err
	}
	return list[n], nil
}

func (d *db) get(name string) (user, error) {
	list, err := d.load()
	if err != nil {
		return user{}, err
	}
	for _, u := range list {
		if u.Username == name {
			return u, nil
		}
	}
	return user{}, emiss
}

func (d *db) bind(key, hwid string) (user, error) {
	list, err := d.load()
	if err != nil {
		return user{}, err
	}
	for i := range list {
		if list[i].Key == key {
			if list[i].HWID == "" {
				list[i].HWID = hwid
				if err := d.save(list); err != nil {
					return user{}, err
				}
			}
			return list[i], nil
		}
	}
	return user{}, ekey
}

func (d *db) load() ([]user, error) {
	if err := d.ensure(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(d.path)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return []user{}, nil
	}

	var list []user
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	if list == nil {
		list = []user{}
	}
	return list, nil
}

func (d *db) save(list []user) error {
	if err := d.ensure(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(d.path, data, 0o644)
}
