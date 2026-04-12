package main

// go requires so many imports
import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// this is better then telegram database
func main() {
	db := newDB("database/users.json")
	if err := db.ensure(); err != nil {
		fmt.Println("\033[31m" + err.Error() + "\033[0m")
		return
	}

	r := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("api> ")
		line, err := r.ReadString('\n')
		if err != nil {
			fmt.Println("\033[31m" + err.Error() + "\033[0m")
			return
		}

		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) == 0 {
			continue
		}

		switch strings.ToLower(parts[0]) {
		case "help":
			// ? i did not ai what? dont talk crazy
			fmt.Println("user create [1h|1d|1w|1m|1y]")
			fmt.Println("user add <username> <1h|1d|1w|1m|1y>")
			fmt.Println("user ban <username> [reason]")
			fmt.Println("user unban <username>")
			fmt.Println("user remove <username>")
			fmt.Println("user resethwid <username>")
			fmt.Println("user list")
			fmt.Println("start")
			fmt.Println("stop")
			fmt.Println("check")

		case "user":
			if len(parts) < 2 {
				fmt.Println("\033[31musage: user <create|add|ban|unban|remove|resethwid|list>\033[0m")
				continue
			}

			switch strings.ToLower(parts[1]) {
			case "create":
				s := ""
				if len(parts) > 2 {
					s = parts[2]
				}

				x, err := exp(s)
				if err != nil {
					fmt.Println("\033[31m" + err.Error() + "\033[0m")
					continue
				}

				u, err := db.make(x)
				if err != nil {
					fmt.Println("\033[31m" + err.Error() + "\033[0m")
					continue
				}

				fmt.Println("\033[32msuccessfully created license\033[0m")
				fmt.Println("license key:", u.Key)
				fmt.Println("expires at:", u.ExpiresAt.Local().Format(time.RFC1123))

			case "add":
				if len(parts) != 4 {
					fmt.Println("\033[31musage: user add <username> <1h|1d|1w|1m|1y>\033[0m")
					continue
				}

				x, err := exp(parts[3])
				if err != nil {
					fmt.Println("\033[31m" + err.Error() + "\033[0m")
					continue
				}

				u, err := db.add(parts[2], x)
				if err != nil {
					fmt.Println("\033[31m" + err.Error() + "\033[0m")
					continue
				}

				fmt.Println("\033[32muser added\033[0m")
				fmt.Println("username:", u.Username)
				fmt.Println("license key:", u.Key)
				fmt.Println("expires at:", u.ExpiresAt.Local().Format(time.RFC1123))

			case "ban":
				if len(parts) < 3 {
					fmt.Println("\033[31musage: user ban <username> [reason]\033[0m")
					continue
				}

				reason := ""
				if len(parts) > 3 {
					reason = strings.Join(parts[3:], " ")
				}

				fmt.Print("\033[33mban " + parts[2] + " (y/n): \033[0m")
				in, _ := r.ReadString('\n')
				x := strings.ToLower(strings.TrimSpace(in))
				if x != "y" && x != "yes" {
					fmt.Println("\033[31mcancelled\033[0m")
					continue
				}

				if err := db.ban(parts[2], reason, true); err != nil {
					fmt.Println("\033[31m" + err.Error() + "\033[0m")
					continue
				}

				fmt.Println("\033[32muser banned\033[0m")

			case "unban":
				if len(parts) != 3 {
					fmt.Println("\033[31musage: user unban <username>\033[0m")
					continue
				}

				fmt.Print("\033[33munban " + parts[2] + " (y/n): \033[0m")
				in, _ := r.ReadString('\n')
				x := strings.ToLower(strings.TrimSpace(in))
				if x != "y" && x != "yes" {
					fmt.Println("\033[31mcancelled\033[0m")
					continue
				}

				if err := db.ban(parts[2], "", false); err != nil {
					fmt.Println("\033[31m" + err.Error() + "\033[0m")
					continue
				}

				fmt.Println("\033[32muser unbanned\033[0m")

			case "remove":
				if len(parts) != 3 {
					fmt.Println("\033[31musage: user remove <username>\033[0m")
					continue
				}

				fmt.Print("\033[33mremove " + parts[2] + " (y/n): \033[0m")
				in, _ := r.ReadString('\n')
				x := strings.ToLower(strings.TrimSpace(in))
				if x != "y" && x != "yes" {
					fmt.Println("\033[31mcancelled\033[0m")
					continue
				}

				if err := db.del(parts[2]); err != nil {
					fmt.Println("\033[31m" + err.Error() + "\033[0m")
					continue
				}

				fmt.Println("\033[32muser removed\033[0m")

			case "resethwid":
				if len(parts) != 3 {
					fmt.Println("\033[31musage: user resethwid <username>\033[0m")
					continue
				}

				fmt.Print("\033[33mreset hwid for " + parts[2] + " (y/n): \033[0m")
				in, _ := r.ReadString('\n')
				x := strings.ToLower(strings.TrimSpace(in))
				if x != "y" && x != "yes" {
					fmt.Println("\033[31mcancelled\033[0m")
					continue
				}

				if err := db.reset(parts[2]); err != nil {
					fmt.Println("\033[31m" + err.Error() + "\033[0m")
					continue
				}

				fmt.Println("\033[32mhwid reset\033[0m")

			case "list":
				list, err := db.all()
				if err != nil {
					fmt.Println("\033[31m" + err.Error() + "\033[0m")
					continue
				}

				if len(list) == 0 {
					fmt.Println("\033[33mno users\033[0m")
					continue
				}

				for _, u := range list {
					name := u.Username
					if name == "" {
						name = "(unregistered)"
					}

					b := "no"
					if u.Banned {
						b = "yes"
					}

					h := "blank"
					if u.HWID != "" {
						h = "set"
					}

					fmt.Println("username:", name)
					fmt.Println("key:", u.Key)
					fmt.Println("banned:", b)
					fmt.Println("ban reason:", u.BanReason)
					fmt.Println("hwid:", h)
					fmt.Println("expires:", u.ExpiresAt.Local().Format(time.RFC1123))
					fmt.Println("")
				}

			default:
				fmt.Println("\033[31musage: user <create|add|ban|unban|remove|resethwid|list>\033[0m")
			}

		case "check":
			c := http.Client{Timeout: 2 * time.Second}
			resp, err := c.Get("http://127.0.0.1:312/") // sexy serverip
			if err != nil || resp.StatusCode != http.StatusOK {
				fmt.Println("\033[31moffline\033[0m")
				continue
			}
			resp.Body.Close()
			fmt.Println("\033[32monline\033[0m")

		case "start":
			if pid() > 0 {
				fmt.Println("\033[33mrunning already\033[0m")
				continue
			}

			x := exec.Command("sh", "-c", "nohup go run server.go >/dev/null 2>&1 &") // i dont really know linux all that well
			x.Dir = "."
			if err := x.Run(); err != nil {
				fmt.Println("\033[31m" + err.Error() + "\033[0m")
				continue
			}

			ok := false
			for i := 0; i < 20; i++ {
				time.Sleep(250 * time.Millisecond)
				c := http.Client{Timeout: 500 * time.Millisecond}
				resp, err := c.Get("http://127.0.0.1:312/")
				if err == nil && resp.StatusCode == http.StatusOK {
					resp.Body.Close()
					ok = true
					break
				}
				if resp != nil {
					resp.Body.Close()
				}
			}

			if ok {
				fmt.Println("\033[32monline\033[0m")
			} else {
				fmt.Println("\033[31moffline\033[0m")
			}

		case "stop":
			n := pid()
			if n == 0 {
				fmt.Println("\033[31moffline\033[0m")
				continue
			}

			p, err := os.FindProcess(n)
			if err != nil || p.Kill() != nil {
				_ = os.Remove("server.pid") // pid? what? what the hell is a pid? ohh a pid
				fmt.Println("\033[31moffline\033[0m")
				continue
			}

			_ = os.Remove("server.pid")
			down := false
			for i := 0; i < 20; i++ {
				time.Sleep(250 * time.Millisecond)
				c := http.Client{Timeout: 500 * time.Millisecond}
				resp, err := c.Get("http://127.0.0.1:312/")
				if err != nil {
					down = true
					break
				}
				if resp != nil {
					resp.Body.Close()
				}
			}

			if down {
				fmt.Println("\033[31moffline\033[0m")
			} else {
				fmt.Println("\033[33mrunning already\033[0m")
			}

		default:
			fmt.Println("\033[31munknown command\033[0m")
		}
	}
}

func pid() int {
	data, err := os.ReadFile("server.pid")
	if err != nil {
		return 0
	}

	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || n <= 0 {
		_ = os.Remove("server.pid")
		return 0
	}

	p, err := os.FindProcess(n)
	if err != nil || p.Signal(syscall.Signal(0)) != nil {
		_ = os.Remove("server.pid")
		return 0
	}

	return n
}

// rahhhhhh
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

func (d *db) all() ([]user, error) {
	return d.load()
}

func (d *db) make(x time.Time) (user, error) {
	list, err := d.load()
	if err != nil {
		return user{}, err
	}

	now := time.Now().UTC()
	s := strconv.FormatInt(time.Now().UnixNano(), 10)
	u := user{
		Key:       "cat" + s[len(s)-16:],
		CreatedAt: now,
		ExpiresAt: x,
	}

	list = append(list, u)
	if err := d.save(list); err != nil {
		return user{}, err
	}

	return u, nil
}

func (d *db) add(name string, x time.Time) (user, error) {
	list, err := d.load()
	if err != nil {
		return user{}, err
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return user{}, fmt.Errorf("username required")
	}
	if len(name) > 16 {
		return user{}, fmt.Errorf("username too long")
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return user{}, fmt.Errorf("username must only use letters and numbers")
		}
	}

	for _, u := range list {
		if strings.EqualFold(u.Username, name) {
			return user{}, fmt.Errorf("username already exists")
		}
	}

	now := time.Now().UTC()
	s := strconv.FormatInt(time.Now().UnixNano(), 10)
	u := user{
		Username:  name,
		Key:       "cat" + s[len(s)-16:],
		CreatedAt: now,
		ExpiresAt: x,
	}

	list = append(list, u)
	if err := d.save(list); err != nil {
		return user{}, err
	}

	return u, nil
}

func (d *db) reset(name string) error {
	list, err := d.load()
	if err != nil {
		return err
	}

	for i := range list {
		if strings.EqualFold(list[i].Username, name) {
			list[i].HWID = ""
			return d.save(list)
		}
	}

	return fmt.Errorf("username not found")
}

func (d *db) del(name string) error {
	list, err := d.load()
	if err != nil {
		return err
	}

	for i := range list {
		if strings.EqualFold(list[i].Username, name) {
			list = append(list[:i], list[i+1:]...)
			return d.save(list)
		}
	}

	return fmt.Errorf("username not found")
}

func (d *db) ban(name, reason string, on bool) error {
	list, err := d.load()
	if err != nil {
		return err
	}

	for i := range list {
		if strings.EqualFold(list[i].Username, name) {
			list[i].Banned = on
			if on {
				list[i].BanReason = strings.TrimSpace(reason)
			} else {
				list[i].BanReason = ""
			}
			return d.save(list)
		}
	}

	return fmt.Errorf("username not found")
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

func exp(s string) (time.Time, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return time.Now().UTC().AddDate(0, 0, 30), nil
	}

	now := time.Now().UTC()

	switch { // math.huge
	case strings.HasSuffix(s, "y"):
		n, err := num(s[:len(s)-1])
		if err != nil {
			return time.Time{}, err
		}
		return now.AddDate(n, 0, 0), nil
	case strings.HasSuffix(s, "m"):
		n, err := num(s[:len(s)-1])
		if err != nil {
			return time.Time{}, err
		}
		return now.AddDate(0, n, 0), nil
	case strings.HasSuffix(s, "w"):
		n, err := num(s[:len(s)-1])
		if err != nil {
			return time.Time{}, err
		}
		return now.AddDate(0, 0, n*7), nil
	case strings.HasSuffix(s, "d"):
		n, err := num(s[:len(s)-1])
		if err != nil {
			return time.Time{}, err
		}
		return now.AddDate(0, 0, n), nil
	case strings.HasSuffix(s, "h"):
		n, err := num(s[:len(s)-1])
		if err != nil {
			return time.Time{}, err
		}
		return now.Add(time.Duration(n) * time.Hour), nil
	default:
		return time.Time{}, fmt.Errorf("invalid duration %q, use 1h, 1d, 1w, 1m, or 1y", s)
	}
}

func num(s string) (int, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid duration")
	}
	if n > int64(^uint(0)>>1) {
		return 0, fmt.Errorf("duration too large")
	}
	return int(n), nil
}
