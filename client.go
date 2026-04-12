package main

// apparently everything needs 10 imports
import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
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
}

func main() {
	ansi() // i found out windows thinks ansi doesnt exist

	r := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("client> ")
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
			fmt.Println("register  <username> <license-key>")
			fmt.Println("login     <username>")

		case "register":
			if len(parts) != 3 {
				fmt.Println("\033[31musage: register <username> <license-key>\033[0m")
				continue
			}

			ts := time.Now().Unix()
			n := nonce()
			s, err := sig()
			if err != nil {
				fmt.Println("\033[31mserver offline\033[0m")
				continue
			}

			req := reg{
				Username: parts[1],
				Key:      parts[2],
				Ts:       ts,
				Nonce:    n,
			}
			req.Sig = sign(s, map[string]string{
				"key":      req.Key,
				"nonce":    req.Nonce,
				"ts":       fmt.Sprintf("%d", req.Ts),
				"username": req.Username,
			})

			data, _ := json.Marshal(req)
			// dont touch my fucking vps jesus 
			resp, err := http.Post("http://150.241.230.45:312/register", "application/json", bytes.NewReader(data))
			if err != nil {
				fmt.Println("\033[31mserver offline\033[0m")
				continue
			}

			var out res
			if json.NewDecoder(resp.Body).Decode(&out) != nil {
				resp.Body.Close()
				fmt.Println("\033[31mserver offline\033[0m")
				continue
			}
			resp.Body.Close()

			if !out.Success {
				fmt.Println("\033[31m" + out.Message + "\033[0m")
				continue
			}

			fmt.Println("\033[32mregistered " + parts[1] + "\033[0m")

		case "login":
			if len(parts) != 2 {
				fmt.Println("\033[31musage: login <username>\033[0m")
				continue
			}

			h, err := hwid()
			if err != nil {
				fmt.Println("\033[31m" + err.Error() + "\033[0m")
				continue
			}

			ts := time.Now().Unix()
			n := nonce()
			s, err := sig()
			if err != nil {
				fmt.Println("\033[31mserver offline\033[0m")
				continue
			}

			req := auth{
				Username: parts[1],
				HWID:     h,
				Ts:       ts,
				Nonce:    n,
			}
			req.Sig = sign(s, map[string]string{
				"hwid":     req.HWID,
				"nonce":    req.Nonce,
				"ts":       fmt.Sprintf("%d", req.Ts),
				"username": req.Username,
			})

			data, _ := json.Marshal(req)
			// DONT MAKE ME SAY IT AGAIN
			resp, err := http.Post("http://150.241.230.45:312/auth", "application/json", bytes.NewReader(data))
			if err != nil {
				fmt.Println("\033[31mserver offline\033[0m")
				continue
			}

			var out res
			if json.NewDecoder(resp.Body).Decode(&out) != nil {
				resp.Body.Close()
				fmt.Println("\033[31mserver offline\033[0m")
				continue
			}
			resp.Body.Close()

			if !out.Success {
				fmt.Println("\033[31m" + out.Message + "\033[0m")
				continue
			}

			fmt.Println("\033[32mlogin success for " + out.Username + "\033[0m")
			if out.ExpiresAt != "" {
				fmt.Println("expires at:", out.ExpiresAt)
			}

		default:
			fmt.Println("\033[31munknown command\033[0m")
		}
	}
}

func hwid() (string, error) {
	// hwid uncrackable 69420
	var key syscall.Handle
	err := syscall.RegOpenKeyEx(
		syscall.HKEY_LOCAL_MACHINE,
		syscall.StringToUTF16Ptr(`SOFTWARE\Microsoft\Cryptography`),
		0,
		syscall.KEY_READ|syscall.KEY_WOW64_64KEY,
		&key,
	)
	if err != nil {
		return "", err
	}
	defer syscall.RegCloseKey(key)

	name := syscall.StringToUTF16Ptr("MachineGuid")
	var typ uint32
	var size uint32
	if err := syscall.RegQueryValueEx(key, name, nil, &typ, nil, &size); err != nil {
		return "", err
	}

	buf := make([]byte, size)
	if err := syscall.RegQueryValueEx(key, name, nil, &typ, &buf[0], &size); err != nil {
		return "", err
	}

	u16 := make([]uint16, 0, len(buf)/2)
	for i := 0; i+1 < len(buf); i += 2 {
		u16 = append(u16, binary.LittleEndian.Uint16(buf[i:i+2]))
	}

	raw := strings.TrimSpace(syscall.UTF16ToString(u16))
	if raw == "" {
		return "", fmt.Errorf("failed to read hwid")
	}

	sum := sha256.Sum256([]byte(strings.ToLower(raw)))
	return fmt.Sprintf("%x", sum), nil
}

func ansi() { // the windows docs said this works and once it worked 
	// i also thought there was a much more simple way of doing this but i guess not
	k := syscall.NewLazyDLL("kernel32.dll")
	g := k.NewProc("GetConsoleMode")
	s := k.NewProc("SetConsoleMode")

	for _, h := range []int{syscall.STD_OUTPUT_HANDLE, syscall.STD_ERROR_HANDLE} {
		c, err := syscall.GetStdHandle(h)
		if err != nil {
			continue
		}

		var m uint32
		ok, _, _ := g.Call(uintptr(c), uintptr(unsafe.Pointer(&m)))
		if ok == 0 {
			continue
		}

		const vt = 0x0004
		_, _, _ = s.Call(uintptr(c), uintptr(m|vt))
	}
}

func nonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func sig() (string, error) {
    // I SWEAR TO FUCKING GOD SAY WALLIAH 
	resp, err := http.Get("http://150.241.230.45:312/sig")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var out struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Sig     string `json:"sig"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if !out.Success || out.Sig == "" {
		return "", fmt.Errorf("missing sig")
	}

	return out.Sig, nil
}

func sign(sec string, m map[string]string) string {
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
	return hex.EncodeToString(h.Sum(nil))
}
