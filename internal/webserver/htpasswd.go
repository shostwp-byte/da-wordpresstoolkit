package webserver

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

const (
	RulePasswordProtect = "password_protect"
	DefaultAuthRealm    = "Protected WordPress Site"
	apr1Alphabet        = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// PasswordProtectionStatus describes the active HTTP Basic Authentication state for an instance.
type PasswordProtectionStatus struct {
	Enabled      bool   `json:"enabled"`
	Username     string `json:"username,omitempty"`
	Realm        string `json:"realm"`
	HTPasswdPath string `json:"-"`
}

// HashAPR1 generates an Apache/LiteSpeed/OpenLiteSpeed/Nginx-compatible `$apr1$<salt>$<hash>` password digest.
func HashAPR1(password, salt string) (string, error) {
	if len(password) == 0 || len(password) > 128 {
		return "", errors.New("HTTP Basic password length must be 1..128 characters")
	}
	if salt == "" {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		sb := make([]byte, 8)
		for i, b := range buf {
			sb[i] = apr1Alphabet[int(b)%len(apr1Alphabet)]
		}
		salt = string(sb)
	}
	if len(salt) > 8 {
		salt = salt[:8]
	}
	for i := 0; i < len(salt); i++ {
		if !strings.ContainsRune(apr1Alphabet, rune(salt[i])) {
			return "", errors.New("invalid character in APR1 salt")
		}
	}

	pw := []byte(password)
	sl := []byte(salt)

	h := md5.New()
	_, _ = h.Write(pw)
	_, _ = h.Write([]byte("$apr1$"))
	_, _ = h.Write(sl)

	alt := md5.New()
	_, _ = alt.Write(pw)
	_, _ = alt.Write(sl)
	_, _ = alt.Write(pw)
	final := alt.Sum(nil)

	for pl := len(pw); pl > 0; pl -= 16 {
		n := 16
		if pl < 16 {
			n = pl
		}
		_, _ = h.Write(final[:n])
	}

	for i := len(pw); i != 0; i >>= 1 {
		if i&1 != 0 {
			_, _ = h.Write([]byte{0})
		} else {
			_, _ = h.Write(pw[:1])
		}
	}
	final = h.Sum(nil)

	for r := 0; r < 1000; r++ {
		round := md5.New()
		if r&1 != 0 {
			_, _ = round.Write(pw)
		} else {
			_, _ = round.Write(final[:16])
		}
		if r%3 != 0 {
			_, _ = round.Write(sl)
		}
		if r%7 != 0 {
			_, _ = round.Write(pw)
		}
		if r&1 != 0 {
			_, _ = round.Write(final[:16])
		} else {
			_, _ = round.Write(pw)
		}
		final = round.Sum(nil)
	}

	var encoded [22]byte
	apr1To64(encoded[0:4], uint32(final[0])<<16|uint32(final[6])<<8|uint32(final[12]), 4)
	apr1To64(encoded[4:8], uint32(final[1])<<16|uint32(final[7])<<8|uint32(final[13]), 4)
	apr1To64(encoded[8:12], uint32(final[2])<<16|uint32(final[8])<<8|uint32(final[14]), 4)
	apr1To64(encoded[12:16], uint32(final[3])<<16|uint32(final[9])<<8|uint32(final[15]), 4)
	apr1To64(encoded[16:20], uint32(final[4])<<16|uint32(final[10])<<8|uint32(final[5]), 4)
	apr1To64(encoded[20:22], uint32(final[11]), 2)

	return "$apr1$" + salt + "$" + string(encoded[:]), nil
}

// VerifyAPR1 verifies a plaintext password against an `$apr1$<salt>$<hash>` digest in constant time.
func VerifyAPR1(password, encoded string) bool {
	if !strings.HasPrefix(encoded, "$apr1$") {
		return false
	}
	rest := strings.TrimPrefix(encoded, "$apr1$")
	idx := strings.IndexByte(rest, '$')
	if idx <= 0 || idx > 8 {
		return false
	}
	salt := rest[:idx]
	recomputed, err := HashAPR1(password, salt)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(recomputed), []byte(encoded)) == 1
}

func apr1To64(dst []byte, v uint32, n int) {
	for i := 0; i < n; i++ {
		dst[i] = apr1Alphabet[v&0x3f]
		v >>= 6
	}
}

func (a *Adapter) htpasswdFilePath(acct dausers.Account, instID string) (string, error) {
	if err := config.ValidateInstanceID(instID); err != nil {
		return "", err
	}
	home := filepath.Clean(strings.TrimSpace(acct.HomeDir))
	if home == "" || home == "." || home == string(filepath.Separator) {
		return "", errors.New("invalid account home directory for .htpasswd")
	}
	if st, err := os.Lstat(home); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("security violation: account home directory is a symlink")
	}
	htDir := filepath.Join(home, ".htpasswd")
	if st, err := os.Lstat(htDir); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("security violation: .htpasswd directory is a symlink")
	}
	p := filepath.Join(htDir, "da-wptk-"+instID+".htpasswd")
	if st, err := os.Lstat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("security violation: .htpasswd file is a symlink")
	}
	return p, nil
}

func sanitizeRealmLabel(realm string) string {
	r := strings.TrimSpace(realm)
	if r == "" {
		return DefaultAuthRealm
	}
	var b strings.Builder
	for _, ch := range r {
		if ch >= 32 && ch <= 126 && ch != '"' && ch != '\\' && ch != '$' && ch != ';' {
			b.WriteRune(ch)
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() == 0 {
		return DefaultAuthRealm
	}
	return b.String()
}

// GetPasswordProtectionStatus inspects the active HTTP Basic Authentication rule & .htpasswd metadata.
func (a *Adapter) GetPasswordProtectionStatus(acct dausers.Account, inst store.InstanceRecord) PasswordProtectionStatus {
	enabled := a.IsRuleApplied(acct, inst, RulePasswordProtect)
	htPath, err := a.htpasswdFilePath(acct, inst.ID)
	if err != nil {
		return PasswordProtectionStatus{Enabled: enabled, Realm: DefaultAuthRealm}
	}
	user, realm := readHTPasswdMetadata(htPath)
	if realm == "" {
		realm = DefaultAuthRealm
	}
	return PasswordProtectionStatus{
		Enabled:      enabled,
		Username:     user,
		Realm:        realm,
		HTPasswdPath: htPath,
	}
}

// SetPasswordProtection enables, updates, or disables HTTP Basic Authentication across Apache, LiteSpeed, OpenLiteSpeed, and Nginx.
func (a *Adapter) SetPasswordProtection(
	ctx context.Context,
	acct dausers.Account,
	inst store.InstanceRecord,
	enabled bool,
	authUser string,
	authPassword string,
	realm string,
) (PasswordProtectionStatus, error) {
	htPath, err := a.htpasswdFilePath(acct, inst.ID)
	if err != nil {
		return PasswordProtectionStatus{}, err
	}
	cleanRealm := sanitizeRealmLabel(realm)

	if !enabled {
		if err := a.SyncRules(ctx, acct, inst, map[string]bool{RulePasswordProtect: false}); err != nil {
			return PasswordProtectionStatus{}, err
		}
		_ = os.Remove(htPath)
		return PasswordProtectionStatus{
			Enabled: false,
			Realm:   cleanRealm,
		}, nil
	}

	user := strings.TrimSpace(authUser)
	existUser, existHash := readHTPasswdEntry(htPath)
	if user == "" {
		user = existUser
	}
	if err := config.ValidateIdentifier(user); err != nil || strings.ContainsRune(user, ':') {
		return PasswordProtectionStatus{}, fmt.Errorf("invalid HTTP Basic username %q", user)
	}

	var encodedHash string
	if strings.TrimSpace(authPassword) != "" {
		if len(authPassword) < 6 {
			return PasswordProtectionStatus{}, errors.New("HTTP Basic password must be at least 6 characters")
		}
		h, hErr := HashAPR1(authPassword, "")
		if hErr != nil {
			return PasswordProtectionStatus{}, hErr
		}
		encodedHash = h
	} else if existHash != "" && user == existUser {
		encodedHash = existHash
	} else {
		return PasswordProtectionStatus{}, errors.New("auth_password is required when enabling HTTP password protection")
	}

	htDir := filepath.Dir(htPath)
	if err := os.MkdirAll(htDir, 0o755); err != nil {
		return PasswordProtectionStatus{}, err
	}
	_ = chownNoFollow(htDir, acct.UID, acct.GID)

	body := fmt.Sprintf("# realm=%s\n%s:%s\n", cleanRealm, user, encodedHash)
	tmpPath := htPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(body), 0o644); err != nil {
		return PasswordProtectionStatus{}, err
	}
	_ = chownNoFollow(tmpPath, acct.UID, acct.GID)
	if err := os.Rename(tmpPath, htPath); err != nil {
		_ = os.Remove(tmpPath)
		return PasswordProtectionStatus{}, err
	}

	if err := a.SyncRules(ctx, acct, inst, map[string]bool{RulePasswordProtect: true}); err != nil {
		return PasswordProtectionStatus{}, err
	}

	return PasswordProtectionStatus{
		Enabled:      true,
		Username:     user,
		Realm:        cleanRealm,
		HTPasswdPath: htPath,
	}, nil
}

// VerifyHTTPBasicAuth validates HTTP Basic credentials against the instance's `.htpasswd` file.
func (a *Adapter) VerifyHTTPBasicAuth(acct dausers.Account, inst store.InstanceRecord, username, password string) bool {
	htPath, err := a.htpasswdFilePath(acct, inst.ID)
	if err != nil {
		return false
	}
	wantUser, wantHash := readHTPasswdEntry(htPath)
	if wantUser == "" || wantHash == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(username), []byte(wantUser)) != 1 {
		return false
	}
	return VerifyAPR1(password, wantHash)
}

func readHTPasswdMetadata(htPath string) (user string, realm string) {
	raw, err := os.ReadFile(htPath)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# realm=") {
			realm = strings.TrimPrefix(trimmed, "# realm=")
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if idx := strings.IndexByte(trimmed, ':'); idx > 0 {
			user = trimmed[:idx]
		}
	}
	return user, realm
}

func readHTPasswdEntry(htPath string) (user string, hash string) {
	raw, err := os.ReadFile(htPath)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if idx := strings.IndexByte(trimmed, ':'); idx > 0 {
			return trimmed[:idx], strings.TrimSpace(trimmed[idx+1:])
		}
	}
	return "", ""
}

func (a *Adapter) buildHTAccessPasswordBlock(acct dausers.Account, inst store.InstanceRecord) string {
	htPath, err := a.htpasswdFilePath(acct, inst.ID)
	if err != nil {
		return ""
	}
	_, realm := readHTPasswdMetadata(htPath)
	cleanRealm := sanitizeRealmLabel(realm)
	slashPath := filepath.ToSlash(htPath)
	return strings.Join([]string{
		`AuthType Basic`,
		fmt.Sprintf(`AuthName "%s"`, cleanRealm),
		fmt.Sprintf(`AuthUserFile "%s"`, slashPath),
		`Require valid-user`,
	}, "\n")
}

func (a *Adapter) buildNginxPasswordBlock(acct dausers.Account, inst store.InstanceRecord) string {
	htPath, err := a.htpasswdFilePath(acct, inst.ID)
	if err != nil {
		return ""
	}
	_, realm := readHTPasswdMetadata(htPath)
	cleanRealm := sanitizeRealmLabel(realm)
	slashPath := filepath.ToSlash(htPath)
	locPath := strings.TrimSuffix(inst.SubPath, "/") + "/"
	return fmt.Sprintf(
		"location ^~ %s {\n    auth_basic \"%s\";\n    auth_basic_user_file \"%s\";\n}",
		locPath,
		cleanRealm,
		slashPath,
	)
}
