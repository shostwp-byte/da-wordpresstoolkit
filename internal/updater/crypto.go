package updater

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	ErrInvalidSignature = errors.New("Ed25519 release signature verification failed")
	ErrChecksumMismatch = errors.New("SHA-256 release archive digest mismatch")
	ErrMissingChecksum  = errors.New("release asset missing from signed checksums.txt")
)

// GenerateKeyPairHex generates a new Ed25519 signing keypair encoded as lowercase hex strings.
// privHex is 128 hex chars (64-byte private key) and pubHex is 64 hex chars (32-byte public key).
func GenerateKeyPairHex() (privHex string, pubHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(priv), hex.EncodeToString(pub), nil
}

// ParsePublicKeyHex decodes a 32-byte Ed25519 public key from hex (or base64).
func ParsePublicKeyHex(raw string) (ed25519.PublicKey, error) {
	s := strings.TrimSpace(raw)
	if len(s) == ed25519.PublicKeySize*2 {
		b, err := hex.DecodeString(s)
		if err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	return nil, errors.New("invalid Ed25519 public key (expected 64-char hex or base64 32-byte key)")
}

// ParsePrivateKey decodes an Ed25519 private key from a 32-byte seed or 64-byte private key (hex or base64).
func ParsePrivateKey(raw string) (ed25519.PrivateKey, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty Ed25519 private key")
	}
	if b, err := hex.DecodeString(s); err == nil {
		switch len(b) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(b), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(b), nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		switch len(b) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(b), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(b), nil
		}
	}
	return nil, errors.New("invalid Ed25519 private key (expected 64-hex seed or 128-hex private key)")
}

// ParseSignatureBytes decodes a 64-byte Ed25519 signature from raw bytes, hex text, or base64 text.
func ParseSignatureBytes(raw []byte) ([]byte, error) {
	if len(raw) == ed25519.SignatureSize {
		out := make([]byte, ed25519.SignatureSize)
		copy(out, raw)
		return out, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if idx := strings.Fields(trimmed); len(idx) > 0 {
		trimmed = idx[0]
	}
	if len(trimmed) == ed25519.SignatureSize*2 {
		if b, err := hex.DecodeString(trimmed); err == nil && len(b) == ed25519.SignatureSize {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(b) == ed25519.SignatureSize {
		return b, nil
	}
	return nil, fmt.Errorf("%w: malformed signature format", ErrInvalidSignature)
}

// SignChecksumsDir computes SHA-256 digests for all regular release artifacts in dir,
// writes checksums.txt, signs checksums.txt with privKey into checksums.txt.sig, and self-verifies.
func SignChecksumsDir(dir string, privKey ed25519.PrivateKey) (string, string, map[string]string, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return "", "", nil, errors.New("invalid Ed25519 private key length")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", nil, err
	}

	var fileNames []string
	for _, ent := range entries {
		if ent.IsDir() || !ent.Type().IsRegular() {
			continue
		}
		name := ent.Name()
		if name == "checksums.txt" || name == "checksums.txt.sig" {
			continue
		}
		fileNames = append(fileNames, name)
	}
	if len(fileNames) == 0 {
		return "", "", nil, fmt.Errorf("no release artifacts found in %s", dir)
	}
	sort.Strings(fileNames)

	digests := make(map[string]string, len(fileNames))
	var buf bytes.Buffer
	for _, name := range fileNames {
		sum, hErr := sha256FileHex(filepath.Join(dir, name))
		if hErr != nil {
			return "", "", nil, hErr
		}
		digests[name] = sum
		fmt.Fprintf(&buf, "%s  %s\n", sum, name)
	}

	checksumsBytes := buf.Bytes()
	sig := ed25519.Sign(privKey, checksumsBytes)
	pubHex := hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	sigHex := hex.EncodeToString(sig) + "\n"

	if _, vErr := VerifyChecksumsSignature(checksumsBytes, []byte(sigHex), pubHex); vErr != nil {
		return "", "", nil, fmt.Errorf("internal self-verification failed: %w", vErr)
	}

	checksumsPath := filepath.Join(dir, "checksums.txt")
	sigPath := filepath.Join(dir, "checksums.txt.sig")
	if err := os.WriteFile(checksumsPath, checksumsBytes, 0o644); err != nil {
		return "", "", nil, err
	}
	if err := os.WriteFile(sigPath, []byte(sigHex), 0o644); err != nil {
		return "", "", nil, err
	}
	return checksumsPath, sigPath, digests, nil
}

// VerifyChecksumsSignature cryptographically verifies checksums.txt against checksums.txt.sig
// using pubKeyHex BEFORE parsing any asset SHA-256 entries.
func VerifyChecksumsSignature(checksumsBytes []byte, sigRaw []byte, pubKeyHex string) (map[string]string, error) {
	if len(checksumsBytes) == 0 || len(checksumsBytes) > 512*1024 {
		return nil, fmt.Errorf("%w: invalid checksums.txt size", ErrInvalidSignature)
	}
	pubKey, err := ParsePublicKeyHex(pubKeyHex)
	if err != nil {
		return nil, err
	}
	sigBytes, err := ParseSignatureBytes(sigRaw)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pubKey, checksumsBytes, sigBytes) {
		return nil, ErrInvalidSignature
	}

	digests := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(checksumsBytes))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("%w: malformed checksum line", ErrInvalidSignature)
		}
		hashHex := strings.ToLower(strings.TrimSpace(fields[0]))
		assetName := strings.TrimPrefix(strings.TrimSpace(fields[1]), "*")
		if len(hashHex) != sha256.Size*2 {
			return nil, fmt.Errorf("%w: invalid SHA-256 hex length for %s", ErrInvalidSignature, assetName)
		}
		if _, dErr := hex.DecodeString(hashHex); dErr != nil {
			return nil, fmt.Errorf("%w: non-hex SHA-256 digest for %s", ErrInvalidSignature, assetName)
		}
		if strings.ContainsAny(assetName, `/\`) || strings.Contains(assetName, "..") || assetName == "" {
			return nil, fmt.Errorf("%w: unsafe asset filename %q", ErrInvalidSignature, assetName)
		}
		digests[assetName] = hashHex
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(digests) == 0 {
		return nil, fmt.Errorf("%w: checksums.txt contains no asset entries", ErrInvalidSignature)
	}
	return digests, nil
}

func constantTimeHexEqual(a, b string) bool {
	ab, err1 := hex.DecodeString(strings.ToLower(strings.TrimSpace(a)))
	bb, err2 := hex.DecodeString(strings.ToLower(strings.TrimSpace(b)))
	if err1 != nil || err2 != nil || len(ab) != sha256.Size || len(bb) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

func sha256FileHex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
