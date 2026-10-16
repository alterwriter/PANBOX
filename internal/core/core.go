package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
)

var Severities = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func ID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func Secret(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + hex.EncodeToString(b)
}

func Hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func Fingerprint(module, rule, path, context string) string {
	path = strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	context = strings.Join(strings.Fields(context), " ")
	return Hash(strings.ToLower(module) + "\x00" + rule + "\x00" + path + "\x00" + context)
}

func ValidSeverity(s string) bool { _, ok := Severities[s]; return ok }

func Gate(status string, severities []string) (bool, error) {
	if status != "complete" {
		return false, errors.New("scan incomplete")
	}
	for _, s := range severities {
		if Severities[s] >= Severities["high"] {
			return false, nil
		}
	}
	return true, nil
}

func Delta(baseAvailable, inBase bool) string {
	if !baseAvailable {
		return "baseline_unknown"
	}
	if inBase {
		return "existing"
	}
	return "new"
}
