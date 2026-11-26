// Package importer turns user input (WireGuard/AmneziaWG .conf, OpenVPN
// .ovpn, share links, base64 subscription bodies) into Moley profiles.
//
// Rule for every parser: warnings and errors may name directives, keys,
// schemes, line numbers and file names, but never values that could be
// secrets (keys, passwords, UUIDs, certificates). Errors from url.Parse,
// strconv and base64 echo their input, so they are never wrapped into
// messages; parsers return their own fixed texts instead.
package importer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"moley/internal/model"
)

type Result struct {
	Profiles []model.Profile
	Warnings []string // e.g. unknown/ignored directives, never silently dropped
}

// Options carries secrets the input itself doesn't hold.
type Options struct {
	// KeyPassword decrypts an encrypted private key (OpenVPN <key>). The
	// decrypted key is what gets stored (sealed at rest by the daemon).
	KeyPassword string
}

// Parse detects the format of data and returns profiles. name is a hint (file
// name or "" for pasted text) used for IDs and Source.
func Parse(name string, data []byte) (Result, error) { return ParseWith(name, data, Options{}) }

// ParseWith is Parse with secrets supplied out of band.
func ParseWith(name string, data []byte, opts Options) (Result, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // UTF-8 BOM
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	if strings.TrimSpace(text) == "" {
		return Result{}, errors.New("input is empty")
	}
	base := baseName(name)

	var res Result
	var err error
	switch detect(text) {
	case formatWireGuard:
		res, err = parseWireGuard(text)
		setFileProvenance(&res, base)
	case formatOpenVPN:
		res, err = parseOpenVPN(text, opts)
		setFileProvenance(&res, base)
	case formatClash:
		return Result{}, errors.New("Clash/mihomo YAML subscriptions are not supported yet")
	case formatSingBox:
		return Result{}, errors.New("sing-box JSON configs are not supported yet")
	case formatLinks:
		res, err = parseLinks(text)
	default:
		if decoded, ok := decodeBase64(text); ok && detect(decoded) == formatLinks {
			res, err = parseLinks(decoded)
		} else {
			return Result{}, errors.New("unrecognized input: expected a WireGuard or OpenVPN config, share links, or a base64 subscription")
		}
	}
	if err != nil {
		return Result{}, err
	}
	assignIDs(res.Profiles)
	return res, nil
}

type format int

const (
	formatUnknown format = iota
	formatWireGuard
	formatOpenVPN
	formatClash
	formatSingBox
	formatLinks
)

func detect(text string) format {
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "{") {
		var top map[string]json.RawMessage
		if json.Unmarshal([]byte(trimmed), &top) == nil {
			if _, ok := top["outbounds"]; ok {
				return formatSingBox
			}
			if _, ok := top["endpoints"]; ok {
				return formatSingBox
			}
		}
		return formatUnknown
	}
	hasLink := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.EqualFold(line, "[interface]") {
			return formatWireGuard
		}
		if strings.HasPrefix(line, "proxies:") {
			return formatClash
		}
		if isOpenVPNMarker(line) {
			return formatOpenVPN
		}
		if strings.Contains(line, "://") {
			hasLink = true
		}
	}
	if hasLink {
		return formatLinks
	}
	return formatUnknown
}

// isOpenVPNMarker reports lines that only appear in .ovpn files.
func isOpenVPNMarker(line string) bool {
	if line == "<ca>" || line == "client" || line == "tls-client" {
		return true
	}
	first, _, _ := strings.Cut(line, " ")
	switch first {
	case "remote", "dev", "proto":
		return !strings.Contains(line, "://")
	}
	return false
}

// decodeBase64 accepts std or URL alphabets, padded or not, with line breaks.
func decodeBase64(s string) (string, bool) {
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return "", false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), true
		}
	}
	return "", false
}

var directiveName = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// describeKey returns a quoted directive/key name for a warning, or a generic
// placeholder when the token does not look like a name. A stray line of key
// material would otherwise be echoed as an "unknown directive".
func describeKey(s string) string {
	if len(s) <= 32 && directiveName.MatchString(s) {
		return strconv.Quote(s)
	}
	return "(unreadable name)"
}

func baseName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// setFileProvenance uses the file stem as the ID hint and records the source.
// Pasted text (no name) falls back to the kind for the ID.
func setFileProvenance(res *Result, base string) {
	stem := base
	if i := strings.LastIndex(stem, "."); i > 0 {
		stem = stem[:i]
	}
	for i := range res.Profiles {
		p := &res.Profiles[i]
		p.ID = stem
		if base != "" {
			p.Source = "file:" + base
		} else {
			p.Source = "paste"
		}
	}
}

const maxIDLen = 48

var nonIDChars = regexp.MustCompile(`[^a-z0-9_-]+`)
var dashRuns = regexp.MustCompile(`-{2,}`)

// slugify maps a free-form name onto model's ID alphabet. It returns "" when
// nothing usable is left (e.g. a name made only of emoji).
func slugify(s string) string {
	s = nonIDChars.ReplaceAllString(strings.ToLower(s), "-")
	s = dashRuns.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > maxIDLen {
		s = strings.TrimRight(s[:maxIDLen], "-")
	}
	if s != "" && !isAlnum(s[0]) {
		s = strings.TrimRight(truncate("p-"+s, maxIDLen), "-")
	}
	return s
}

func isAlnum(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// assignIDs turns the name hints parsers left in Profile.ID into valid,
// unique IDs: slugified, falling back to the kind, then "-2", "-3"… on clashes.
func assignIDs(profiles []model.Profile) {
	used := map[string]bool{}
	for i := range profiles {
		base := slugify(profiles[i].ID)
		if base == "" {
			base = profiles[i].Kind
		}
		id := base
		for n := 2; used[id]; n++ {
			suffix := "-" + strconv.Itoa(n)
			id = strings.TrimRight(truncate(base, maxIDLen-len(suffix)), "-") + suffix
		}
		used[id] = true
		profiles[i].ID = id
	}
}

// marshalConfig encodes sing-box options as a profile Config: no "type" or
// "tag" (the compiler sets those), and no empty "server", which embedded
// option.ServerOptions always emits even when a "servers" list is used.
func marshalConfig(v any) (json.RawMessage, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	delete(obj, "type")
	delete(obj, "tag")
	if string(obj["server"]) == `""` {
		delete(obj, "server")
	}
	return json.Marshal(obj)
}
