package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Location identifies where a payload is injected.
type Location string

const (
	LocationQuery  Location = "query"
	LocationBody   Location = "body"
	LocationJSON   Location = "json"
	LocationCookie Location = "cookie"
	LocationHeader Location = "header"
)

// InjectionPoint describes a single user-controlled value in a request.
type InjectionPoint struct {
	Location Location `json:"location"`
	Name     string   `json:"name"`
	Original string   `json:"original"`
	Method   string   `json:"method"`
	// Path is used for nested JSON bodies, for example "user.profile.id".
	Path string `json:"path,omitempty"`
}

func (p InjectionPoint) Label() string {
	if p.Location == LocationJSON && p.Path != "" {
		return fmt.Sprintf("%s:%s", p.Location, p.Path)
	}
	return fmt.Sprintf("%s:%s", p.Location, p.Name)
}

// Boundary is the syntactic context that turns a SQL fragment into a valid
// statement for the target parameter.
type Boundary struct {
	Prefix string `json:"prefix"`
	Suffix string `json:"suffix"`
}

func (b Boundary) String() string {
	return fmt.Sprintf("prefix=%q suffix=%q", b.Prefix, b.Suffix)
}

// Session stores everything learned about a confirmed injection.
type Session struct {
	Target      string         `json:"target"`
	Method      string         `json:"method"`
	Point       InjectionPoint `json:"point"`
	DBMS        string         `json:"dbms"`
	DBMSVersion string         `json:"dbms_version,omitempty"`
	Technique   string         `json:"technique"`
	Boundary    Boundary       `json:"boundary"`
	Columns     int            `json:"columns,omitempty"`
	StringCol   int            `json:"string_column,omitempty"`
	Confidence  float64        `json:"confidence"`
	WAF         string         `json:"waf,omitempty"`
	BaselineLen int            `json:"baseline_length,omitempty"`
	BaselineMS  int64          `json:"baseline_ms,omitempty"`
}

// DiscoverInjectionPoints builds the list of injectable values from the
// target URL, request body, cookies and custom headers.
func DiscoverInjectionPoints(opts *Options) ([]InjectionPoint, error) {
	var points []InjectionPoint
	method := strings.ToUpper(strings.TrimSpace(opts.Method))
	if method == "" {
		method = http.MethodGet
	}
	if opts.Data != "" && method == http.MethodGet {
		method = http.MethodPost
	}

	u, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	for name, values := range u.Query() {
		original := ""
		if len(values) > 0 {
			original = values[0]
		}
		points = append(points, InjectionPoint{
			Location: LocationQuery,
			Name:     name,
			Original: original,
			Method:   method,
		})
	}

	if opts.Data != "" {
		if looksLikeJSON(opts.Data) {
			paths, err := flattenJSONPaths(opts.Data)
			if err == nil {
				for _, p := range paths {
					points = append(points, InjectionPoint{
						Location: LocationJSON,
						Name:     p.name,
						Path:     p.path,
						Original: p.value,
						Method:   method,
					})
				}
			}
		} else if form, err := url.ParseQuery(opts.Data); err == nil {
			for name, values := range form {
				original := ""
				if len(values) > 0 {
					original = values[0]
				}
				points = append(points, InjectionPoint{
					Location: LocationBody,
					Name:     name,
					Original: original,
					Method:   method,
				})
			}
		}
	}

	if opts.Cookie != "" {
		for _, part := range strings.Split(opts.Cookie, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			pair := strings.SplitN(part, "=", 2)
			if len(pair) != 2 {
				continue
			}
			points = append(points, InjectionPoint{
				Location: LocationCookie,
				Name:     strings.TrimSpace(pair[0]),
				Original: pair[1],
				Method:   method,
			})
		}
	}

	for _, raw := range opts.Header {
		pair := strings.SplitN(raw, ":", 2)
		if len(pair) != 2 {
			continue
		}
		points = append(points, InjectionPoint{
			Location: LocationHeader,
			Name:     strings.TrimSpace(pair[0]),
			Original: strings.TrimSpace(pair[1]),
			Method:   method,
		})
	}

	points = filterPoints(points, opts)
	if len(points) == 0 {
		return nil, fmt.Errorf("no injectable parameters found; pass a query string, --data, --cookie or --header")
	}
	return points, nil
}

func filterPoints(points []InjectionPoint, opts *Options) []InjectionPoint {
	include := splitCSV(opts.Param)
	exclude := splitCSV(opts.SkipParam)
	level := opts.Level
	if level <= 0 {
		level = 1
	}

	var out []InjectionPoint
	for _, p := range points {
		if len(include) > 0 && !matchesAny(p, include) {
			continue
		}
		if matchesAny(p, exclude) {
			continue
		}
		switch p.Location {
		case LocationCookie:
			if level < 2 {
				continue
			}
		case LocationHeader:
			if level < 3 {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

func matchesAny(p InjectionPoint, names []string) bool {
	for _, n := range names {
		if strings.EqualFold(n, p.Name) || strings.EqualFold(n, p.Path) {
			return true
		}
	}
	return false
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func looksLikeJSON(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

type jsonPath struct {
	path  string
	name  string
	value string
}

func flattenJSONPaths(raw string) ([]jsonPath, error) {
	var root interface{}
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return nil, err
	}
	var out []jsonPath
	var walk func(prefix string, value interface{})
	walk = func(prefix string, value interface{}) {
		switch v := value.(type) {
		case map[string]interface{}:
			for k, child := range v {
				path := k
				if prefix != "" {
					path = prefix + "." + k
				}
				walk(path, child)
			}
		case []interface{}:
			for i, child := range v {
				path := fmt.Sprintf("%s[%d]", prefix, i)
				walk(path, child)
			}
		case string:
			out = append(out, jsonPath{path: prefix, name: lastJSONKey(prefix), value: v})
		case float64, bool, nil:
			out = append(out, jsonPath{path: prefix, name: lastJSONKey(prefix), value: fmt.Sprintf("%v", v)})
		}
	}
	walk("", root)
	return out, nil
}

func lastJSONKey(path string) string {
	path = strings.TrimSuffix(path, "]")
	if i := strings.LastIndex(path, "["); i >= 0 {
		path = path[:i]
	}
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}

func setJSONPath(raw string, path string, value string) (string, error) {
	var root interface{}
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return "", err
	}
	segments := splitJSONPath(path)
	if len(segments) == 0 {
		return "", fmt.Errorf("empty JSON path")
	}
	current := root
	for i, seg := range segments {
		last := i == len(segments)-1
		switch node := current.(type) {
		case map[string]interface{}:
			child, ok := node[seg.key]
			if !ok {
				return "", fmt.Errorf("JSON path not found: %s", path)
			}
			if seg.index >= 0 {
				arr, ok := child.([]interface{})
				if !ok || seg.index >= len(arr) {
					return "", fmt.Errorf("JSON index out of range: %s", path)
				}
				if last {
					arr[seg.index] = value
				} else {
					current = arr[seg.index]
				}
			} else if last {
				node[seg.key] = value
			} else {
				current = child
			}
		case []interface{}:
			if seg.index < 0 || seg.index >= len(node) {
				return "", fmt.Errorf("JSON index out of range: %s", path)
			}
			if last {
				node[seg.index] = value
			} else {
				current = node[seg.index]
			}
		default:
			return "", fmt.Errorf("JSON path is not traversable: %s", path)
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

type jsonSegment struct {
	key   string
	index int
}

func splitJSONPath(path string) []jsonSegment {
	var segments []jsonSegment
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			continue
		}
		key := part
		index := -1
		if i := strings.Index(part, "["); i >= 0 {
			key = part[:i]
			idx := strings.TrimSuffix(part[i+1:], "]")
			if n, err := strconv.Atoi(idx); err == nil {
				index = n
			}
		}
		segments = append(segments, jsonSegment{key: key, index: index})
	}
	return segments
}
