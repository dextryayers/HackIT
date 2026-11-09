package main

// Expression-engine for the `dsl` matcher type, built on expr-lang/expr.
// The environment mirrors the subset of nuclei's DSL used by the template
// library: response scalars as float64/string values, plus the common
// helper functions (contains/regex/len/to_number/…). Expressions compile
// once per evaluation; failures fall back to the legacy atom evaluator in
// matcher.go so nothing that used to match changes behavior.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

func toStr(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func toFloat(v interface{}) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f
	default:
		f, _ := strconv.ParseFloat(toStr(t), 64)
		return f
	}
}

// flatten needles: each argument may be a single needle or a
// pipe-separated list (`contains_any(body, 'a|b')`).
func flattenNeedles(args []interface{}) []string {
	var out []string
	for _, a := range args {
		for _, part := range strings.Split(toStr(a), "|") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func headerValue(allHeaders, name string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ":"))
	for _, line := range strings.Split(allHeaders, "\n") {
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line[:idx])) == name {
			return strings.TrimSpace(line[idx+1:])
		}
	}
	return ""
}

func buildDSLEnv(resp *ResponseInfo) map[string]interface{} {
	body := resp.Body
	headers := resp.Headers

	contains := func(hay, needle interface{}) bool {
		return strings.Contains(toStr(hay), toStr(needle))
	}
	containsAny := func(hay interface{}, needles ...interface{}) bool {
		h := toStr(hay)
		for _, n := range flattenNeedles(needles) {
			if strings.Contains(h, n) {
				return true
			}
		}
		return false
	}
	containsAll := func(hay interface{}, needles ...interface{}) bool {
		h := toStr(hay)
		flat := flattenNeedles(needles)
		if len(flat) == 0 {
			return false
		}
		for _, n := range flat {
			if !strings.Contains(h, n) {
				return false
			}
		}
		return true
	}
	regexFn := func(hay, pattern interface{}) bool {
		re, err := getRegex(toStr(pattern))
		return err == nil && re.MatchString(toStr(hay))
	}
	startsWith := func(hay, prefix interface{}) bool {
		return strings.HasPrefix(toStr(hay), toStr(prefix))
	}
	endsWith := func(hay, suffix interface{}) bool {
		return strings.HasSuffix(toStr(hay), toStr(suffix))
	}
	lenFn := func(v interface{}) int {
		switch t := v.(type) {
		case string:
			return len(t)
		case []interface{}:
			return len(t)
		case map[string]interface{}:
			return len(t)
		default:
			return len(toStr(t))
		}
	}
	toNumber := toFloat
	toString := toStr
	toLower := func(s interface{}) string { return strings.ToLower(toStr(s)) }
	toUpper := func(s interface{}) string { return strings.ToUpper(toStr(s)) }
	concat := func(parts ...interface{}) string {
		var b strings.Builder
		for _, p := range parts {
			b.WriteString(toStr(p))
		}
		return b.String()
	}
	hexDecode := func(s interface{}) string {
		cleaned := strings.NewReplacer(" ", "", "0x", "", "\\x", "").Replace(toStr(s))
		b, err := hex.DecodeString(cleaned)
		if err != nil {
			return ""
		}
		return string(b)
	}
	base64Decode := func(s interface{}) string {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(toStr(s)))
		if err != nil {
			return ""
		}
		return string(b)
	}
	urlDecode := func(s interface{}) string {
		dec, err := url.QueryUnescape(toStr(s))
		if err != nil {
			return toStr(s)
		}
		return dec
	}
	md5Fn := func(s interface{}) string { h := md5.Sum([]byte(toStr(s))); return hex.EncodeToString(h[:]) }
	sha1Fn := func(s interface{}) string { h := sha1.Sum([]byte(toStr(s))); return hex.EncodeToString(h[:]) }
	sha256Fn := func(s interface{}) string { h := sha256.Sum256([]byte(toStr(s))); return hex.EncodeToString(h[:]) }
	headerFn := func(name interface{}) string { return headerValue(headers, toStr(name)) }

	return map[string]interface{}{
		"status_code":    float64(resp.StatusCode),
		"content_length": float64(resp.BodyLen),
		"body_size":      float64(resp.BodyLen),
		"body_length":    float64(resp.BodyLen),
		"duration":       resp.Duration.Seconds(),
		"duration_ms":    float64(resp.Duration.Milliseconds()),
		"body":           body,
		"header":         headers,
		"all_headers":    headers,
		"content_type":   resp.ContentType,

		// "contains" is an infix operator in expr-lang; the function form
		// lives under __contains and expressions are rewritten by
		// normalizeDSLExpr before compilation.
		"__contains":    contains,
		"contains_any":  containsAny,
		"contains_all":  containsAll,
		"regex":         regexFn,
		"starts_with":   startsWith,
		"ends_with":     endsWith,
		"len":           lenFn,
		"to_number":     toNumber,
		"to_string":     toString,
		"to_lower":      toLower,
		"to_upper":      toUpper,
		"lower":         toLower,
		"upper":         toUpper,
		"concat":        concat,
		"hex_decode":    hexDecode,
		"base64_decode": base64Decode,
		"url_decode":    urlDecode,
		"md5":           md5Fn,
		"sha1":          sha1Fn,
		"sha256":        sha256Fn,
		"header_value":  headerFn,
	}
}

var containsCallRe = regexp.MustCompile(`\bcontains\s*\(`)

// normalizeDSLExpr rewrites nucleus-style `contains(...)` calls into
// `__contains(...)` so they don't collide with expr-lang's infix
// `contains` operator. Rewrites apply only outside quoted strings.
func normalizeDSLExpr(e string) string {
	var b, seg strings.Builder
	flush := func() {
		b.WriteString(containsCallRe.ReplaceAllString(seg.String(), "__contains("))
		seg.Reset()
	}
	runes := []byte(e)
	i := 0
	for i < len(runes) {
		c := runes[i]
		switch c {
		case '\'', '"':
			quote := c
			flush()
			b.WriteByte(c)
			i++
			for i < len(runes) {
				cc := runes[i]
				b.WriteByte(cc)
				if cc == '\\' && i+1 < len(runes) {
					i++
					b.WriteByte(runes[i])
					i++
					continue
				}
				if cc == quote {
					i++
					break
				}
				i++
			}
			continue
		}
		seg.WriteByte(c)
		i++
	}
	flush()
	return b.String()
}

type compiledDSL struct {
	program *vm.Program
	err     error
}

var dslCache sync.Map // expression -> compiledDSL
var dslCacheCount int32

func compileDSL(expression string, asBool bool) (*vm.Program, error) {
	normalized := normalizeDSLExpr(expression)
	variant := "v"
	if asBool {
		variant = "b"
	}
	key := normalized + "\x00" + variant
	if cached, ok := dslCache.Load(key); ok {
		c := cached.(compiledDSL)
		return c.program, c.err
	}
	var program *vm.Program
	var err error
	opts := []expr.Option{
		expr.Env(buildDSLEnv(&ResponseInfo{})),
		expr.DisableAllBuiltins(),
	}
	if asBool {
		opts = append(opts, expr.AsBool())
	}
	program, err = expr.Compile(normalized, opts...)
	if atomic.LoadInt32(&dslCacheCount) < 2000 {
		dslCache.Store(key, compiledDSL{program, err})
		atomic.AddInt32(&dslCacheCount, 1)
	}
	return program, err
}

// evalDSLBool evaluates an expression that must yield a boolean.
func evalDSLBool(expression string, resp *ResponseInfo) (bool, error) {
	program, err := compileDSL(expression, true)
	if err != nil {
		return false, err
	}
	env := buildDSLEnv(resp)
	out, err := expr.Run(program, env)
	if err != nil {
		return false, err
	}
	b, ok := out.(bool)
	if !ok {
		// tolerate truthy scalars (e.g. regex(...) as number)
		switch t := out.(type) {
		case string:
			return t != "", nil
		case float64:
			return t != 0, nil
		}
		return false, fmt.Errorf("dsl expression did not yield bool")
	}
	return b, nil
}

// evalDSLValue evaluates an expression and stringifies the result
// (used by `type: dsl` extractors).
func evalDSLValue(expression string, resp *ResponseInfo) (string, error) {
	program, err := compileDSL(expression, false)
	if err != nil {
		return "", err
	}
	out, err := expr.Run(program, buildDSLEnv(resp))
	if err != nil {
		return "", err
	}
	return toStr(out), nil
}
