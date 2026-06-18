package main

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ============================================================================
// JS String Literal Extraction Engine — Modern JS Edition
// Extracts ALL string literals from JS source with awareness of modern syntax:
//   - Brace-depth JSON config extraction
//   - Dynamic import() URLs
//   - Template literal interpolation decomposition
//   - Import attributes/assertions
//   - Worker/ServiceWorker/WASM patterns
//   - CSS-in-JS tagged template awareness
//   - Concatenation with ||, &&, ??, ternary
// ============================================================================

var (
	// Comment stripping
	singleLineComment = regexp.MustCompile(`//[^\n]*`)
	multiLineComment  = regexp.MustCompile(`/\*[\s\S]*?\*/`)

	// String literal extraction
	singleQuotedStr = regexp.MustCompile(`'([^'\\]*(?:\\.[^'\\]*)*)'`)
	doubleQuotedStr = regexp.MustCompile(`"([^"\\]*(?:\\.[^"\\]*)*)"`)
	backtickStr     = regexp.MustCompile("`([^`\\\\]*(?:\\\\.[^`\\\\]*)*)`")

	// URL-like patterns within strings
	urlInStr     = regexp.MustCompile(`(https?://[^\s"'\` + "`" + `,;)]+)`)
	pathInStr    = regexp.MustCompile(`(/\w[\w\-./]*(?:\.[a-zA-Z]{2,})?(?:[?#][^\s"'\` + "`" + `,;)]*)?)`)
	apiPathInStr = regexp.MustCompile(`(/\w[\w\-./]*(?:api|graphql|rest|v\d|auth|oauth|token|admin|webhook|hook|callback|proxy|upload|download|ws|socket)[\w\-./]*)`)

	// Concatenation-aware URL reconstruction
	// Matches: "https://api.example.com/" + rest or "/api/v2/" + path
	concatLeftAbsolute = regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `]+)["'\` + "`" + `]\s*\+`)
	concatLeftRelative = regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `]+/)["'\` + "`" + `]\s*\+`)
	concatLeftKeyword  = regexp.MustCompile(`["'\` + "`" + `]([^"'\` + "`" + `]{4,}(?:api|graphql|rest|s3|cdn|auth|token|admin|service|host|url|base|proxy|ws|socket|endpoint|server|domain|bucket|origin|prefix|path|route))["'\` + "`" + `]\s*\+`)
	concatRight        = regexp.MustCompile(`\+\s*["'\` + "`" + `]([^"'\` + "`" + `]{4,}(?:api|graphql|rest|v\d|auth|oauth|token|admin|webhook|hook|callback|proxy|upload|download|endpoint|path|route|key|id|secret))["'\` + "`" + `]`)

	// JSON object field extraction (key: "value" in object literals)
	jsonFieldStr = regexp.MustCompile(`["'\` + "`" + `]?(\w+)["'\` + "`" + `]?\s*:\s*["'\` + "`" + `]([^"'\` + "`" + `\n]{3,})["'\` + "`" + `]`)

	// URL field names commonly containing API endpoints
	urlFieldNames = regexp.MustCompile(`(?i)^(?:url|uri|href|src|endpoint|api_url|api_endpoint|base_url|base|host|origin|target|redirect|callback|webhook|proxy|redirect_uri|return_url|postback|notify_url|service_url|server_url|upload_url|download_url|icon|image|avatar|logo|cover|thumbnail|preview|asset|manifest|data_url|action|form_action|link|self|next|prev|first|last|related)$`)

	// ── Modern JS patterns ──

	// Dynamic import(): import('./module.js'), import('https://cdn.example.com/lib.js')
	dynamicImportPat = regexp.MustCompile(`import\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`)

	// import.meta.url
	importMetaURL = regexp.MustCompile(`import\.meta\.url`)

	// new Worker() / new SharedWorker()
	workerPat  = regexp.MustCompile(`new\s+(?:Worker|SharedWorker)\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	swRegisterPat = regexp.MustCompile(`(?:navigator\.serviceWorker\.register|self\s*\.\s*registration)\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)

	// WebAssembly.instantiateStreaming('/app.wasm')
	wasmPat = regexp.MustCompile(`(?:WebAssembly|Wasm)\s*\.\s*(?:instantiateStreaming|compileStreaming|instantiate|compile)\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)

	// CSS-in-JS tagged template literals: css`...`, styled.div`...`, injectGlobal`...`, createGlobalStyle`...`
	// Matches the tag name before a backtick template — we detect to avoid false CSS positives
	cssTaggedTemplate = regexp.MustCompile(`(?i)(?:(?:css|styled|injectGlobal|createGlobalStyle|keyframes|createStyles|makeStyles|styles|useStyles|sx|tw|cx|clsx|classnames|emotion|stitches|linaria|griffel|astroturf|macaron|style9|fela|glamor|aphrodite|cxs|goober|styletron|vueStyled|vueStyle|reactNative)\s*(?:\.\w+)*\s*` + "``" + `)`)

	// Import assertion / attribute: import json from './data.json' assert { type: 'json' }
	importAssertPat = regexp.MustCompile(`import\s+\w+\s+from\s+["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*(?:assert|with)\s*\{`)

	// Dynamic import with assertion / attribute: import('./data.json', { assert: { type: 'json' } })
	dynamicImportAssertPat = regexp.MustCompile(`import\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*,\s*\{[^}]*?(?:assert|with)\s*:`)

	// ESM export from: export { default } from './module.js'
	exportFromPat = regexp.MustCompile(`export\s+(?:\{[^}]*\}|\*\s+as\s+\w+|\w+)?\s*from\s+["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)

	// Webpack/ESBuild/Rollup dynamic chunk: import(/* webpackChunkName: "..." */ './module.js')
	webpackDynamicImp = regexp.MustCompile(`import\s*\(\s*/\*[\s\S]*?\*/\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`)

	// CSS url() references in CSS-in-JS: url('/images/foo.png')
	cssURLRef = regexp.MustCompile(`(?i)url\s*\(\s*["'\` + "`" + `]?([^"'\` + "`" + `\)]+)["'\` + "`" + `]?\s*\)`)

	// @import in CSS or CSS-in-JS: @import url('./reset.css')
	cssImportRef = regexp.MustCompile(`(?i)@import\s+(?:url\s*\()?\s*["'\` + "`" + `]([^"'\` + "`" + `\)]+)["'\` + "`" + `]?\s*(?:\))?`)

	// Template literal interpolation decomposition:
	// Matches static parts between ${} interpolations
	// e.g., `https://api.${domain}.com/v2/${endpoint}` -> "https://api.", ".com/v2/", "" -> reconstruct: "https://api..com/v2/"
	interpolationSplitPat = regexp.MustCompile("([^$]*(?:\\$\\{[^}]+\\}[^$]*)*)")

	// Cross-origin / postMessage target origin patterns
	postMessageOriginPat = regexp.MustCompile(`(?:postMessage|sendMessage)\s*\(\s*[^,]+,\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)

	// window.open(url, ...)
	windowOpenPat = regexp.MustCompile(`window\.open\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)

	// location.assign / location.replace / location.href
	locationAssignPat = regexp.MustCompile(`location\s*\.\s*(?:assign|replace|href)\s*(?:=\s*["'\` + "`" + `]|\s*\(\s*["'\` + "`" + `])\s*([^"'\` + "`" + `\)]+)["'\` + "`" + `]`)

	// Next.js router.push, router.replace
	routerPushPat = regexp.MustCompile(`router\s*\.\s*(?:push|replace)\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `\)]+)["'\` + "`" + `]`)

	// Angular Router: this.router.navigate(['/path'])
	angularRouterPat = regexp.MustCompile(`router\s*\.\s*navigate\s*\(\s*\[["'\` + "`" + `]([^"'\` + "`" + `\]\)]+)["'\` + "`" + `]`)

	// Vue Router: this.$router.push('/path'), router.push({ path: '/path' })
	vueRouterPushPat = regexp.MustCompile(`\$?router\s*\.\s*(?:push|replace)\s*\(\s*\{[^}]*?(?:path|name)\s*:\s*["'\` + "`" + `]([^"'\` + "`" + `}]+)["'\` + "`" + `]`)

	// SvelteKit load: export const load = ({ fetch }) => { ... }
	svelteKitLoadPat = regexp.MustCompile(`export\s+(?:const|function|async\s+function)\s+load\s*[=\(]`)
)

// ExtractedString represents a discovered string value from JS analysis
type ExtractedString struct {
	Value   string `json:"value"`
	Context string `json:"context"`
	IsURL   bool   `json:"is_url"`
	IsPath  bool   `json:"is_path"`
}

// stripJSComments removes comments from JS code with proper string/comment awareness.
// Simple regex-based stripping destroys URLs (https:// contains //) and strings
// that happen to contain // or /* */ sequences.
func stripJSComments(code string) string {
	var out strings.Builder
	out.Grow(len(code))
	i := 0
	for i < len(code) {
		// Single-line comment
		if code[i] == '/' && i+1 < len(code) && code[i+1] == '/' {
			i += 2
			for i < len(code) && code[i] != '\n' {
				i++
			}
			continue
		}
		// Multi-line comment
		if code[i] == '/' && i+1 < len(code) && code[i+1] == '*' {
			i += 2
			for i+1 < len(code) && !(code[i] == '*' && code[i+1] == '/') {
				i++
			}
			i += 2 // skip */
			continue
		}
		// String literals — pass through unchanged
		if code[i] == '\'' || code[i] == '"' {
			quote := code[i]
			out.WriteByte(quote)
			i++
			for i < len(code) {
				if code[i] == '\\' {
					out.WriteByte(code[i])
					i++
					if i < len(code) {
						out.WriteByte(code[i])
						i++
					}
					continue
				}
				if code[i] == quote {
					out.WriteByte(quote)
					i++
					break
				}
				if code[i] == '\n' {
					break
				}
				out.WriteByte(code[i])
				i++
			}
			continue
		}
		// Template literals (backtick) — pass through with interpolation awareness
		if code[i] == '`' {
			out.WriteByte('`')
			i++
			depth := 0
			for i < len(code) {
				if code[i] == '\\' {
					out.WriteByte(code[i])
					i++
					if i < len(code) {
						out.WriteByte(code[i])
						i++
					}
					continue
				}
				if code[i] == '`' && depth == 0 {
					out.WriteByte('`')
					i++
					break
				}
				if code[i] == '$' && i+1 < len(code) && code[i+1] == '{' {
					depth++
				}
				if code[i] == '}' && depth > 0 {
					depth--
				}
				out.WriteByte(code[i])
				i++
			}
			continue
		}
		out.WriteByte(code[i])
		i++
	}
	return out.String()
}

// extractAllStrings extracts every string literal from JS source code
func extractAllStrings(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)

	addStr := func(val, ctx string) {
		val = strings.TrimSpace(val)
		if val == "" || seen[val] {
			return
		}
		if len(val) < 3 {
			return
		}
		seen[val] = true
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		isPath := strings.HasPrefix(val, "/")
		results = append(results, ExtractedString{
			Value:   val,
			Context: ctx,
			IsURL:   isURL,
			IsPath:  isPath,
		})
	}

	// Single-quoted strings
	for _, m := range singleQuotedStr.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addStr(m[1], "single")
		}
	}

	// Double-quoted strings
	for _, m := range doubleQuotedStr.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addStr(m[1], "double")
		}
	}

	// Template literals (backtick) - only non-interpolated
	for _, m := range backtickStr.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			val := m[1]
			if strings.Contains(val, "${") {
				continue
			}
			addStr(val, "template")
		}
	}

	// JSON field values that look like URLs/endpoints
	for _, m := range jsonFieldStr.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 3 {
			fieldName := m[1]
			fieldVal := m[2]
			if urlFieldNames.MatchString(fieldName) {
				addStr(fieldVal, "json_field")
			}
		}
	}

	// URL-like patterns from template literals with interpolation
	templateParts := backtickStr.FindAllString(cleaned, -1)
	for _, t := range templateParts {
		for _, m := range urlInStr.FindAllStringSubmatch(t, -1) {
			if len(m) >= 2 {
				addStr(m[1], "template_url")
			}
		}
		for _, m := range apiPathInStr.FindAllStringSubmatch(t, -1) {
			if len(m) >= 2 {
				addStr(m[1], "template_path")
			}
		}
	}

	return results
}

// extractModernJSModuleURLs extracts import/export module URLs from modern JS
func extractModernJSModuleURLs(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)

	addResolved := func(val, ctx string) {
		val = strings.Trim(val, "'\"`")
		val = strings.TrimSpace(val)
		if val == "" || seen[val] {
			return
		}
		seen[val] = true
		if len(val) < 3 {
			return
		}
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		isPath := strings.HasPrefix(val, "/") || strings.HasPrefix(val, "./") || strings.HasPrefix(val, "../")
		results = append(results, ExtractedString{
			Value:   val,
			Context: ctx,
			IsURL:   isURL,
			IsPath:  isPath,
		})
	}

	// Dynamic import(): import('./module.js')
	for _, m := range dynamicImportPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "dynamic_import")
		}
	}

	// Dynamic import with webpack comments: import(/* webpackChunkName: "..." */ './module.js')
	for _, m := range webpackDynamicImp.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "webpack_import")
		}
	}

	// Import assertion: import x from './data.json' assert { type: 'json' }
	for _, m := range importAssertPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "import_assert")
		}
	}

	// Dynamic import with assertion
	for _, m := range dynamicImportAssertPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "dynamic_import_assert")
		}
	}

	// ESM export from
	for _, m := range exportFromPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "export_from")
		}
	}

	// import.meta.url awareness (boolean — marks file as ESM)
	importMetaURL.FindAllString(cleaned, -1)

	return results
}

// extractTemplateLiteralInterpolations decomposes ${} templates and extracts
// static prefix/suffix parts for URL reconstruction
// e.g., `https://api.${domain}.com/v2/${path}` → "https://api..com/v2/" (gaps where ${} was)
func extractTemplateLiteralInterpolations(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)

	templateParts := backtickStr.FindAllString(cleaned, -1)
	for _, t := range templateParts {
		// Find all ${...} interpolations
		interpRe := regexp.MustCompile(`\$\{[^}]+\}`)
		// Replace ${...} with a placeholder and check both prefix and suffix
		parts := interpRe.Split(t, -1)
		if len(parts) < 2 {
			continue
		}

		// Reconstruct by joining parts (removing interpolation gaps)
		reconstructed := strings.Join(parts, "")
		reconstructed = strings.Trim(reconstructed, "` \t\n\r")

		if reconstructed == "" || seen[reconstructed] || len(reconstructed) < 5 {
			continue
		}
		seen[reconstructed] = true

		isURL := strings.HasPrefix(reconstructed, "http://") || strings.HasPrefix(reconstructed, "https://") || strings.HasPrefix(reconstructed, "//")
		isPath := strings.HasPrefix(reconstructed, "/")
		if isURL || isPath {
			results = append(results, ExtractedString{
				Value:   reconstructed,
				Context: "template_reconstructed",
				IsURL:   isURL,
				IsPath:  isPath,
			})
		}

		// Also extract individual parts that are URL-like
		for _, part := range parts {
			part = strings.Trim(part, "` \t\n\r")
			if part == "" || len(part) < 5 {
				continue
			}
			pIsURL := strings.HasPrefix(part, "http://") || strings.HasPrefix(part, "https://") || strings.HasPrefix(part, "//")
			pIsPath := strings.HasPrefix(part, "/")
			if !pIsURL && !pIsPath {
				continue
			}
			if seen[part] {
				continue
			}
			seen[part] = true
			results = append(results, ExtractedString{
				Value:   part,
				Context: "template_part",
				IsURL:   pIsURL,
				IsPath:  pIsPath,
			})
		}
	}

	return results
}

// extractCSSReferences extracts url() and @import references from CSS-in-JS
func extractCSSReferences(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)

	// Only scan within backtick template literals (CSS-in-JS context)
	templateParts := backtickStr.FindAllString(cleaned, -1)
	for _, t := range templateParts {
		// Skip if clearly not CSS
		if !strings.Contains(t, "{") && !strings.Contains(t, "@import") {
			// Still check for url() directly
		}

		// url('/images/foo.png') or url(https://cdn.example.com/foo.png)
		for _, m := range cssURLRef.FindAllStringSubmatch(t, -1) {
			if len(m) >= 2 {
				val := strings.TrimSpace(m[1])
				if val != "" && !seen[val] && len(val) >= 3 {
					seen[val] = true
					isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
					isPath := strings.HasPrefix(val, "/") || strings.HasPrefix(val, "data:")
					if isURL || isPath {
						results = append(results, ExtractedString{
							Value:   val,
							Context: "css_url",
							IsURL:   isURL,
							IsPath:  isPath,
						})
					}
				}
			}
		}

		// @import 'reset.css' or @import url('./reset.css')
		for _, m := range cssImportRef.FindAllStringSubmatch(t, -1) {
			if len(m) >= 2 {
				val := strings.TrimSpace(m[1])
				if val != "" && !seen[val] && len(val) >= 3 {
					seen[val] = true
					isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
					isPath := strings.HasPrefix(val, "/") || strings.HasPrefix(val, "./") || strings.HasPrefix(val, "../")
					if isURL || isPath {
						results = append(results, ExtractedString{
							Value:   val,
							Context: "css_import",
							IsURL:   isURL,
							IsPath:  isPath,
						})
					}
				}
			}
		}
	}

	return results
}

// extractEnvironmentURLs extracts URLs from Worker/Window/Location/Router patterns
func extractEnvironmentURLs(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)

	addResolved := func(val, ctx string) {
		val = strings.Trim(val, "'\"`")
		val = strings.TrimSpace(val)
		if val == "" || seen[val] || len(val) < 3 {
			return
		}
		seen[val] = true
		isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
		isPath := strings.HasPrefix(val, "/") || strings.HasPrefix(val, "./") || strings.HasPrefix(val, "../")
		results = append(results, ExtractedString{
			Value:   val,
			Context: ctx,
			IsURL:   isURL,
			IsPath:  isPath,
		})
	}

	// new Worker('...')
	for _, m := range workerPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "worker")
		}
	}

	// navigator.serviceWorker.register('...')
	for _, m := range swRegisterPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "service_worker")
		}
	}

	// WebAssembly.instantiateStreaming('...')
	for _, m := range wasmPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "wasm")
		}
	}

	// postMessage('...', targetOrigin)
	for _, m := range postMessageOriginPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "postmessage_origin")
		}
	}

	// window.open('...')
	for _, m := range windowOpenPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "window_open")
		}
	}

	// location.assign/replace/href
	for _, m := range locationAssignPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "location_assign")
		}
	}

	// router.push('/path') — Next.js/Nuxt
	for _, m := range routerPushPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "router_push")
		}
	}

	// Angular Router: this.router.navigate(['/path'])
	for _, m := range angularRouterPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "angular_router")
		}
	}

	// Vue Router: router.push({ path: '/path' })
	for _, m := range vueRouterPushPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "vue_router")
		}
	}

	return results
}

// extractConcatenationPatterns detects URL concatenation like:
// "https://api." + domain + ".com/v2/" + endpoint
// Also catches ||, &&, ??, ternary concatenation patterns
func extractConcatenationPatterns(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)

	// Left-side absolute URL: "https://api.example.com/" + ...
	for _, m := range concatLeftAbsolute.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			val := strings.TrimSpace(m[1])
			if val != "" && !seen[val] {
				seen[val] = true
				results = append(results, ExtractedString{
					Value:   val,
					Context: "concat_left_abs",
					IsURL:   true,
					IsPath:  false,
				})
			}
		}
	}

	// Left-side relative path: "/api/v2/" + ...
	for _, m := range concatLeftRelative.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			val := strings.TrimSpace(m[1])
			if val != "" && !seen[val] {
				seen[val] = true
				results = append(results, ExtractedString{
					Value:   val,
					Context: "concat_left_rel",
					IsURL:   false,
					IsPath:  true,
				})
			}
		}
	}

	// Left-side keyword-based: "https://api." + ...
	for _, m := range concatLeftKeyword.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			val := strings.TrimSpace(m[1])
			if val != "" && !seen[val] {
				seen[val] = true
				isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
				results = append(results, ExtractedString{
					Value:   val,
					Context: "concat_left_keyword",
					IsURL:   isURL,
					IsPath:  strings.HasPrefix(val, "/"),
				})
			}
		}
	}

	// Right-side: ... + "/api/v2/users"
	for _, m := range concatRight.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			val := strings.TrimSpace(m[1])
			if val != "" && !seen[val] {
				seen[val] = true
				isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://")
				results = append(results, ExtractedString{
					Value:   val,
					Context: "concat_right",
					IsURL:   isURL,
					IsPath:  strings.HasPrefix(val, "/"),
				})
			}
		}
	}

	// URL as default/fallback: const url = baseURL || "https://api.example.com"
	orDefaultPat := regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]+)["'\` + "`" + `]\s*(?:\|\||\?\?|&&)`)
	for _, m := range orDefaultPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			val := strings.TrimSpace(m[1])
			if val != "" && !seen[val] {
				seen[val] = true
				results = append(results, ExtractedString{
					Value:   val,
					Context: "or_default",
					IsURL:   true,
					IsPath:  false,
				})
			}
		}
	}

	// Ternary operator: condition ? "https://api.example.com" : "/fallback"
	ternaryPat := regexp.MustCompile(`\?\s*["'\` + "`" + `]([^"'\` + "`" + `\s]{5,})["'\` + "`" + `]\s*:`)
	for _, m := range ternaryPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			val := strings.TrimSpace(m[1])
			if val != "" && !seen[val] {
				seen[val] = true
				isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
				isPath := strings.HasPrefix(val, "/")
				if isURL || isPath {
					results = append(results, ExtractedString{
						Value:   val,
						Context: "ternary",
						IsURL:   isURL,
						IsPath:  isPath,
					})
				}
			}
		}
	}

	// Template literal inside concatenation: `https://api.` + domain
	backtickConcatPat := regexp.MustCompile("`([^`\\\\]*(?:\\\\.[^`\\\\]*)*)`\\s*\\+")
	for _, m := range backtickConcatPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			val := strings.TrimSpace(m[1])
			if val != "" && !seen[val] && len(val) >= 5 {
				seen[val] = true
				isURL := strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//")
				isPath := strings.HasPrefix(val, "/")
				if isURL || isPath {
					results = append(results, ExtractedString{
						Value:   val,
						Context: "backtick_concat_left",
						IsURL:   isURL,
						IsPath:  isPath,
					})
				}
			}
		}
	}

	return results
}

// extractJSONConfigObjects extracts URL-like values from JS config/options objects
// Uses proper brace-depth matching instead of regex $ anchor
func extractJSONConfigObjects(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)

	// Find JSON-like object assignments with brace-depth matching
	objStarts := findAllObjAssignments(cleaned)
	for _, startPos := range objStarts {
		endPos := findMatchingBrace(cleaned, startPos)
		if endPos <= startPos {
			continue
		}
		objStr := cleaned[startPos : endPos+1]

		// Normalize JS object literal to JSON
		objStr = strings.ReplaceAll(objStr, `'`, `"`)
		// Only quote keys preceded by {, ,, or start-of-context (not word: inside string values)
		keyRe := regexp.MustCompile(`([{,]\s*)(\w+)\s*:`)
		objStr = keyRe.ReplaceAllString(objStr, `$1"$2":`)
		// Also handle first key if at start of string
		if strings.HasPrefix(objStr, `"`) || strings.HasPrefix(objStr, `'`) {
			// already quoted
		} else if len(objStr) > 0 && objStr[0] != '{' {
			objStr = "{" + objStr
		}
		firstKeyRe := regexp.MustCompile(`^\{\s*(\w+)\s*:`)
		objStr = firstKeyRe.ReplaceAllString(objStr, `{"$1":`)
		// Remove trailing commas before } and ]
		objStr = regexp.MustCompile(`,(\s*[}\]])`).ReplaceAllString(objStr, "$1")

		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(objStr), &parsed); err == nil {
			extractStringsFromParsed(parsed, &results, seen, "")
		}
	}

	// Property assignments: this.apiUrl = "https://..."
	propAssign := regexp.MustCompile(`(\w+)\.(\w+)\s*=\s*["'\` + "`" + `]([^"'\` + "`" + `\n]{5,})["'\` + "`" + `]`)
	for _, m := range propAssign.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 4 {
			val := strings.TrimSpace(m[3])
			if (strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") ||
				strings.HasPrefix(val, "/") || strings.HasPrefix(val, "ws")) && !seen[val] {
				seen[val] = true
				results = append(results, ExtractedString{
					Value:   val,
					Context: "prop_assign_" + m[1] + "." + m[2],
					IsURL:   strings.HasPrefix(val, "http"),
					IsPath:  strings.HasPrefix(val, "/"),
				})
			}
		}
	}

	// Object spread/spread element: { ...defaults, apiUrl: "https://..." }
	spreadPropAssign := regexp.MustCompile(`\.\.\.\w+\s*,\s*["'\` + "`" + `]?(\w+)["'\` + "`" + `]?\s*:\s*["'\` + "`" + `]([^"'\` + "`" + `,}\n]{5,})["'\` + "`" + `]`)
	for _, m := range spreadPropAssign.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 3 {
			fieldName := m[1]
			val := strings.TrimSpace(m[2])
			if urlFieldNames.MatchString(fieldName) && !seen[val] {
				seen[val] = true
				results = append(results, ExtractedString{
					Value:   val,
					Context: "spread_assign_" + fieldName,
					IsURL:   strings.HasPrefix(val, "http"),
					IsPath:  strings.HasPrefix(val, "/"),
				})
			}
		}
	}

	return results
}

// findAllObjAssignments finds positions of opening braces in object assignments
// Matches: const|let|var|static name = {, name = {, return {, : {
func findAllObjAssignments(code string) []int {
	var positions []int
	// Simple cases: const x = {, var y = {, let z = {, this.config = {
	pat := regexp.MustCompile(`(?:const|let|var|static|return|=\s*)\s+\w*\s*=\s*\{`)
	for _, idx := range pat.FindAllStringIndex(code, -1) {
		if idx[1] > 0 && idx[1] < len(code) {
			// idx[1] points past '{' — but we need the position of '{'
			bracePos := strings.LastIndex(code[:idx[1]], "{")
			if bracePos >= 0 {
				positions = append(positions, bracePos)
			}
		}
	}
	// Also match: { directly as function return or arrow body implicit return
	arrowObjPat := regexp.MustCompile(`=>\s*\{`)
	for _, idx := range arrowObjPat.FindAllStringIndex(code, -1) {
		bracePos := strings.LastIndex(code[:idx[1]], "{")
		if bracePos >= 0 {
			positions = append(positions, bracePos)
		}
	}
	return positions
}

// findMatchingBrace finds the closing brace for a brace at startPos
func findMatchingBrace(s string, startPos int) int {
	if startPos >= len(s) || s[startPos] != '{' {
		return -1
	}
	depth := 0
	for i := startPos; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		case '\'':
			// Skip string literal
			i++
			for i < len(s) {
				if s[i] == '\\' {
					i += 2
					continue
				}
				if s[i] == '\'' {
					break
				}
				i++
			}
		case '"':
			i++
			for i < len(s) {
				if s[i] == '\\' {
					i += 2
					continue
				}
				if s[i] == '"' {
					break
				}
				i++
			}
		case '`':
			i++
			for i < len(s) {
				if s[i] == '\\' {
					i += 2
					continue
				}
				if s[i] == '`' {
					break
				}
				// Skip ${} interpolations — the template content is consumed
				// entirely by this inner loop, so don't touch depth
				if s[i] == '$' && i+1 < len(s) && s[i+1] == '{' {
					i += 2 // skip ${
					// Skip past the matching } of the interpolation
					interpDepth := 1
					for i < len(s) && interpDepth > 0 {
						if s[i] == '{' {
							interpDepth++
						} else if s[i] == '}' {
							interpDepth--
						} else if s[i] == '\\' {
							i++
						}
						if interpDepth > 0 {
							i++
						}
					}
					continue
				}
				i++
			}
		}
	}
	return -1
}

// extractStringsFromParsed walks parsed JSON and extracts URL-like strings
func extractStringsFromParsed(data map[string]interface{}, results *[]ExtractedString, seen map[string]bool, prefix string) {
	for key, val := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := val.(type) {
		case string:
			if (strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") ||
				strings.HasPrefix(v, "/") || strings.HasPrefix(v, "ws://") || strings.HasPrefix(v, "wss://") ||
				strings.HasPrefix(v, "//")) &&
				!seen[v] {
				seen[v] = true
				*results = append(*results, ExtractedString{
					Value:   v,
					Context: "json_parse_" + fullKey,
					IsURL:   strings.HasPrefix(v, "http") || strings.HasPrefix(v, "//"),
					IsPath:  strings.HasPrefix(v, "/"),
				})
			}
		case map[string]interface{}:
			extractStringsFromParsed(v, results, seen, fullKey)
		case []interface{}:
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					extractStringsFromParsed(m, results, seen, fullKey)
				}
				if s, ok := item.(string); ok {
					if (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") ||
						strings.HasPrefix(s, "/") || strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://")) &&
						!seen[s] {
						seen[s] = true
						*results = append(*results, ExtractedString{
							Value:   s,
							Context: "json_parse_" + fullKey + "[]",
							IsURL:   strings.HasPrefix(s, "http"),
							IsPath:  strings.HasPrefix(s, "/"),
						})
					}
				}
			}
		}
	}
}

// extractSvelteKitLoadURLs extracts URLs from SvelteKit load functions
func extractSvelteKitLoadURLs(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)

	if !svelteKitLoadPat.MatchString(cleaned) {
		return nil
	}

	// Extract fetch() calls inside load functions
	// export const load = async ({ fetch, url }) => { const res = await fetch('/api/data') }
	loadSectionRe := regexp.MustCompile(`(?s)(?:export\s+(?:const|function|async\s+function)\s+load\s*[=\(])[\s\S]{0,500}?\}`)
	for _, m := range loadSectionRe.FindAllStringSubmatch(cleaned, -1) {
		if len(m) < 2 {
			continue
		}
		section := m[0]
		// Extract fetch() URLs within load
		fetchInLoad := regexp.MustCompile(`fetch\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `\)]+)["'\` + "`" + `]`)
		for _, fm := range fetchInLoad.FindAllStringSubmatch(section, -1) {
			if len(fm) >= 2 {
				val := strings.TrimSpace(fm[1])
				if !seen[val] && len(val) >= 3 {
					seen[val] = true
					results = append(results, ExtractedString{
						Value:   val,
						Context: "sveltekit_load_fetch",
						IsURL:   strings.HasPrefix(val, "http"),
						IsPath:  strings.HasPrefix(val, "/"),
					})
				}
			}
		}
	}

	return results
}

// ============================================================================
// Enhanced JS Analysis Pipeline
// ============================================================================

type JSAnalysisResult struct {
	Strings        []ExtractedString
	ModuleURLs     []ExtractedString
	TemplateParts  []ExtractedString
	CSSRefs        []ExtractedString
	EnvURLs        []ExtractedString
	Concatenations []ExtractedString
	ConfigObjects  []ExtractedString
	SvelteKitURLs  []ExtractedString
	Endpoints      []EndpointResult
	Secrets        []SensitiveFinding
}

// analyzeJS performs comprehensive analysis on JS source code
func analyzeJS(code string, sourceURL string) JSAnalysisResult {
	var result JSAnalysisResult

	result.Strings = extractAllStrings(code)
	result.ModuleURLs = extractModernJSModuleURLs(code)
	result.TemplateParts = extractTemplateLiteralInterpolations(code)
	result.CSSRefs = extractCSSReferences(code)
	result.EnvURLs = extractEnvironmentURLs(code)
	result.Concatenations = extractConcatenationPatterns(code)
	result.ConfigObjects = extractJSONConfigObjects(code)
	result.SvelteKitURLs = extractSvelteKitLoadURLs(code)
	result.Endpoints = extractEndpoints(code)
	result.Secrets = findSensitive(code, sourceURL)

	return result
}

// extractJSStringURLs returns all URL-like strings from JS analysis
func extractJSStringURLs(result JSAnalysisResult) []ExtractedString {
	var urls []ExtractedString
	seen := make(map[string]bool)

	sources := [][]ExtractedString{
		result.Strings,
		result.ModuleURLs,
		result.TemplateParts,
		result.CSSRefs,
		result.EnvURLs,
		result.Concatenations,
		result.ConfigObjects,
		result.SvelteKitURLs,
	}

	for _, list := range sources {
		for _, s := range list {
			if s.IsURL || s.IsPath {
				if !seen[s.Value] {
					seen[s.Value] = true
					urls = append(urls, s)
				}
			}
		}
	}

	return urls
}

// hasESMSyntax returns true if code contains ESM import/export syntax
func hasESMSyntax(code string) bool {
	cleaned := stripJSComments(code)
	// Check for modern ESM syntax (not just CommonJS require)
	if regexp.MustCompile(`\bimport\s+(?:\w+\s+from\s+["'\` + "`" + `]|["'\` + "`" + `]|\{|meta|\s*\()`).MatchString(cleaned) {
		return true
	}
	if regexp.MustCompile(`\bexport\s+(?:default|const|let|var|function|class|type|interface|\{|\[|\*)`).MatchString(cleaned) {
		return true
	}
	return false
}

// isCSSInJS returns true if code appears to be CSS-in-JS tagged template content
func isCSSInJS(code string) bool {
	return cssTaggedTemplate.MatchString(code)
}

// extractJSPropertyNames extracts object property names that look like route paths
func extractJSPropertyNames(code string) []string {
	cleaned := stripJSComments(code)
	var names []string
	seen := make(map[string]bool)

	// Match property names in route config objects: '/users': { ... }
	propPat := regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]{2,})["'\` + "`" + `]\s*:`)
	for _, m := range propPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			name := m[1]
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}

	return names
}
