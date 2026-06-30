package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var sensitiveFilePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.env$`),
	regexp.MustCompile(`(?i)\.git/config$`),
	regexp.MustCompile(`(?i)\.htaccess$`),
	regexp.MustCompile(`(?i)config\.(json|yaml|yml|php|js|py)$`),
	regexp.MustCompile(`(?i)secret`),
	regexp.MustCompile(`(?i)credential`),
	regexp.MustCompile(`(?i)token`),
	regexp.MustCompile(`(?i)password`),
	regexp.MustCompile(`(?i)api[_-]?key`),
	regexp.MustCompile(`(?i)auth\.(json|yaml|yml|php|js|py)$`),
	regexp.MustCompile(`(?i)(dump|backup|sql|db|database)`),
}

func isSensitiveFile(rawURL string) bool {
	for _, re := range sensitiveFilePatterns {
		if re.MatchString(rawURL) {
			return true
		}
	}
	return false
}

func (c *Crawler) performActiveBrute() {
	paths := []string{
		"/app.js", "/main.js", "/index.js", "/bundle.js", "/vendor.js",
		"/common.js", "/utils.js", "/helpers.js", "/functions.js",
		"/core.js", "/app.min.js", "/main.min.js", "/all.js",
		"/script.js", "/scripts.js", "/application.js", "/global.js",
		"/site.js", "/theme.js", "/custom.js", "/init.js", "/config.js",
		"/conf.js", "/settings.js", "/runtime.js", "/polyfills.js", "/styles.js",
		"/static/js/main.js", "/static/js/bundle.js", "/static/js/app.js",
		"/static/js/main.min.js", "/static/js/bundle.min.js",
		"/static/js/vendor.js", "/static/js/runtime.js",
		"/static/js/polyfills.js", "/static/js/common.js",
		"/dist/js/main.js", "/dist/js/bundle.js", "/dist/js/app.js",
		"/dist/js/vendor.js", "/dist/js/runtime.js",
		"/dist/main.js", "/dist/bundle.js", "/dist/app.js",
		"/build/js/main.js", "/build/js/bundle.js", "/build/js/app.js",
		"/build/main.js", "/build/bundle.js",
		"/assets/js/main.js", "/assets/js/bundle.js", "/assets/js/app.js",
		"/assets/js/vendor.js", "/assets/js/common.js",
		"/public/js/main.js", "/public/js/bundle.js",
		"/js/app.js", "/js/main.js", "/js/bundle.js", "/js/vendor.js",
		"/js/common.js", "/js/scripts.js", "/js/global.js",
		"/webpack-runtime.js", "/webpack.js",
		"/runtime~main.js", "/runtime~app.js",
		"/main.chunk.js", "/app.chunk.js", "/vendor.chunk.js",
		"/0.chunk.js", "/1.chunk.js", "/2.chunk.js", "/3.chunk.js",
		"/service-worker.js", "/sw.js", "/sw.ts",
		"/worker.js", "/workers.js", "/firebase-messaging-sw.js",
		"/serviceworker.js", "/precache-manifest.js",
		"/manifest.json", "/manifest.webmanifest",
		"/site.webmanifest", "/browserconfig.xml",
		"/asset-manifest.json", "/asset-manifest.json.map",
		"/webpack-assets.json", "/webpack-stats.json",
		"/stats.json", "/report.json",
		"/app.js.map", "/main.js.map", "/bundle.js.map", "/vendor.js.map",
		"/app.min.js.map", "/main.min.js.map",
		"/static/js/main.js.map", "/static/js/bundle.js.map",
		"/dist/main.js.map", "/dist/bundle.js.map",
		"/js/app.js.map", "/js/main.js.map",
		"/main.ts", "/app.ts", "/index.ts", "/config.ts",
		"/main.mjs", "/app.mjs", "/index.mjs",
		"/main.cjs", "/app.cjs", "/index.cjs",
		"/tsconfig.json", "/tsconfig.app.json",
		"/tsconfig.node.json", "/tsconfig.json.map",
		"/jsconfig.json",
		"/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
		"/humans.txt", "/security.txt", "/.well-known/security.txt",
		"/crossdomain.xml", "/clientaccesspolicy.xml",
		"/.env", "/.env.production", "/.env.development", "/.env.local",
		"/.env.example", "/env.js", "/env.json",
		"/config.json", "/config.js", "/config.yaml", "/config.yml",
		"/settings.json", "/settings.js",
		"/secrets.json", "/secrets.js",
		"/credentials.json", "/credentials.js",
		"/keys.json", "/keys.js",
		"/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
		"/graphql", "/graphql/", "/gql",
		"/swagger.json", "/swagger.yaml", "/swagger.yml",
		"/api-docs", "/api/docs", "/docs",
		"/openapi.json", "/openapi.yaml",
		"/.well-known/openid-configuration",
		"/package.json", "/package-lock.json", "/yarn.lock",
		"/pnpm-lock.yaml", "/bower.json",
		"/.npmrc", "/.yarnrc", "/.yarnrc.yml",
		"/lerna.json", "/nx.json", "/turbo.json",
		"/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
		"/.dockerignore", "/Makefile",
		"/Jenkinsfile", "/.github/workflows/ci.yml",
		"/.gitlab-ci.yml", "/.circleci/config.yml",
		"/.travis.yml", "/azure-pipelines.yml",
		"/.git/config", "/.git/HEAD", "/.gitignore",
		"/.gitattributes", "/.gitmodules",
		"/index.php", "/index.html", "/index.htm",
		"/index.asp", "/index.aspx", "/index.jsp",
		"/index.do", "/index.action",
		"/login.php", "/admin.php", "/wp-admin",
		"/wp-content", "/wp-includes",
		"/admin", "/login", "/signup", "/register",
		"/backup", "/backups", "/dump", "/dumps",
		"/sql", "/database", "/db",
		"/test", "/tests", "/dev", "/debug",
		"/staging", "/sandbox", "/demo",
		"/.htaccess", "/.htpasswd", "/.user.ini",
		"/nginx.conf", "/web.config", "/.htrouter.php",
		"/_next/static/chunks/pages",
		"/_next/static/chunks/main.js",
		"/_next/static/chunks/webpack.js",
		"/_next/static/chunks/framework.js",
		"/_next/static/chunks/commons.js",
		"/_next/static/chunks/app.js",
		"/_next/static/chunks/vendors.js",
		"/_next/static/runtime/main.js",
		"/_next/static/runtime/webpack.js",
		"/_next/data/build-id.json",
		"/_nuxt/js/app.js", "/_nuxt/js/vendor.js",
		"/_nuxt/js/main.js", "/_nuxt/js/runtime.js",
		"/_nuxt/static/commons/app.js",
		"/nuxt.config.js", "/nuxt.config.ts",
		"/angular.json", "/workspace.json",
		"/polyfills.js", "/runtime-es2015.js", "/runtime-es5.js",
		"/main-es2015.js", "/main-es5.js",
		"/styles-es2015.js", "/styles-es5.js",
		"/svelte.config.js", "/vite.config.js",
		"/solid.config.js", "/astro.config.mjs",
		"/firebase.json", "/firestore.indexes.json",
		"/firebase-messaging-sw.js",
		"/__/firebase/init.json",
		"/version", "/version.json", "/version.txt",
		"/health", "/healthcheck", "/healthz",
		"/status", "/status.json",
		"/metrics", "/metrics.json",
		"/info", "/info.json",
		"/.well-known/assetlinks.json",
		"/.well-known/apple-app-site-association",
		"/.well-known/change-password",
		"/_next/static/chunks/app/layout.js",
		"/_next/static/chunks/app/page.js",
		"/_next/static/chunks/app/loading.js",
		"/_next/static/chunks/app/error.js",
		"/_next/static/css/app.css",
		"/_next/static/css/pages.css",
		"/_next/data/build-id.json",
		"/@vite/client", "/@vite/env",
		"/manifest.json", "/vite.svg",
		"/dashboard", "/profile", "/settings", "/search",
		"/checkout", "/cart", "/payment", "/billing",
		"/onboarding", "/verify-email", "/reset-password",
		"/forgot-password", "/2fa", "/mfa",
		"/admin/users", "/admin/settings", "/admin/logs",
		"/admin/analytics", "/admin/api-keys", "/admin/webhooks",
		"/api-keys", "/webhooks", "/integrations",
		"/notifications", "/subscriptions", "/plans", "/pricing",
		"/redoc", "/rapidoc", "/graphiql", "/graphql/playground",
		"/altair", "/voyager", "/prisma", "/admin/panel",
		"/docs/swagger", "/docs/api", "/api/docs",
		"/.aws/credentials", "/aws-config.json",
		"/aws-exports.js", "/amplify-config.js",
		"/firebase-config.js", "/firebaseConfig.js",
		"/supabase-config.js", "/supabaseClient.js",
		"/vercel.json", "/netlify.toml",
		"/_redirects", "/_headers",
		"/deno.json", "/deno.jsonc", "/import_map.json",
		"/bun.lockb", "/bunfig.toml",
		"/jest.config.js", "/vitest.config.ts",
		"/.storybook/", "/playwright.config.ts",
		"/cypress.json", "/cypress/",
		"/.snyk", "/dependabot.yml",
		"/.github/dependabot.yml",
		"/.github/workflows/codeql.yml",
		"/sonar-project.properties",
		"/codecov.yml",
		"/_render", "/_ssr", "/_rsc", "/__rsc",
		"/_next/data/",
		"/src/", "/app/", "/pages/", "/components/",
		"/lib/", "/utils/", "/helpers/",
		"/sitemap.xml.gz", "/sitemap_index.xml",
		"/.well-known/security.txt",
		"/.well-known/did.json",
		"/.well-known/microsoft-identity-association.json",
		"/.well-known/nodeinfo",
		"/.well-known/webfinger",
		"/.well-known/matrix/client",
		"/.well-known/matrix/server",
		"/.well-known/apple-app-site-association",
		"/.well-known/assetlinks.json",
		"/.well-known/change-password",
		"/.well-known/dnt-policy.txt",
		"/.well-known/gpc.json",
		"/.well-known/keybase.txt",
		"/.well-known/private-tab",
		"/.well-known/autoconfig/mail",
		"/.well-known/caldav",
		"/.well-known/carddav",
		"/ads.txt",
		"/app-ads.txt",
		"/graphql/console",
		"/graphiql",
		"/hasura/console",
		"/prisma/studio",
		"/_dev/",
		"/__internals/",
		"/_debug/",
		"/debug/",
		"/dev/",
		"/.env.staging",
		"/.env.prod",
		"/.env.test",
		"/env.local",
		"/.config.json",
		"/app.config.json",
		"/next.config.js",
		"/nuxt.config.ts",
		"/astro.config.mjs",
		"/svelte.config.js",
		"/remix.config.js",
		"/.env.production.local",
		"/.env.development.local",
		"/.env.test.local",
		"/.env.staging.local",
	}

	limiter := make(chan struct{}, 20)
	for _, p := range paths {
		p := p
		limiter <- struct{}{}
		c.WG.Add(1)
		go func() {
			defer c.WG.Done()
			defer func() { <-limiter }()
			fullURL := fmt.Sprintf("%s%s", strings.TrimSuffix(c.BaseURL, "/"), p)
			if c.Filters.HasSeen(fullURL) {
				return
			}
			req, _ := http.NewRequest("GET", fullURL, nil)
			c.setHeaders(req)
			req.Header.Set("Accept", "*/*")
			resp, err := c.Client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			isJS := strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".ts") || strings.HasSuffix(p, ".mjs") || strings.HasSuffix(p, ".cjs") || strings.HasSuffix(p, ".jsx") || strings.HasSuffix(p, ".tsx") || strings.HasSuffix(p, ".json") || strings.HasSuffix(p, ".map")
			isCodeFile := isJS || strings.HasSuffix(p, ".env") || strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".conf") || strings.HasSuffix(p, ".config") || strings.HasSuffix(p, ".php") || strings.HasSuffix(p, ".py")
			if resp.StatusCode == 200 {
				bodyStr := ""
				if isJS {
					bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
					bodyStr = string(bodyBytes)
				}
				if isJS || isCodeFile || isSensitiveFile(fullURL) {
					c.addQueueItem(urlQueue{url: fullURL, source: c.BaseURL, depth: 1})
					if strings.HasSuffix(fullURL, ".js") || strings.HasSuffix(fullURL, ".mjs") || strings.HasSuffix(fullURL, ".cjs") {
						c.checkSourceMap(fullURL)
					}
					if c.Opts.ShowCode && isJS && bodyStr != "" && len(bodyStr) < 512*1024 {
						bodyJSON, _ := json.Marshal(bodyStr)
						writeOutput(`{"type":"js_source","url":%q,"status":200,"length":%d,"body":%s,"method":"brute"}`+"\n", fullURL, len(bodyStr), string(bodyJSON))
					}
				}
				writeOutput(`{"type":"discovered","url":%q,"source":%q,"method":"brute","status":200}`+"\n", fullURL, c.BaseURL)
			}
		}()
	}
	c.WG.Wait()
}
