package main

import (
	"regexp"
	"strings"
)

var techPatterns = []struct {
	Name    string
	Type    string
	Pattern *regexp.Regexp
}{
	{"React", "framework", regexp.MustCompile(`__REACT_DEVTOOLS_GLOBAL_HOOK__|React\.createElement|react\.js|react\.min\.js`)},
	{"React (next)", "framework", regexp.MustCompile(`__NEXT_DATA__|next\.js|/_next/static`)},
	{"Vue.js", "framework", regexp.MustCompile(`Vue\.component|vue\.js|vue\.min\.js|__VUE__`)},
	{"Nuxt.js", "framework", regexp.MustCompile(`__NUXT__|nuxt\.js|/_nuxt/`)},
	{"Angular", "framework", regexp.MustCompile(`angular\.js|angular\.min\.js|ng-app|ng-controller|ng-model|NgModule`)},
	{"Svelte", "framework", regexp.MustCompile(`svelte\.(?:js|min\.js)|__SVELTE__|sveltekit`)},
	{"SvelteKit", "framework", regexp.MustCompile(`__SVELTEKIT_DATA__|sveltekit\.js`)},
	{"SolidJS", "framework", regexp.MustCompile(`solid\.js|solidjs|__SOLID_START__`)},
	{"Qwik", "framework", regexp.MustCompile(`qwik\.js|__QWIK__|qwikloader`)},
	{"Next.js", "ssr", regexp.MustCompile(`__NEXT_DATA__|/_next/static|next\.js`)},
	{"Nuxt.js", "ssr", regexp.MustCompile(`__NUXT__|/_nuxt/|nuxt\.config`)},
	{"Remix", "ssr", regexp.MustCompile(`__remixContext|@remix-run`)},
	{"Gatsby", "ssr", regexp.MustCompile(`___gatsby|gatsby\.js`)},
	{"Astro", "ssr", regexp.MustCompile(`astro\.js|__ASTRO__|astro.config`)},
	{"jQuery", "library", regexp.MustCompile(`jquery\.js|jquery\.min\.js|jQuery\.`)},
	{"Lodash", "library", regexp.MustCompile(`lodash\.js|lodash\.min\.js|_.template`)},
	{"Axios", "library", regexp.MustCompile(`axios\.js|axios\.min\.js|axios\.`)},
	{"D3.js", "library", regexp.MustCompile(`d3\.js|d3\.min\.js|d3\.`)},
	{"Three.js", "library", regexp.MustCompile(`three\.js|three\.min\.js|THREE\.`)},
	{"Moment.js", "library", regexp.MustCompile(`moment\.js|moment\.min\.js`)},
	{"Chart.js", "library", regexp.MustCompile(`chart\.js|chart\.min\.js|Chart\.`)},
	{"Bootstrap", "css", regexp.MustCompile(`bootstrap\.css|bootstrap\.min\.css|bootstrap\.js|bootstrap\.min\.js`)},
	{"Tailwind CSS", "css", regexp.MustCompile(`tailwindcss|tailwind\.css`)},
	{"Font Awesome", "css", regexp.MustCompile(`font-awesome|fontawesome|fa\.css`)},
	{"Material UI", "ui", regexp.MustCompile(`@mui|material-ui|MUI\.`)},
	{"Ant Design", "ui", regexp.MustCompile(`antd|ant-design|ant\.`)},
	{"Chakra UI", "ui", regexp.MustCompile(`@chakra-ui|chakra\.`)},
	{"Shadcn/ui", "ui", regexp.MustCompile(`shadcn|@radix-ui`)},
	{"Webpack", "bundler", regexp.MustCompile(`webpackJsonp|__webpack_require__|webpackChunk`)},
	{"Vite", "bundler", regexp.MustCompile(`vite\.(?:js|min\.js)|__vite__|/@vite/`)},
	{"ESBuild", "bundler", regexp.MustCompile(`esbuild\.(?:js|min\.js)|esbuild`)},
	{"Parcel", "bundler", regexp.MustCompile(`parcelRequire|parcel`)},
	{"TypeScript", "lang", regexp.MustCompile(`ts\.(?:js|min\.js)|@babel/preset-typescript|typescript`)},
	{"Babel", "tool", regexp.MustCompile(`@babel|babel-polyfill|babel\.js`)},
	{"SWC", "tool", regexp.MustCompile(`@swc|swc\.`)},
	{"ESLint", "tool", regexp.MustCompile(`eslint\.config\.js|eslintrc\.`)},
	{"Prettier", "tool", regexp.MustCompile(`prettier\.config\.js|\.prettierrc`)},
	{"WebSocket", "realtime", regexp.MustCompile(`new\s+WebSocket|ws\.connect|io\.connect`)},
	{"Socket.IO", "realtime", regexp.MustCompile(`socket\.io\.js|socket\.io\.min\.js|io\.connect`)},
	{"GraphQL", "api", regexp.MustCompile(`graphql|gql\s*\x60|ApolloClient|urql`)},
	{"Apollo Client", "api", regexp.MustCompile(`@apollo|apollo-client|ApolloClient|__APOLLO_STATE__`)},
	{"tRPC", "api", regexp.MustCompile(`@trpc|trpc\.`)},
	{"Supabase", "backend", regexp.MustCompile(`supabase\.js|@supabase|supabase`)},
	{"Firebase", "backend", regexp.MustCompile(`firebase\.js|firebase\.app|@firebase`)},
	{"Stripe", "payment", regexp.MustCompile(`stripe\.js|stripe\.min\.js|Stripe\(`)},
	{"PostHog", "analytics", regexp.MustCompile(`posthog\.js|posthog\.min\.js`)},
	{"Google Analytics", "analytics", regexp.MustCompile(`gtag|ga\.js|analytics\.js`)},
	{"Cloudflare", "infra", regexp.MustCompile(`cloudflare|__cfduid|c dn-cgi`)},
	{"CloudFront", "infra", regexp.MustCompile(`cloudfront\.net`)},
	{"Fastly", "infra", regexp.MustCompile(`fastly\.net`)},
	{"Akamai", "infra", regexp.MustCompile(`akamai`)},
}

func (c *Crawler) detectTechnologies(body string, pageURL string, ct string) {
	var detected []TechDetect
	seen := make(map[string]bool)
	for _, tp := range techPatterns {
		if tp.Pattern.MatchString(body) && !seen[tp.Name] {
			seen[tp.Name] = true
			detected = append(detected, TechDetect{
				Name:   tp.Name,
				Type:   tp.Type,
				Source: pageURL,
			})
		}
	}
	// Add some server headers if available from content-type
	if strings.Contains(ct, "next") && !seen["Next.js"] {
		detected = append(detected, TechDetect{Name: "Next.js", Type: "ssr", Source: pageURL})
	}
	for _, d := range detected {
		writeOutput(`{"type":"tech","name":%q,"tech_type":%q,"source":%q}`+"\n", d.Name, d.Type, d.Source)
	}
}
