package main

import (
	"fmt"
	"os"
	"strings"
)

func GenerateCompletion(shell string) {
	switch shell {
	case "bash":
		fmt.Print(`_atomix_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="-u -target -l -list -id -tags -severity -templates -t -threads -c -concurrency -timeout -retries -rate-limit -bulk-size -stream -w -workflow -hm -headless -p -proxy -sni -r -resolvers -resolver -scan-all-ips -ip-version -exclude-ports -eh -pn -pipeline -m -method -path -fuzz -fuzz-mode -fuzz-recursive -o -output -json -jsonl -csv -html -md -markdown -sarif -silent -v -verbose -d -debug -nc -no-color -stats -metrics -trace -no-meta -ep -epid -et -etag -es -esev -probe -H -header -rand-agent -custom-agent -http2 -http2-downgrade -keep-alive -max-redirects -follow-redirects -cookie -auth -auth-type -auth-token -client-cert -client-key -client-ca -waf-detect -waf-skip -tech-detect -interactsh -oob-server -oob-token -oob-type -monitor -mf -monitor-format -push -push-format -slack -telegram -telegram-chat -webhook -dashboard -dashboard-port -diff -replay -health -smart -nc -no-color -version -h -help"
    COMPREPLY=($(compgen -W "${opts}" -- ${cur}))
    return 0
}
complete -F _atomix_completion atomix
`)
	case "zsh":
		fmt.Print(`#compdef atomix
_atomix() {
    local -a opts
    opts=(
        '-u[target URL]'
        '-target[target URL]'
        '-l[list templates]'
        '-list[list templates]'
        '-id[template ID]'
        '-tags[template tags]'
        '-severity[filter severity]'
        '-templates[template directory]'
        '-t[threads]'
        '-threads[threads]'
        '-c[concurrency]'
        '-concurrency[concurrency]'
        '-timeout[request timeout]'
        '-retries[max retries]'
        '-rate-limit[rate limit]'
        '-bulk-size[bulk size]'
        '-stream[stream mode]'
        '-w[workflow file]'
        '-workflow[workflow file]'
        '-hm[headless mode]'
        '-headless[headless mode]'
        '-p[proxy URL]'
        '-proxy[proxy URL]'
        '-sni[SNI name]'
        '-r[resolvers]'
        '-resolvers[resolvers]'
        '-resolver[custom resolver]'
        '-scan-all-ips[scan all IPs]'
        '-ip-version[IP version]'
        '-exclude-ports[exclude ports]'
        '-eh[exclude hosts]'
        '-pn[pipeline mode]'
        '-pipeline[pipeline mode]'
        '-m[HTTP method]'
        '-method[HTTP method]'
        '-path[request path]'
        '-fuzz[fuzz mode]'
        '-fuzz-mode[fuzz mode type]'
        '-fuzz-recursive[recursive fuzz]'
        '-o[output file]'
        '-output[output file]'
        '-json[JSON output]'
        '-jsonl[JSONL output]'
        '-csv[CSV output]'
        '-html[HTML output]'
        '-md[Markdown output]'
        '-markdown[Markdown output]'
        '-sarif[SARIF output]'
        '-silent[silent mode]'
        '-v[verbose]'
        '-verbose[verbose]'
        '-d[debug]'
        '-debug[debug]'
        '-no-color[disable colors]'
        '-stats[show stats]'
        '-metrics[show metrics]'
        '-trace[show trace]'
        '-no-meta[no metadata]'
        '-ep[exclude paths]'
        '-epid[exclude template IDs]'
        '-et[exclude types]'
        '-etag[exclude tags]'
        '-es[exclude severities]'
        '-esev[exclude severities]'
        '-probe[probe mode]'
        '-H[custom header]'
        '-header[custom header]'
        '-rand-agent[random user agent]'
        '-custom-agent[custom user agent]'
        '-http2[HTTP/2]'
        '-http2-downgrade[HTTP/2 downgrade]'
        '-keep-alive[keep-alive]'
        '-max-redirects[max redirects]'
        '-follow-redirects[follow redirects]'
        '-cookie[set cookie]'
        '-auth[auth type]'
        '-auth-type[auth type]'
        '-auth-token[auth token]'
        '-client-cert[client cert]'
        '-client-key[client key]'
        '-client-ca[client CA]'
        '-waf-detect[WAF detection]'
        '-waf-skip[skip WAF]'
        '-tech-detect[tech detection]'
        '-interactsh[interactsh]'
        '-oob-server[OOB server]'
        '-oob-token[OOB token]'
        '-oob-type[OOB type]'
        '-monitor[monitor mode]'
        '-mf[monitor format]'
        '-monitor-format[monitor format]'
        '-push[push URL]'
        '-push-format[push format]'
        '-slack[Slack webhook]'
        '-telegram[Telegram bot token]'
        '-telegram-chat[Telegram chat ID]'
        '-webhook[webhook URL]'
        '-dashboard[enable dashboard]'
        '-dashboard-port[dashboard port]'
        '-diff[diff results]'
        '-replay[replay finding]'
        '-health[health check]'
        '-smart[smart scan]'
        '-version[show version]'
        '-h[help]'
        '-help[help]'
    )
    _describe 'atomix' opts
}
_atomix "$@"
`)
	case "fish":
		fmt.Print(`complete -c atomix -s u -l target -d "Target URL"
complete -c atomix -s l -l list -d "List templates"
complete -c atomix -l id -d "Template ID"
complete -c atomix -l tags -d "Template tags"
complete -c atomix -l severity -d "Filter by severity"
complete -c atomix -l templates -d "Template directory"
complete -c atomix -s t -l threads -d "Threads"
complete -c atomix -s c -l concurrency -d "Concurrency"
complete -c atomix -l timeout -d "Request timeout"
complete -c atomix -l retries -d "Max retries"
complete -c atomix -l rate-limit -d "Rate limit"
complete -c atomix -l bulk-size -d "Bulk size"
complete -c atomix -l stream -d "Stream mode"
complete -c atomix -s w -l workflow -d "Workflow file"
complete -c atomix -l hm -l headless -d "Headless mode"
complete -c atomix -s p -l proxy -d "Proxy URL"
complete -c atomix -l sni -d "SNI name"
complete -c atomix -s r -l resolvers -d "Resolvers"
complete -c atomix -l scan-all-ips -d "Scan all IPs"
complete -c atomix -l ip-version -d "IP version"
complete -c atomix -l exclude-ports -d "Exclude ports"
complete -c atomix -s eh -d "Exclude hosts"
complete -c atomix -l pn -l pipeline -d "Pipeline mode"
complete -c atomix -s m -l method -d "HTTP method"
complete -c atomix -l path -d "Request path"
complete -c atomix -l fuzz -d "Fuzz mode"
complete -c atomix -l fuzz-mode -d "Fuzz mode type"
complete -c atomix -l fuzz-recursive -d "Recursive fuzz"
complete -c atomix -s o -l output -d "Output file"
complete -c atomix -l json -d "JSON output"
complete -c atomix -l jsonl -d "JSONL output"
complete -c atomix -l csv -d "CSV output"
complete -c atomix -l html -d "HTML output"
complete -c atomix -l md -l markdown -d "Markdown output"
complete -c atomix -l sarif -d "SARIF output"
complete -c atomix -l silent -d "Silent mode"
complete -c atomix -s v -l verbose -d "Verbose"
complete -c atomix -s d -l debug -d "Debug"
complete -c atomix -l no-color -d "Disable colors"
complete -c atomix -l stats -d "Show stats"
complete -c atomix -l metrics -d "Show metrics"
complete -c atomix -l trace -d "Show trace"
complete -c atomix -l no-meta -d "No metadata"
complete -c atomix -l ep -d "Exclude paths"
complete -c atomix -l epid -d "Exclude template IDs"
complete -c atomix -l et -d "Exclude types"
complete -c atomix -l etag -d "Exclude tags"
complete -c atomix -l es -l esev -d "Exclude severities"
complete -c atomix -l probe -d "Probe mode"
complete -c atomix -s H -l header -d "Custom header"
complete -c atomix -l rand-agent -d "Random user agent"
complete -c atomix -l custom-agent -d "Custom user agent"
complete -c atomix -l http2 -d "HTTP/2"
complete -c atomix -l http2-downgrade -d "HTTP/2 downgrade"
complete -c atomix -l keep-alive -d "Keep-alive"
complete -c atomix -l max-redirects -d "Max redirects"
complete -c atomix -l follow-redirects -d "Follow redirects"
complete -c atomix -l cookie -d "Set cookie"
complete -c atomix -l auth -l auth-type -d "Auth type"
complete -c atomix -l auth-token -d "Auth token"
complete -c atomix -l client-cert -d "Client cert"
complete -c atomix -l client-key -d "Client key"
complete -c atomix -l client-ca -d "Client CA"
complete -c atomix -l waf-detect -d "WAF detection"
complete -c atomix -l waf-skip -d "Skip WAF"
complete -c atomix -l tech-detect -d "Tech detection"
complete -c atomix -l interactsh -d "Interactsh"
complete -c atomix -l oob-server -d "OOB server"
complete -c atomix -l oob-token -d "OOB token"
complete -c atomix -l oob-type -d "OOB type"
complete -c atomix -l monitor -d "Monitor mode"
complete -c atomix -l mf -l monitor-format -d "Monitor format"
complete -c atomix -l push -d "Push URL"
complete -c atomix -l push-format -d "Push format"
complete -c atomix -l slack -d "Slack webhook"
complete -c atomix -l telegram -d "Telegram bot token"
complete -c atomix -l telegram-chat -d "Telegram chat ID"
complete -c atomix -l webhook -d "Webhook URL"
complete -c atomix -l dashboard -d "Enable dashboard"
complete -c atomix -l dashboard-port -d "Dashboard port"
complete -c atomix -l diff -d "Diff results"
complete -c atomix -l replay -d "Replay finding"
complete -c atomix -l health -d "Health check"
complete -c atomix -l smart -d "Smart scan"
complete -c atomix -l version -d "Show version"
complete -c atomix -s h -l help -d "Show help"
`)
	}
}

func HandleCompletion(shell string) {
	if shell == "" {
		fmt.Fprintf(os.Stderr, "%s Usage: atomix --completion bash|zsh|fish\n",
			SColor(ColorYellow, "[!]"))
		os.Exit(1)
	}
	shell = strings.ToLower(shell)
	valid := map[string]bool{"bash": true, "zsh": true, "fish": true}
	if !valid[shell] {
		fmt.Fprintf(os.Stderr, "%s Unsupported shell: %s (use bash, zsh, fish)\n",
			SColor(ColorRed, "[!]"), shell)
		os.Exit(1)
	}
	GenerateCompletion(shell)
}
