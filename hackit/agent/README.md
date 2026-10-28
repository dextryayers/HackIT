# HackIt Agent

HackIt Agent is the AI orchestration layer of HackIt. It connects a Python
command-line application to native Go engines, so a single interface can run
reconnaissance, OSINT, web scanning, payload generation, analysis and reporting
against an authorised target.

The agent is designed around three principles:

* **Provider independence** — use a cloud API or a local Ollama model. If the
  selected provider fails, the agent falls back to any other configured
  provider automatically.
* **Evidence first** — scanners compare against a baseline and only promote
  observations to findings when there is a real signal. Payload probing is
  disabled unless the operator explicitly authorises it.
* **Graceful degradation** — every optional dependency (Rich, prompt_toolkit,
  LangChain, LangGraph) has a built-in fallback. The agent still works on a
  minimal Python installation.

---

## Quick start

```bash
# from the repository root
pip install -e .
pip install -e ".[agent,graph]"      # optional LangChain memory + LangGraph

# build every Go binary (AI engine, chat engine, worker, hative, swarm, modules)
bash hackit/agent/go/build.sh

# configure a provider (interactive)
hackit agent setting

# verify connectivity, model discovery and Ollama
hackit agent doctor

# start the terminal UI
hackit agent chat
```

`hackit agent setting` writes keys to `~/.hackit/config.json`. Keys are
obfuscated with the `__enc__` prefix; environment variables always take
precedence and are the recommended approach for CI:

```bash
export GEMINI_API_KEY="..."
export OPENAI_API_KEY="..."
export ANTHROPIC_API_KEY="..."
export GROQ_API_KEY="..."
export DEEPSEEK_API_KEY="..."
export OPENROUTER_API_KEY="..."
export MISTRAL_API_KEY="..."
export TOGETHER_API_KEY="..."
```

### Local Ollama

```bash
ollama serve
ollama pull llama3.1
hackit agent setting --provider ollama
```

The agent detects `http://127.0.0.1:11434` automatically, lists installed
models and selects a sensible default. Override the endpoint with
`OLLAMA_HOST` or `HACKIT_OLLAMA_HOST`. Both `http://host:port` and `host:port`
forms are accepted.

Local models can be slower than cloud APIs. The agent automatically applies a
300-second floor for Ollama and a 120-second default for hosted providers.
Override either with:

```bash
export HACKIT_AI_TIMEOUT=600
```

Reasoning models such as Qwen3 expose a separate thinking channel. HackIt
requests it (`think:true`) and renders it in the `THINKING` panel, while the
final answer and persisted memory receive only `message.content`. The same
separation is applied to OpenAI-compatible `reasoning_content`, Claude
`thinking_delta` and Gemini thought parts. Force a single-channel response with
`HACKIT_OLLAMA_THINK=off` (or the engine flag `-think off`) if a local model is
too slow; `-think auto` is the default and enables thinking only when the model
reports the capability.

---

## Supported providers

| Provider | Environment variables | Default model |
| --- | --- | --- |
| Google Gemini | `GEMINI_API_KEY`, `GOOGLE_API_KEY` | `gemini-2.5-flash` |
| Groq | `GROQ_API_KEY` | `llama-3.3-70b-versatile` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4o-mini` |
| Anthropic Claude | `ANTHROPIC_API_KEY`, `CLAUDE_API_KEY` | `claude-sonnet-4-20250514` |
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| OpenRouter | `OPENROUTER_API_KEY` | `google/gemini-2.5-flash:free` |
| Mistral | `MISTRAL_API_KEY` | `mistral-small-latest` |
| Together AI | `TOGETHER_API_KEY`, `TOGETHERAI_API_KEY` | `meta-llama/Llama-3.3-70B-Instruct-Turbo` |
| Ollama | none (local) | first installed model |

Every provider supports the same features: chat, streaming, payload
generation, scan analysis and the autonomous workflow. Provider-specific model
fallbacks are applied when a model name is retired or unavailable.

---

## Commands

```text
hackit agent chat                 interactive Chat / Autopilot UI
hackit agent auto <target>        full autonomous pipeline
hackit agent payload <type>       forge payloads with the active provider
hackit agent probe <type> <url>   authorised payload verification
hackit agent osint <query>        username, e-mail or domain footprint
hackit agent models [provider]    curated + live model discovery
hackit agent doctor               keys, latency, models and Ollama diagnostics
hackit agent status               compact configuration summary
hackit agent memory               show or manage long-term memory
hackit agent swarm <target>       launch the 28-node swarm
hackit agent dashboard <target>   real-time swarm TUI
hackit agent setting              configure provider, key and model
hackit agent reset                erase keys, provider, models or history
```

### Slash commands inside `agent chat`

| Command | Purpose |
| --- | --- |
| `/help` | command palette |
| `/status`, `/provider`, `/model` | inspect or switch AI configuration |
| `/payload <type> [context]` | generate payloads for `sqli`, `xss`, `ssrf`, `lfi`, `ssti`, `cmdi`, `open_redirect`, ... |
| `/probe <type> <url> [--param name]` | send generated payloads (requires `HACKIT_AUTHORIZED=1`) |
| `/scan <url>` / `/auto <target>` | run the scanner or the full pipeline |
| `/osint <query>` | OSINT footprint |
| `/memory`, `/forget`, `/export` | memory management |
| `/report` | generate a report from the current run |
| `/clear` | clear the screen and conversation |

Any input that is not a registered command is sent to the AI as natural
language. Unknown `/word` input is also treated as a question — the engine does
not mistake it for a mode.

---

## Autonomous pipeline

`hackit agent auto <target>` runs the same pipeline exposed by
`hackit/agent/workflow`:

```text
recon → OSINT → JavaScript → parameters → payload forge → AI analysis
      → attack plan → active verification → correlation → report
```

* **recon** — port scan, subdomain enumeration, technology/WAF fingerprinting,
  header audit and directory fuzzing.
* **OSINT** — public profiles, breach references and domain registration data.
* **payload** — the active provider forges payloads for the vulnerability
  classes suggested by the collected context; curated payloads remain
  available if the model is offline or slow.
* **analysis / plan** — the provider correlates observations and proposes an
  ordered, evidence-based plan that names concrete endpoints and parameters.
* **active verification** — native modules run against the base URL, every
  same-origin endpoint found by the fuzzer/JS analysis, and URLs that exercise
  each discovered parameter. Generated payloads are then probed across all
  classes, targets and parameters. `HACKIT_MODULE_TASKS` (default `72`) and
  `HACKIT_PROBE_BUDGET` (default `60`) bound the work.
* **coverage / attack log** — every module task and payload probe is recorded
  with its target, parameter, result and evidence. Confirmed signals become
  findings; the report includes an Active Coverage section and an Attack Log.
* **report** — Markdown, HTML and Mermaid reports under
  `hackit/agent/go/reports/pentest/`.

Intermediate state is persisted in `~/.hackit/workflow_state/`, so a run can be
audited or resumed. If LangGraph is installed it is used as the state machine;
otherwise a dependency-free sequential runner executes the identical nodes.

### Authorization gate

`hackit agent auto <target>` and `/auto <target>` run in explicit authorized
active mode. They print an `AUTHORIZED` notice, execute attack modules against
discovered endpoints, and verify generated payloads. **Only use them against
systems you own or have explicit written permission to test.**

The standalone `/probe` command and legacy callers remain gated:

```bash
export HACKIT_AUTHORIZED=1
```

`run_pentest(..., authorized=False)` keeps the pipeline passive. Payload
generation and passive scanning modules do not require the flag.

---

## Memory

The memory layer stores a rolling conversation window and durable facts
(targets, domains, CVEs) in `~/.hackit/agent_memory/<session>.json`.

* With LangChain installed, the layer uses `ConversationBufferWindowMemory`
  (0.2–0.3) or a `langchain-core` message adapter (1.x, where the legacy class
  was removed).
* Without LangChain, a built-in JSON window provides the same behaviour with no
  extra dependencies.

Memory is injected into the system prompt on every turn, so the agent keeps
track of the current engagement across commands and terminal restarts. It is
explicitly labelled background context: the latest user request always takes
precedence, and benchmark/self-test artifacts (`HACKIT_UI_OK`, `STREAM_OK`,
`Reply with exactly ...`) are filtered on load, append and import. Reasoning
tokens are never written to memory.

---

## Chat UI

`hackit agent chat` and `hackit agent autopilot` open a full-screen terminal UI
built with prompt_toolkit and Rich. It provides:

* a live transcript with separate `THINKING` and `HACKIT` answer panels, so
  reasoning never mixes with the final response,
* a framed composer and navigable `/` command palette (`Up`/`Down` selects,
  `Enter` accepts, `Tab` completes, `Esc` closes; `Ctrl+P` opens it),
* a session sidebar with provider, model, memory, target and workflow engine,
* structured `SCAN`, `OSINT` and `AUTONOMOUS PENTEST` panels with per-module
  status, progress, coverage, findings tables and final summaries instead of
  raw logs,
* real token streaming from the Go engines (SSE for OpenAI-compatible, Gemini
  and Claude; NDJSON for Ollama),
* a scrollable transcript with a scrollbar: mouse wheel, `PageUp`/`PageDown`,
  `Ctrl+Up`/`Ctrl+Down` and `Ctrl+Home`/`Ctrl+End`. Output follows the tail
  until you scroll up and resumes following when you return to the bottom,
* a frozen/live transcript cache, capped streaming previews and batched tokens,
  so long reasoning traces and long conversations do not re-render the whole
  transcript for every token,
* one accent colour per mode, Markdown rendering and a plain-text fallback,
* `Ctrl+C` cancellation of generation and running scan/pipeline subprocesses;
  partial streamed output is discarded.

The full-screen renderer requires a TTY, a non-dumb `TERM`, at least 72 columns
and 18 rows, plus prompt_toolkit and Rich. Otherwise, or when
`HACKIT_INLINE=1` is set, the same commands run in the inline renderer. If
prompt_toolkit itself is missing, input falls back to standard `input()` without
losing any functionality.

---

## Architecture

```text
hackit/agent/
├── __init__.py        Click commands and shell dispatch
├── brain.py           Python ↔ Go bridge, provider fallback, streaming
├── providers.py       provider registry, keys, models, doctor
├── payloads.py        curated + AI payload forging and probing
├── memory.py          LangChain-optional conversation memory
├── interactive.py     command controller, inline UI and UI selection
├── tui.py             full-screen prompt_toolkit renderer and palette
├── dashboard.py       real-time swarm TUI
├── workflow/
│   ├── __init__.py    LangGraph or built-in sequential runner
│   ├── nodes.py       recon, OSINT, payload, analysis, execute, report
│   ├── state.py       typed state and persistence
│   └── tools.py       GoBridge (worker, hative, AI engine)
└── go/
    ├── main.go        native AI engine
    ├── chat_go/       streaming chat engine
    ├── worker/        parallel native scanner modules
    ├── hative/        full scanner and report generator
    ├── native/        scanner implementations
    ├── swarm/         28-node autonomous swarm
    └── build.sh       build every binary
```

The Python layer owns configuration, prompts, memory and orchestration. The Go
layer owns network scanning, concurrency and streaming. JSON on stdout is the
contract; diagnostics are written to stderr so callers can always parse output.

---

## Troubleshooting

**`No AI provider is configured`**
Run `hackit agent doctor`. If a key is set only in the environment, export it
in the same shell that launches HackIt.

**`HTTP 401/403` from a provider**
The key is invalid, revoked or lacks access to the selected model. `doctor`
prints the provider message without truncating the relevant detail.

**Ollama is online but chat fails**
Check that a model is installed (`ollama list`) and that `OLLAMA_HOST` points
to the running instance. The agent auto-selects the first installed model when
no model is configured.

**Scanners return no findings**
That is expected for hardened targets. The native scanners compare against a
baseline and require database-specific errors, reproducible delays, confirmed
boolean differentials or internal-service content. A generic HTTP 200 or 500 is
never reported as a vulnerability.

**The AI report mentions a vulnerability that was not found**
Only the findings table and verified probe hits count as evidence. AI narrative
sections are labelled `narrative, not evidence`, and unsupported confirmation
language is rewritten deterministically. Re-run the relevant probe with
`HACKIT_AUTHORIZED=1` to turn a hypothesis into evidence.

**Go binary not found**
Run `bash hackit/agent/go/build.sh` from the repository root. The bridge falls
back from `worker` to `hative` where possible, but the AI engines must exist.

**LangChain is not detected**
Install the optional extra: `pip install -e ".[agent,graph]"`. The built-in
memory and workflow remain fully functional without it.

---

## Development

```bash
# Python syntax check
python3 -m py_compile hackit/agent/*.py hackit/agent/workflow/*.py

# Go build and vet
cd hackit/agent/go && go build ./... && go vet ./...
cd hackit/agent/go/chat_go && go build ./... && go vet ./...

# rebuild all binaries
bash hackit/agent/go/build.sh
```

Please test active features only against systems you own or are explicitly
authorised to assess.
