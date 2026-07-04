# HackIT AI — 170-Todo Deep Improvement Plan

## CHAT (10)
- [ ] 1. Stream AI response token-by-token (real-time output, not batch)
- [ ] 2. Syntax highlighting for code blocks in responses
- [ ] 3. Conversation export to Markdown / JSON / PDF
- [ ] 4. Multi-turn context with token-aware sliding window
- [ ] 5. Quick-action buttons for common /commands
- [ ] 6. Response word-wrap with proper indentation preservation
- [ ] 7. Search/filter within conversation history
- [ ] 8. System prompt customization per session
- [ ] 9. Response streaming progress bar (token count / ETA)
- [ ] 10. Multi-language code block label rendering

## SWARM (12)
- [ ] 11. Real-time sub-agent progress streaming to CLI
- [ ] 12. DAG visualization of agent dependencies
- [ ] 13. Agent crash recovery with state checkpointing
- [ ] 14. Distributed agent execution across workers
- [ ] 15. Agent heartbeat + timeout detection
- [ ] 16. Priority-based task scheduling across agents
- [ ] 17. Inter-agent message deduplication
- [ ] 18. Swarm output aggregation with conflict resolution
- [ ] 19. Agent resource usage tracking (CPU/mem per agent)
- [ ] 20. Swarm dry-run mode (plan only, no execution)
- [ ] 21. Agent warm-pool for latency reduction
- [ ] 22. Swarm result correlation with CVSS scoring

## HATIVE (20)
- [ ] 23. REST API mode (HTTP server, not just CLI)
- [ ] 24. WebSocket live progress streaming
- [ ] 25. Module dependency graph (DAG execution order)
- [ ] 26. Incremental scans (skip completed modules via cache)
- [ ] 27. Scan profile system (quick / full / stealth / custom)
- [ ] 28. Target list file (batch scan multiple targets)
- [ ] 29. Output formats: SARIF, JSON, CSV, HTML, PDF
- [ ] 30. Module hot-swap (enable/disable at runtime)
- [ ] 31. Scan pause/resume with state serialization
- [ ] 32. Rate limiting (requests/sec per module)
- [ ] 33. Proxy chain support (HTTP/SOCKS5 per module)
- [ ] 34. Custom payload injection per module
- [ ] 35. Module chaining (pipe output of one to another)
- [ ] 36. Interactive mode (TUI inside hative itself)
- [ ] 37. Machine-readable exit codes (JSON error codes)
- [ ] 38. Plugin system (load external .so modules)
- [ ] 39. Memory-mapped result sharing between modules
- [ ] 40. Health check endpoint for monitoring
- [ ] 41. Scan scheduling (cron-like recurring scans)
- [ ] 42. Cloud storage sync (S3/GCS for scan artifacts)

## NATIVE (25)
- [ ] 43. **CORS** — misconfiguration testing module
- [ ] 44. **CSRF** — anti-CSRF token validation module
- [ ] 45. **LFI** — local file inclusion testing
- [ ] 46. **SSTI** — server-side template injection testing
- [ ] 47. **XXE** — XML external entity injection testing
- [ ] 48. **CMD Injection** — OS command injection testing
- [ ] 49. **LDAP** — LDAP injection testing
- [ ] 50. **NoSQLi** — NoSQL injection (MongoDB, etc.)
- [ ] 51. **JWT** — JWT token weakness scanner (alg=none, weak keys)
- [ ] 52. **GraphQL** — introspection + injection testing
- [ ] 53. **WebSocket** — WS endpoint discovery + fuzzing
- [ ] 54. **gRPC** — gRPC reflection + method fuzzing
- [ ] 55. **Race Condition** — TOCTOU race detection
- [ ] 56. **Deserialization** — insecure deserialization (Java/PHP/Python)
- [ ] 57. **IDOR** — insecure direct object reference scanner
- [ ] 58. **Mass Assignment** — parameter pollution testing
- [ ] 59. **Open Redirect** — comprehensive redirect validation
- [ ] 60. **CRLF Injection** — HTTP response splitting
- [ ] 61. **Server-Side Request Forgery** — blind SSRF + callback
- [ ] 62. **Prototype Pollution** — client-side pollution detection
- [ ] 63. **Web Cache Poisoning** — cache key manipulation
- [ ] 64. **HTTP Request Smuggling** — CL.TE/TE.CL detection
- [ ] 65. **API Fuzzer** — OpenAPI/Swagger-based endpoint fuzzing
- [ ] 66. **OAuth** — OAuth flow misconfiguration scanner
- [ ] 67. **Cloud Metadata** — cloud provider metadata exposure

## AI ENGINE (15)
- [ ] 68. Provider auto-fallback chain with latency ranking
- [ ] 69. Response caching (semantic cache for repeated queries)
- [ ] 70. Streaming support in Go engine (SSE/WebSocket)
- [ ] 71. Token budget enforcement per conversation turn
- [ ] 72. Multi-modal input support (image + text analysis)
- [ ] 73. Custom system prompt template system
- [ ] 74. Structured output mode (JSON schema enforcement)
- [ ] 75. Provider cost tracking and budget alerts
- [ ] 76. Prompt injection detection and filtering
- [ ] 77. Context compression (summarize old turns to save tokens)
- [ ] 78. Parallel provider query with best-response selection
- [ ] 79. Response validation (check for hallucination patterns)
- [ ] 80. Local model integration via Ollama/llama.cpp
- [ ] 81. Function/tool calling support (let AI call hative modules)
- [ ] 82. Rate-limit aware retry with exponential backoff

## AGENT CLI (15)
- [ ] 83. Rich REPL with prompt_toolkit (multiline, syntax-highlighted input)
- [ ] 84. Session persistence (save/restore conversation)
- [ ] 85. Multi-session tabs (switch between conversations)
- [ ] 86. File attachment support (/upload path/to/file)
- [ ] 87. Pipeline commands (chain multiple /commands)
- [ ] 88. Output redirect to file (/output results.txt)
- [ ] 89. Context injection (/context add "additional info")
- [ ] 90. Command aliases (user-defined shortcuts)
- [ ] 91. Batch mode (script file with commands)
- [ ] 92. Notification on long-running task completion (bell/desktop)
- [ ] 93. Progress bar for AI response chunks
- [ ] 94. AI response diff view (compare two responses)
- [ ] 95. Theme customization (custom color schemes)
- [ ] 96. Plugin commands (third-party extensions)
- [ ] 97. Accessibility mode (screen-reader friendly output)

## LANGGRAPH (15)
- [ ] 98. Parallel node execution for independent phases
- [ ] 99. Dynamic routing (skip nodes based on previous results)
- [ ] 100. Human-in-the-loop approval gates per phase
- [ ] 101. Graph state persistence to disk (crash recovery)
- [ ] 102. Visual graph export (Mermaid/Graphviz of execution)
- [ ] 103. Conditional branching (if vuln found → deep dive)
- [ ] 104. Sub-graphs for complex modules (recursive analysis)
- [ ] 105. Execution trace log for debugging
- [ ] 106. Result deduplication across nodes
- [ ] 107. Time-boxed execution per node (max duration)
- [ ] 108. Retry with different strategy on failure
- [ ] 109. Node dependency validation (pre-flight check)
- [ ] 110. Incremental graph execution (resume from last node)
- [ ] 111. Graph metrics (node duration, data size, error rate)
- [ ] 112. Graph template system (reusable workflow patterns)

## UI/UX (15)
- [ ] 113. Image rendering in terminal (Sixel/Kitty protocol)
- [ ] 114. Link click detection for URLs in responses
- [ ] 115. Collapsible sections for long outputs
- [ ] 116. Message search with highlighting
- [ ] 117. Emoji picker for input (full Unicode support)
- [ ] 118. Split-pane view (input on left, output on right)
- [ ] 119. Mouse support (click to select, scroll navigation)
- [ ] 120. Typing indicator animation (smoother, GPU-accelerated)
- [ ] 121. Low-battery/energy-saver mode (reduce frame rate)
- [ ] 122. High-contrast mode for accessibility
- [ ] 123. Unicode vs. ASCII fallback (detect terminal support)
- [ ] 124. Customizable keybindings (vi/emacs mode)
- [ ] 125. Message timestamp display
- [ ] 126. Conversation search across sessions
- [ ] 127. Inline file preview (images as ASCII art)

## REPORT (10)
- [ ] 128. PDF report generation with charts (go/pdf library)
- [ ] 129. Executive summary page (non-technical overview)
- [ ] 130. CVSS v3.1 vector calculation per finding
- [ ] 131. Remediation timeline (effort estimate per fix)
- [ ] 132. Exploit PoC generation for confirmed vulns
- [ ] 133. Compliance mapping (OWASP Top 10, PCI-DSS, HIPAA)
- [ ] 134. Custom report branding (logo, colors, footer)
- [ ] 135. Report diff between scans (regression detection)
- [ ] 136. Automated email delivery of reports
- [ ] 137. Report API (programmatic report generation)

## BRIDGE (10)
- [ ] 138. gRPC bridge for Go↔Python (instead of subprocess)
- [ ] 139. Shared memory for large data transfer
- [ ] 140. Binary protocol (Protocol Buffers) for IPC
- [ ] 141. Bridge health monitoring (heartbeat + latency)
- [ ] 142. Bi-directional streaming (Python + Go push events)
- [ ] 143. Bridge authentication (mutual TLS)
- [ ] 144. Connection pooling for parallel requests
- [ ] 145. Request timeout handling with graceful degradation
- [ ] 146. Bridge metrics (requests/sec, latency percentiles)
- [ ] 147. Zero-downtime bridge restart

## CLI (10)
- [ ] 148. `hackit init` — project scaffolding
- [ ] 149. `hackit scan --profile quick` — preset profiles
- [ ] 150. `hackit schedule` — cron-based recurring scans
- [ ] 151. `hackit export --format sarif` — SARIF output
- [ ] 152. `hackit compare <scan1> <scan2>` — diff scans
- [ ] 153. `hackit dashboard` — web-based real-time dashboard
- [ ] 154. `hackit plugin install <name>` — plugin management
- [ ] 155. `hackit self-update` — auto-update binary
- [ ] 156. `hackit config validate` — config file validation
- [ ] 157. `hackit stats` — usage statistics and telemetry

## CONFIG (8)
- [ ] 158. YAML/JSON config file with schema validation
- [ ] 159. Environment variable auto-discovery
- [ ] 160. Per-scan config overrides
- [ ] 161. Secret management (encrypted API key storage)
- [ ] 162. Config inheritance (base + override layers)
- [ ] 163. Dynamic config reload without restart
- [ ] 164. Config diff between environments
- [ ] 165. Provider health auto-config (ping before use)

## PERFORMANCE (5)
- [ ] 166. Module result caching with TTL (avoid duplicate scans)
- [ ] 167. Lazy module loading (only import when used)
- [ ] 168. Concurrent result processing pipeline
- [ ] 169. Memory-mapped result files for large scans
- [ ] 170. Adaptive parallelism (auto-tune concurrency)

---

**Total: 170 todo items**
