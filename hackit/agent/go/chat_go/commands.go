package main

import "fmt"

var CommandMap = map[string]string{
	"code":       "Generate production-ready code with clear explanation. Use ```language blocks. Include imports, error handling, input validation, and a usage example. Prefer modern idiomatic syntax.",
	"debug":      "Debug the provided code or error message. Identify root cause logically, suggest minimal fix with code example, and explain why the bug occurred. Check for off-by-one, nil/None, type mismatches.",
	"explain":    "Explain the given concept in simple intuitive terms. Use analogies. Break complex ideas into digestible parts. Start from basics even for intermediate topics.",
	"translate":  "Translate the provided text to the target language. Preserve tone, context, idioms, and cultural nuances. Output both original and translation side by side.",
	"write":      "Write creative engaging content in the requested format (story, poem, email, article, tweet, script). Match tone (formal, casual, persuasive) to the audience.",
	"summarize":  "Summarize concisely. Extract key points, main arguments, and conclusions in 3-5 bullet points. Use bold for key terms. Omit fluff and examples.",
	"math":       "Solve the math problem step by step. Show formulas, intermediate calculations, unit conversions, and final answer. Verify reasonableness of result.",
	"research":   "Provide thorough well-structured analysis. Cover history, current state, key players, statistics, competing approaches, and future outlook. Cite sources where known.",
	"review":     "Review code for bugs, security vulnerabilities, race conditions, memory leaks, style issues, and performance problems. Rate reliability 1-10. Be specific with line-level feedback.",
	"refactor":   "Refactor the provided code. Improve readability, performance, security, and maintainability. Show before/after with explanation for each change. Prefer standard library over dependencies.",
	"test":       "Generate comprehensive unit tests. Include happy path, edge cases (empty input, boundaries, null/None), error paths, and property-based assertions. Use the project's existing test framework.",
	"diagram":    "Generate a Mermaid.js diagram. Output valid mermaid code inside ```mermaid blocks. Choose the right diagram type (flowchart, sequence, class, mindmap) for the concept.",
	"learn":      "Teach step by step from basics. Use scaffolding — build on previous concepts. Include code examples, checkpoints, and a mini-exercise. Adapt pace to complexity.",
	"quick":      "Give a very concise direct answer. One paragraph max, 1-3 sentences preferred. Bold key terms. No preamble like 'Sure!' or 'Here is...'. Just the answer.",
	"detail":     "Give a comprehensive detailed answer. Use sections (##), examples, comparisons, references. Cover theory, practice, trade-offs, and advanced considerations.",
	"search":     "Search the web for current information. Summarize findings with key statistics, dates, sources, and conflicting viewpoints if any. Note recency of information.",
	"plan":       "Create a detailed step-by-step plan. Include phases, timeline estimates, required resources/dependencies, deliverables, success criteria, and risk factors.",
	"compare":    "Compare and contrast the given items. Use a structured format: overview table, similarities list, differences analysis, pros/cons per item, then recommendation.",
	"analyze":    "Perform deep analysis. Identify patterns, trends, anomalies, correlations, and actionable insights. Support conclusions with evidence from the data provided.",
}

func GetCommandInstruction(cmd string) string {
	if desc, ok := CommandMap[cmd]; ok {
		return fmt.Sprintf("\n[Command: /%s]\nInstruction: %s\nAdapt your response to fulfill this instruction precisely.", cmd, desc)
	}
	return ""
}
