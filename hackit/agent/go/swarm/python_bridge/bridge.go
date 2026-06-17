package python_bridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const pythonAIProvider = "ollama"
const pythonAIModel = "llama3"

type AIRequest struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Prompt   string `json:"prompt"`
	System   string `json:"system"`
}

type AIResponse struct {
	Text  string `json:"text"`
	Error string `json:"error"`
}

func CallAI(prompt, system string) (string, error) {
	enginePath := findAIEngine()
	if enginePath != "" {
		return callGoAI(enginePath, prompt, system)
	}
	return callOllamaDirect(prompt, system)
}

func callGoAI(enginePath, prompt, system string) (string, error) {
	cmd := exec.Command(enginePath,
		"-provider", pythonAIProvider,
		"-key", "AUTO_DETECT",
		"-prompt", prompt,
		"-system", system,
		"-model", pythonAIModel,
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("go ai engine: %w - %s", err, strings.TrimSpace(out.String()))
	}
	var resp AIResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		return "", fmt.Errorf("parse response: %w - raw: %s", err, out.String()[:min(200, out.Len())])
	}
	if resp.Error != "" {
		return "", fmt.Errorf("ai error: %s", resp.Error)
	}
	return resp.Text, nil
}

func callOllamaDirect(prompt, system string) (string, error) {
	url := "http://localhost:11434/api/generate"
	body := map[string]interface{}{
		"model":  pythonAIModel,
		"prompt": system + "\n\n" + prompt,
		"stream": false,
	}
	data, _ := json.Marshal(body)
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return "", fmt.Errorf("ollama direct: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if errText, ok := result["error"].(string); ok && errText != "" {
		return "", fmt.Errorf("ollama error: %s", errText)
	}
	text, _ := result["response"].(string)
	return text, nil
}

func CallPythonScript(scriptPath string, args ...string) (string, error) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
		if err != nil {
			return "", fmt.Errorf("python not found")
		}
	}
	cmd := exec.Command(python, append([]string{scriptPath}, args...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("python script: %w - %s", err, strings.TrimSpace(out.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

func findAIEngine() string {
	dirs := []string{
		".",
		filepath.Join(".."),
		filepath.Join("..", ".."),
	}
	base := os.Getenv("HACKIT_DIR")
	if base != "" {
		dirs = append([]string{filepath.Join(base, "hackit", "agent", "go")}, dirs...)
	}
	for _, d := range dirs {
		path := filepath.Join(d, "ai_engine")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func AnalyzeWithAI(agentName string, prompt string) (string, error) {
	system := fmt.Sprintf(`You are %s, a specialized cybersecurity AI agent in the HackIT autonomous swarm. 
Respond concisely with technical analysis only. No markdown formatting.`, agentName)
	return CallAI(prompt, system)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
