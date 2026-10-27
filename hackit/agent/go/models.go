package main

type AIRequest struct {
	Provider     string `json:"provider"`
	APIKey       string `json:"api_key"`
	Prompt       string `json:"prompt"`
	SystemPrompt string `json:"system_prompt"`
	Model        string `json:"model"`
}

type AIResponse struct {
	Text  string `json:"text"`
	Error string `json:"error"`
}

type TokenEvent struct {
	Token string `json:"token,omitempty"`
	Done  bool   `json:"done,omitempty"`
	Error string `json:"error,omitempty"`
}

type GeminiPart struct {
	Text string `json:"text"`
}

type GeminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []GeminiPart `json:"parts"`
}

type GeminiGenerationConfig struct {
	Temperature     float64 `json:"temperature,omitempty"`
	MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
}

type GeminiRequest struct {
	Contents          []GeminiContent         `json:"contents"`
	SystemInstruction *GeminiContent          `json:"systemInstruction,omitempty"`
	GenerationConfig  *GeminiGenerationConfig `json:"generationConfig,omitempty"`
}

type GeminiResponse struct {
	Candidates []struct {
		Content GeminiContent `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type OpenAIRequest struct {
	Model       string    `json:"model"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
	Stream      bool      `json:"stream,omitempty"`
}

type ClaudeRequest struct {
	Model     string    `json:"model"`
	System    string    `json:"system,omitempty"`
	Messages  []Message `json:"messages"`
	MaxTokens int       `json:"max_tokens"`
	Stream    bool      `json:"stream,omitempty"`
}

type OllamaRequest struct {
	Model    string                 `json:"model"`
	Messages []Message              `json:"messages"`
	Stream   bool                   `json:"stream"`
	Format   string                 `json:"format,omitempty"`
	Think    *bool                  `json:"think,omitempty"`
	Options  map[string]interface{} `json:"options,omitempty"`
}

type OllamaResponse struct {
	Message Message `json:"message"`
	Done    bool    `json:"done"`
	Error   string  `json:"error,omitempty"`
}
