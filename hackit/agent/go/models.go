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

type GeminiRequest struct {
	Contents []struct {
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	} `json:"contents"`
}

type OpenAIRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

type ClaudeRequest struct {
	Model    string `json:"model"`
	System   string `json:"system"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	MaxTokens int `json:"max_tokens"`
}
