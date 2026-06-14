package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Notifier struct {
	WebhookURL  string
	Format      string
	SlackURL    string
	TelegramBot string
	TelegramChat string
	Client      *http.Client
}

func NewNotifier(config *ScanConfig) *Notifier {
	return &Notifier{
		WebhookURL:  config.Push,
		Format:      config.PushFormat,
		SlackURL:    config.SlackWebhook,
		TelegramBot: config.TelegramBot,
		TelegramChat: config.TelegramChat,
		Client:     NewHTTPClient(10),
	}
}

func (n *Notifier) Send(results []Result) {
	if n == nil { return }
	if len(results) == 0 { return }

	if n.WebhookURL != "" {
		n.sendWebhook(results)
	}
	if n.SlackURL != "" {
		n.sendSlack(results)
	}
	if n.TelegramBot != "" && n.TelegramChat != "" {
		n.sendTelegram(results)
	}
}

func (n *Notifier) sendWebhook(results []Result) {
	var payload []byte
	switch n.Format {
	case "slack":
		payload, _ = json.Marshal(map[string]interface{}{
			"text": formatSlackMessage(results),
		})
	case "telegram":
		payload, _ = json.Marshal(map[string]string{
			"text": formatTelegramMessage(results),
		})
	default:
		payload, _ = json.Marshal(results)
	}
	http.Post(n.WebhookURL, "application/json", bytes.NewReader(payload))
}

func (n *Notifier) sendSlack(results []Result) {
	msg := map[string]interface{}{
		"text": formatSlackMessage(results),
	}
	payload, _ := json.Marshal(msg)
	http.Post(n.SlackURL, "application/json", bytes.NewReader(payload))
}

func (n *Notifier) sendTelegram(results []Result) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.TelegramBot)
	msg := map[string]string{
		"chat_id": n.TelegramChat,
		"text":    formatTelegramMessage(results),
	}
	payload, _ := json.Marshal(msg)
	http.Post(url, "application/json", bytes.NewReader(payload))
}

func formatSlackMessage(results []Result) string {
	var b strings.Builder
	b.WriteString("*Atomix Scan Results*\n")
	for _, r := range results {
		b.WriteString(fmt.Sprintf("• [%s] %s - %s (%s)\n",
			strings.ToUpper(r.Severity), r.URL, r.TemplateName, r.MatcherName))
	}
	return b.String()
}

func formatTelegramMessage(results []Result) string {
	var b strings.Builder
	b.WriteString("🔍 *Atomix Scan Results*\n\n")
	for _, r := range results {
		b.WriteString(fmt.Sprintf("• *%s*: %s\n  `%s` (%s)\n\n",
			strings.ToUpper(r.Severity), r.URL, r.TemplateName, r.MatcherName))
	}
	return b.String()
}
