package main

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

type ConfigFile struct {
	URL              string   `yaml:"url,omitempty"`
	TargetFile       string   `yaml:"target-file,omitempty"`
	TemplateDir      string   `yaml:"templates,omitempty"`
	Threads          int      `yaml:"threads,omitempty"`
	Concurrency      int      `yaml:"concurrency,omitempty"`
	Timeout          int      `yaml:"timeout,omitempty"`
	Severity         string   `yaml:"severity,omitempty"`
	Tags             string   `yaml:"tags,omitempty"`
	Proxy            string   `yaml:"proxy,omitempty"`
	OutputFile       string   `yaml:"output,omitempty"`
	JSON             bool     `yaml:"json,omitempty"`
	Silent           bool     `yaml:"silent,omitempty"`
	Verbose          bool     `yaml:"verbose,omitempty"`
	Debug            bool     `yaml:"debug,omitempty"`
	NoColor          bool     `yaml:"no-color,omitempty"`
	RateLimit        int      `yaml:"rate-limit,omitempty"`
	MaxRedirects     int      `yaml:"max-redirects,omitempty"`
	FollowRedirects  bool     `yaml:"follow-redirects,omitempty"`
	RandomAgent      bool     `yaml:"random-agent,omitempty"`
	CustomAgent      string   `yaml:"custom-agent,omitempty"`
	Headers          []string `yaml:"headers,omitempty"`
	Cookie           string   `yaml:"cookie,omitempty"`
	Resolvers        []string `yaml:"resolvers,omitempty"`
	DetectTech       bool     `yaml:"detect-tech,omitempty"`
	Interactsh       bool     `yaml:"interactsh,omitempty"`
	SmartScan        bool     `yaml:"smart-scan,omitempty"`
	WafSkip          bool     `yaml:"waf-skip,omitempty"`
	CustomTemplateDir string  `yaml:"custom-templates,omitempty"`
	Priority         bool     `yaml:"priority,omitempty"`
	APIDiscovery     bool     `yaml:"api-discovery,omitempty"`
	Analytics        bool     `yaml:"analytics,omitempty"`
}

func LoadConfigFile(path string) (*ConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) { return &ConfigFile{}, nil }
		return nil, err
	}
	var cfg ConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config parse error: %w", err)
	}
	return &cfg, nil
}

func LoadDefaultConfig() *ConfigFile {
	paths := []string{
		"~/.atomix/config.yaml",
		"~/.atomix/config.yml",
		".atomix.yaml",
		".atomix.yml",
		"atomix.yaml",
		"atomix.yml",
	}
	for _, p := range paths {
		expanded := expandPath(p)
		if _, err := os.Stat(expanded); err == nil {
			cfg, err := LoadConfigFile(expanded)
			if err == nil { return cfg }
		}
	}
	return &ConfigFile{}
}

func expandPath(path string) string {
	if len(path) > 1 && path[0] == '~' {
		home, _ := os.UserHomeDir()
		return home + path[1:]
	}
	return path
}

func MergeConfig(cfg *ScanConfig, fileCfg *ConfigFile) {
	if cfg.URL == "" && fileCfg.URL != "" { cfg.URL = fileCfg.URL }
	if cfg.TargetFile == "" && fileCfg.TargetFile != "" { cfg.TargetFile = fileCfg.TargetFile }
	if cfg.TemplateDir == "" && fileCfg.TemplateDir != "" { cfg.TemplateDir = fileCfg.TemplateDir }
	if cfg.Threads == 0 && fileCfg.Threads != 0 { cfg.Threads = fileCfg.Threads }
	if cfg.Concurrency == 0 && fileCfg.Concurrency != 0 { cfg.Concurrency = fileCfg.Concurrency }
	if cfg.Timeout == 0 && fileCfg.Timeout != 0 { cfg.Timeout = fileCfg.Timeout }
	if cfg.Severity == "" && fileCfg.Severity != "" { cfg.Severity = fileCfg.Severity }
	if cfg.Tags == "" && fileCfg.Tags != "" { cfg.Tags = fileCfg.Tags }
	if cfg.Proxy == "" && fileCfg.Proxy != "" { cfg.Proxy = fileCfg.Proxy }
	if cfg.OutputFile == "" && fileCfg.OutputFile != "" { cfg.OutputFile = fileCfg.OutputFile }
	if !cfg.JSON && fileCfg.JSON { cfg.JSON = true }
	if !cfg.Silent && fileCfg.Silent { cfg.Silent = true }
	if !cfg.Verbose && fileCfg.Verbose { cfg.Verbose = true }
	if !cfg.Debug && fileCfg.Debug { cfg.Debug = true }
	if !cfg.NoColor && fileCfg.NoColor { cfg.NoColor = true }
	if cfg.RateLimit == 0 && fileCfg.RateLimit != 0 { cfg.RateLimit = fileCfg.RateLimit }
	if cfg.MaxRedirects == 0 && fileCfg.MaxRedirects != 0 { cfg.MaxRedirects = fileCfg.MaxRedirects }
	if !cfg.FollowRedirects && fileCfg.FollowRedirects { cfg.FollowRedirects = true }
	if !cfg.RandomAgent && fileCfg.RandomAgent { cfg.RandomAgent = true }
	if cfg.CustomAgent == "" && fileCfg.CustomAgent != "" { cfg.CustomAgent = fileCfg.CustomAgent }
	if len(cfg.Header) == 0 && len(fileCfg.Headers) > 0 { cfg.Header = fileCfg.Headers }
	if cfg.Cookie == "" && fileCfg.Cookie != "" { cfg.Cookie = fileCfg.Cookie }
	if !cfg.DetectTech && fileCfg.DetectTech { cfg.DetectTech = true }
	if !cfg.Interactsh && fileCfg.Interactsh { cfg.Interactsh = true }
	if !cfg.SmartScan && fileCfg.SmartScan { cfg.SmartScan = true }
	if !cfg.WafSkip && fileCfg.WafSkip { cfg.WafSkip = true }
	if cfg.CustomTemplateDir == "" && fileCfg.CustomTemplateDir != "" { cfg.CustomTemplateDir = fileCfg.CustomTemplateDir }
	if !cfg.Analytics && fileCfg.Analytics { cfg.Analytics = true }
	if !cfg.Priority && fileCfg.Priority { cfg.Priority = true }
	if !cfg.APIDiscovery && fileCfg.APIDiscovery { cfg.APIDiscovery = true }
	if cfg.CustomTemplateDir == "" && fileCfg.CustomTemplateDir != "" { cfg.CustomTemplateDir = fileCfg.CustomTemplateDir }
}
