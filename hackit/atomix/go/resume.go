package main

// Resume checkpointing (-resume <file>). Each line records
// "<target>\x01<template-id>" for a completed (target, template) pair.
// On startup the file is replayed; pairs already present are skipped.
// Appends use O_APPEND so a crash mid-write loses at most the last line.

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

type ResumeTracker struct {
	path string
	f    *os.File
	seen map[string]struct{}
	mu   sync.Mutex
}

func resumeKey(target, templateID string) string {
	return sanitizeResumeField(target) + "\x01" + sanitizeResumeField(templateID)
}

func sanitizeResumeField(s string) string {
	return strings.NewReplacer("\x00", " ", "\x01", " ", "\n", " ", "\r", " ").Replace(s)
}

// NewResumeTracker loads (or creates) the checkpoint file at path.
func NewResumeTracker(path string) (*ResumeTracker, error) {
	if path == "" {
		return nil, nil
	}
	seen := make(map[string]struct{})
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "\x01", 2)
			if len(parts) == 2 {
				seen[resumeKey(parts[0], parts[1])] = struct{}{}
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("resume file: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("resume file: %w", err)
	}
	return &ResumeTracker{path: path, f: f, seen: seen}, nil
}

// Done reports whether (target, templateID) already completed.
func (r *ResumeTracker) Done(target, templateID string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.seen[resumeKey(target, templateID)]
	return ok
}

// Mark records a completed pair and appends it to the checkpoint.
func (r *ResumeTracker) Mark(target, templateID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen[resumeKey(target, templateID)] = struct{}{}
	fmt.Fprintf(r.f, "%s\n", resumeKey(target, templateID))
}

// Close flushes and closes the checkpoint file.
func (r *ResumeTracker) Close() {
	if r == nil || r.f == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.f.Close()
}
