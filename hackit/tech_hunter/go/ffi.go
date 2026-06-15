package main

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var ffiMutex sync.Mutex

type procCaller interface {
	Call(args ...uintptr) (uintptr, uintptr, error)
}

func goString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	const maxLen = 5000000
	sl := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), maxLen)
	end := 0
	for end < maxLen && sl[end] != 0 {
		end++
	}
	return string(sl[:end])
}

func runCmdTimeout(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

func runRuby(script string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fullArgs := append([]string{script}, args...)
	cmd := exec.CommandContext(ctx, "ruby", fullArgs...)
	return cmd.Output()
}

func runRubyStdin(script string, stdinData string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ruby", script)
	cmd.Stdin = strings.NewReader(stdinData)
	return cmd.Output()
}

func runLua(script string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	fullArgs := append([]string{script}, args...)
	cmd := exec.CommandContext(ctx, "lua", fullArgs...)
	return cmd.Output()
}
