package main

import (
	"math/rand"
	"time"
)

func shufflePorts(in []int) []int {
	out := make([]int, len(in))
	copy(out, in)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// jitterSleep is now defined in engine.go — removed from here to avoid redeclaration
