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

func jitterSleep(minMs, maxMs int) {
	if maxMs <= minMs {
		maxMs = minMs + 1
	}
	d := rand.Intn(maxMs-minMs) + minMs
	time.Sleep(time.Duration(d) * time.Millisecond)
}
