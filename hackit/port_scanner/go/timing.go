package main

import (
	"fmt"
	"time"
)

// TimingTemplate represents Nmap-style timing templates (T0-T5)
type TimingTemplate struct {
	Name           string
	Timeout        time.Duration
	MinRtt         time.Duration
	MaxRtt         time.Duration
	InitialRtt     time.Duration
	ScanDelay      time.Duration
	MaxScanDelay   time.Duration
	HostTimeout    time.Duration
	MinParallelism int
	MaxParallelism int
	MinRate        float64
	MaxRate        float64
	MaxRetries     int
	HostGroupSize  int
}

// TimingTemplates defines all Nmap timing templates
var TimingTemplates = map[int]TimingTemplate{
	0: {
		Name:           "Paranoid",
		Timeout:        15 * time.Minute,
		MinRtt:         100 * time.Millisecond,
		MaxRtt:         10 * time.Second,
		InitialRtt:     5 * time.Second,
		ScanDelay:      5 * time.Minute,
		MaxScanDelay:   10 * time.Minute,
		HostTimeout:    15 * time.Minute,
		MinParallelism: 1,
		MaxParallelism: 1,
		MinRate:        0.15,
		MaxRate:        0.3,
		MaxRetries:     10,
		HostGroupSize:  1,
	},
	1: {
		Name:           "Sneaky",
		Timeout:        15 * time.Second,
		MinRtt:         100 * time.Millisecond,
		MaxRtt:         10 * time.Second,
		InitialRtt:     2 * time.Second,
		ScanDelay:      15 * time.Second,
		MaxScanDelay:   30 * time.Second,
		HostTimeout:    15 * time.Minute,
		MinParallelism: 1,
		MaxParallelism: 2,
		MinRate:        0.5,
		MaxRate:        1.0,
		MaxRetries:     10,
		HostGroupSize:  1,
	},
	2: {
		Name:           "Polite",
		Timeout:        1 * time.Second,
		MinRtt:         50 * time.Millisecond,
		MaxRtt:         5 * time.Second,
		InitialRtt:     1 * time.Second,
		ScanDelay:      400 * time.Millisecond,
		MaxScanDelay:   2 * time.Second,
		HostTimeout:    10 * time.Minute,
		MinParallelism: 2,
		MaxParallelism: 5,
		MinRate:        1.0,
		MaxRate:        3.0,
		MaxRetries:     6,
		HostGroupSize:  5,
	},
	3: {
		Name:           "Normal",
		Timeout:        1 * time.Second,
		MinRtt:         50 * time.Millisecond,
		MaxRtt:         2 * time.Second,
		InitialRtt:     500 * time.Millisecond,
		ScanDelay:      0,
		MaxScanDelay:   1 * time.Second,
		HostTimeout:    5 * time.Minute,
		MinParallelism: 5,
		MaxParallelism: 10,
		MinRate:        3.0,
		MaxRate:        7.0,
		MaxRetries:     3,
		HostGroupSize:  10,
	},
	4: {
		Name:           "Aggressive",
		Timeout:        500 * time.Millisecond,
		MinRtt:         50 * time.Millisecond,
		MaxRtt:         1 * time.Second,
		InitialRtt:     250 * time.Millisecond,
		ScanDelay:      0,
		MaxScanDelay:   500 * time.Millisecond,
		HostTimeout:    3 * time.Minute,
		MinParallelism: 10,
		MaxParallelism: 25,
		MinRate:        7.0,
		MaxRate:        15.0,
		MaxRetries:     2,
		HostGroupSize:  25,
	},
	5: {
		Name:           "Insane",
		Timeout:        200 * time.Millisecond,
		MinRtt:         50 * time.Millisecond,
		MaxRtt:         500 * time.Millisecond,
		InitialRtt:     100 * time.Millisecond,
		ScanDelay:      0,
		MaxScanDelay:   200 * time.Millisecond,
		HostTimeout:    1 * time.Minute,
		MinParallelism: 25,
		MaxParallelism: 100,
		MinRate:        15.0,
		MaxRate:        30.0,
		MaxRetries:     1,
		HostGroupSize:  50,
	},
}

// GetTimingTemplate returns the timing template for a given level (0-5)
func GetTimingTemplate(level int) TimingTemplate {
	if template, ok := TimingTemplates[level]; ok {
		return template
	}
	return TimingTemplates[3] // Default to Normal
}

// AdaptiveTiming adjusts timing based on network conditions
type AdaptiveTiming struct {
	Template       TimingTemplate
	CurrentRtt     time.Duration
	CurrentDelay   time.Duration
	SuccessRate    float64
	FailureCount   int
	SuccessCount   int
	LastAdjustment time.Time
}

// NewAdaptiveTiming creates a new adaptive timing controller
func NewAdaptiveTiming(template TimingTemplate) *AdaptiveTiming {
	return &AdaptiveTiming{
		Template:       template,
		CurrentRtt:     template.InitialRtt,
		CurrentDelay:   template.ScanDelay,
		LastAdjustment: time.Now(),
	}
}

// AdjustTiming adjusts timing based on network response
func (at *AdaptiveTiming) AdjustTiming(success bool, rtt time.Duration) {
	at.LastAdjustment = time.Now()

	if success {
		at.SuccessCount++
		at.CurrentRtt = rtt

		// If responses are fast, we can be more aggressive
		if rtt < at.Template.MinRtt {
			at.CurrentDelay = max(0, at.CurrentDelay-50*time.Millisecond)
		}
	} else {
		at.FailureCount++

		// If we're getting failures, slow down
		at.CurrentDelay = min(at.Template.MaxScanDelay, at.CurrentDelay+100*time.Millisecond)
	}

	// Calculate success rate
	total := at.SuccessCount + at.FailureCount
	if total > 0 {
		at.SuccessRate = float64(at.SuccessCount) / float64(total)
	}

	// Adjust based on success rate
	if at.SuccessRate < 0.5 && total > 10 {
		// Too many failures, slow down significantly
		at.CurrentDelay = min(at.Template.MaxScanDelay, at.CurrentDelay*2)
	} else if at.SuccessRate > 0.8 && total > 10 {
		// Good success rate, can speed up
		at.CurrentDelay = max(0, at.CurrentDelay/2)
	}
}

// GetRecommendedDelay returns the recommended delay for next probe
func (at *AdaptiveTiming) GetRecommendedDelay() time.Duration {
	return at.CurrentDelay
}

// GetRecommendedTimeout returns the recommended timeout
func (at *AdaptiveTiming) GetRecommendedTimeout() time.Duration {
	// Use the larger of current RTT and template timeout
	timeout := max(at.CurrentRtt*2, at.Template.Timeout)
	return min(timeout, at.Template.MaxRtt)
}

// GetRecommendedParallelism returns recommended parallelism level
func (at *AdaptiveTiming) GetRecommendedParallelism() int {
	// Adjust parallelism based on success rate
	if at.SuccessRate < 0.5 {
		return at.Template.MinParallelism
	} else if at.SuccessRate > 0.8 {
		return at.Template.MaxParallelism
	}
	return (at.Template.MinParallelism + at.Template.MaxParallelism) / 2
}

// CalculateRateLimit calculates packets per second based on timing
func (at *AdaptiveTiming) CalculateRateLimit() int {
	if at.CurrentDelay == 0 {
		return int(at.Template.MaxRate)
	}

	rate := float64(time.Second) / float64(at.CurrentDelay)
	return int(minFloat(rate, at.Template.MaxRate))
}

// ApplyJitter adds random jitter to timing to avoid detection
func ApplyJitter(duration time.Duration, jitterPercent float64) time.Duration {
	if jitterPercent <= 0 {
		return duration
	}

	jitter := duration * time.Duration(jitterPercent) / 100
	randomOffset := time.Duration(randIntn(int(jitter*2))) - jitter

	return duration + randomOffset
}

// SleepWithJitter sleeps with applied jitter
func SleepWithJitter(duration time.Duration, jitterPercent float64) {
	actualDuration := ApplyJitter(duration, jitterPercent)
	time.Sleep(actualDuration)
}

// Helper functions
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func max(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func randIntn(n int) int {
	// Simple random number generator
	return int(time.Now().UnixNano() % int64(n))
}

// GetTimingDescription returns a human-readable description of timing template
func GetTimingDescription(level int) string {
	template := GetTimingTemplate(level)
	return fmt.Sprintf("%s (T%d): Timeout=%v, Delay=%v, Parallelism=%d-%d",
		template.Name,
		level,
		template.Timeout,
		template.ScanDelay,
		template.MinParallelism,
		template.MaxParallelism,
	)
}
