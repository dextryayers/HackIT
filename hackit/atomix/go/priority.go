package main

import (
	"sort"
)

type PriorityLevel int

const (
	PriorityCritical PriorityLevel = iota
	PriorityHigh
	PriorityMedium
	PriorityLow
	PriorityInfo
)

type PrioritizedTemplate struct {
	Template *Template
	Priority PriorityLevel
	Index    int
}

type PriorityQueue []*PrioritizedTemplate

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	return pq[i].Priority < pq[j].Priority
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].Index = i
	pq[j].Index = j
}

func (pq *PriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*PrioritizedTemplate)
	item.Index = n
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.Index = -1
	*pq = old[:n-1]
	return item
}

var severityToPriority = map[string]PriorityLevel{
	"critical": PriorityCritical,
	"high":     PriorityHigh,
	"medium":   PriorityMedium,
	"low":      PriorityLow,
	"info":     PriorityInfo,
}

func NewPrioritizedTemplate(t *Template) *PrioritizedTemplate {
	sev := t.Info.Severity
	prio, ok := severityToPriority[sev]
	if !ok { prio = PriorityInfo }
	return &PrioritizedTemplate{
		Template: t,
		Priority: prio,
	}
}

func PrioritizeTemplates(templates []*Template) []*Template {
	pt := make([]*PrioritizedTemplate, len(templates))
	for i, t := range templates {
		pt[i] = NewPrioritizedTemplate(t)
	}
	sort.Slice(pt, func(i, j int) bool {
		return pt[i].Priority < pt[j].Priority
	})
	result := make([]*Template, len(templates))
	for i, p := range pt {
		result[i] = p.Template
	}
	return result
}

type AdaptivePrioritizer struct {
	scores     map[string]float64
	runs       map[string]int
}

func NewAdaptivePrioritizer() *AdaptivePrioritizer {
	return &AdaptivePrioritizer{
		scores: make(map[string]float64),
		runs:   make(map[string]int),
	}
}

func (ap *AdaptivePrioritizer) RecordMatch(id string) {
	ap.runs[id]++
	ap.scores[id] += 1.0
}

func (ap *AdaptivePrioritizer) RecordMiss(id string) {
	ap.runs[id]++
	if ap.scores[id] > 0 {
		ap.scores[id] *= 0.9
	}
}

func (ap *AdaptivePrioritizer) GetScore(id string) float64 {
	return ap.scores[id]
}

func (ap *AdaptivePrioritizer) Prioritize(templates []*Template) []*Template {
	type scored struct {
		t     *Template
		score float64
	}
	scoredList := make([]scored, len(templates))
	for i, t := range templates {
		base := float64(0)
		baseSev := map[string]float64{
			"critical": 100, "high": 50, "medium": 20, "low": 5, "info": 1,
		}
		if v, ok := baseSev[t.Info.Severity]; ok { base = v }

		apScore := ap.scores[t.ID]
		effectiveness := 0.5
		if ap.runs[t.ID] > 0 {
			effectiveness = apScore / float64(ap.runs[t.ID])
		}
		scoredList[i] = scored{t: t, score: base * (1 + effectiveness*2)}
	}

	sort.Slice(scoredList, func(i, j int) bool {
		return scoredList[i].score > scoredList[j].score
	})

	result := make([]*Template, len(templates))
	for i, s := range scoredList {
		result[i] = s.t
	}
	return result
}

type ConcurrentScheduler struct {
	queue   chan *Template
	results chan []Result
	workers int
}

func NewConcurrentScheduler(workers int) *ConcurrentScheduler {
	if workers <= 0 { workers = 10 }
	return &ConcurrentScheduler{
		queue:   make(chan *Template, 1000),
		results: make(chan []Result, 1000),
		workers: workers,
	}
}

func (cs *ConcurrentScheduler) Submit(t *Template) {
	cs.queue <- t
}

func (cs *ConcurrentScheduler) Start(scanner *Scanner, baseURL string) {
	for i := 0; i < cs.workers; i++ {
		go func() {
			for t := range cs.queue {
				scanner.ProcessTemplate(baseURL, t)
			}
		}()
	}
}

func (cs *ConcurrentScheduler) Stop() {
	close(cs.queue)
	close(cs.results)
}

func (cs *ConcurrentScheduler) RunAll(templates []*Template, scanner *Scanner, baseURL string) []Result {
	prioritized := PrioritizeTemplates(templates)
	cs.Start(scanner, baseURL)
	for _, t := range prioritized {
		cs.Submit(t)
	}
	cs.Stop()
	return scanner.Results
}
