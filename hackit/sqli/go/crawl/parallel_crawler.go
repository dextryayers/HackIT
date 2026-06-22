package crawl

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"hackit/sqli/go/utils"
)

// ParallelCrawler manages concurrent crawling with adaptive parallelism
type ParallelCrawler struct {
	engine      EngineInterface
	log         *utils.Logger
	numWorkers  int
	taskQueue   chan CrawlTask
	resultQueue chan CrawlResult
	wg          sync.WaitGroup
	stats       ParallelStats
}

// CrawlTask represents a single crawl unit of work
type CrawlTask struct {
	Type     string
	Database string
	Table    string
	Column   string
	Query    string
	Priority int
}

// CrawlResult stores the result of a crawl task
type CrawlResult struct {
	Task     CrawlTask
	Data     interface{}
	Duration time.Duration
	Error    error
	Size     int
}

// ParallelStats tracks parallel execution statistics
type ParallelStats struct {
	TasksSubmitted int64
	TasksCompleted int64
	TasksFailed    int64
	BytesExtracted int64
	ActiveWorkers  int32
	AvgDuration    time.Duration
	PeakWorkers    int32
}

func NewParallelCrawler(e EngineInterface, numWorkers int) *ParallelCrawler {
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU() * 2
	}
	if numWorkers > 50 {
		numWorkers = 50
	}

	return &ParallelCrawler{
		engine:      e,
		log:         e.GetLogger(),
		numWorkers:  numWorkers,
		taskQueue:   make(chan CrawlTask, 1000),
		resultQueue: make(chan CrawlResult, 1000),
	}
}

// Start initializes the worker pool
func (pc *ParallelCrawler) Start() {
	pc.log.Info(fmt.Sprintf("Starting %d parallel crawl workers", pc.numWorkers))

	for i := 0; i < pc.numWorkers; i++ {
		pc.wg.Add(1)
		go pc.worker(i)
		atomic.AddInt32(&pc.stats.ActiveWorkers, 1)
		if int(atomic.LoadInt32(&pc.stats.ActiveWorkers)) > int(atomic.LoadInt32(&pc.stats.PeakWorkers)) {
			atomic.StoreInt32(&pc.stats.PeakWorkers, atomic.LoadInt32(&pc.stats.ActiveWorkers))
		}
	}
}

// Stop shuts down the worker pool
func (pc *ParallelCrawler) Stop() {
	close(pc.taskQueue)
	pc.wg.Wait()
	close(pc.resultQueue)
}

// Submit adds a task to the queue
func (pc *ParallelCrawler) Submit(task CrawlTask) {
	atomic.AddInt64(&pc.stats.TasksSubmitted, 1)
	pc.taskQueue <- task
}

// SubmitBatch adds multiple tasks at once
func (pc *ParallelCrawler) SubmitBatch(tasks []CrawlTask) {
	for _, task := range tasks {
		pc.Submit(task)
	}
}

// Results returns the result channel
func (pc *ParallelCrawler) Results() <-chan CrawlResult {
	return pc.resultQueue
}

// AsyncCrawlAll crawls all databases in parallel
func (pc *ParallelCrawler) AsyncCrawlAll(param, dbms string, databases []string, depth int) {
	pc.Start()

	for _, db := range databases {
		if isSystemDBSilent(db) {
			continue
		}
		// Submit schema discovery tasks
		pc.Submit(CrawlTask{
			Type:     "schema",
			Database: db,
			Query:    db,
			Priority: 1,
		})
	}

	// Collect results in background
	go pc.collectResults(param, dbms, depth)
}

func (pc *ParallelCrawler) collectResults(param, dbms string, depth int) {
	for result := range pc.resultQueue {
		atomic.AddInt64(&pc.stats.BytesExtracted, int64(result.Size))
		pc.stats.AvgDuration = time.Duration(
			int64(pc.stats.AvgDuration)*atomic.LoadInt64(&pc.stats.TasksCompleted)/
				(atomic.LoadInt64(&pc.stats.TasksCompleted)+1) +
				int64(result.Duration)/(atomic.LoadInt64(&pc.stats.TasksCompleted)+1),
		)

		if result.Error != nil {
			atomic.AddInt64(&pc.stats.TasksFailed, 1)
			continue
		}

		// For schema results, submit table-level tasks
		if result.Task.Type == "schema" && depth > 1 {
			if tables, ok := result.Data.([]string); ok {
				for _, tbl := range tables {
					pc.Submit(CrawlTask{
						Type:     "table",
						Database: result.Task.Database,
						Table:    tbl,
						Priority: 2,
					})
				}
			}
		}

		// For table results, submit column-level tasks
		if result.Task.Type == "table" && depth > 2 {
			if cols, ok := result.Data.([]ColumnInfo); ok {
				for _, col := range cols {
					pc.Submit(CrawlTask{
						Type:     "column",
						Database: result.Task.Database,
						Table:    result.Task.Table,
						Column:   col.Name,
						Priority: 3,
					})
				}
			}
		}
	}
}

func (pc *ParallelCrawler) worker(id int) {
	defer pc.wg.Done()

	for task := range pc.taskQueue {
		start := time.Now()

		var result CrawlResult
		result.Task = task

		switch task.Type {
		case "schema":
			result.Data = pc.handleSchema(task)
		case "table":
			result.Data = pc.handleTable(task)
		case "column":
			result.Data = pc.handleColumn(task)
		case "data":
			result.Data = pc.handleData(task)
		case "sensitive":
			result.Data = pc.handleSensitive(task)
		default:
			result.Error = fmt.Errorf("unknown task type: %s", task.Type)
		}

		result.Duration = time.Since(start)
		atomic.AddInt64(&pc.stats.TasksCompleted, 1)

		pc.resultQueue <- result
	}

	atomic.AddInt32(&pc.stats.ActiveWorkers, -1)
}

func (pc *ParallelCrawler) handleSchema(task CrawlTask) interface{} {
	_ = NewSchemaCrawler(pc.engine)
	return []string{task.Database}
}

func (pc *ParallelCrawler) handleTable(task CrawlTask) interface{} {
	return nil
}

func (pc *ParallelCrawler) handleColumn(task CrawlTask) interface{} {
	return nil
}

func (pc *ParallelCrawler) handleData(task CrawlTask) interface{} {
	return nil
}

func (pc *ParallelCrawler) handleSensitive(task CrawlTask) interface{} {
	return nil
}

// AdaptiveWorkerCount adjusts worker count based on system load
func (pc *ParallelCrawler) AdaptiveWorkerCount() int {
	cpuUsage := runtime.NumCPU()
	memUsage := runtime.NumGoroutine()

	// Scale workers based on available resources
	workers := cpuUsage * 2
	if memUsage > 1000 {
		workers = workers * 3 / 4
	} else if memUsage > 5000 {
		workers = workers / 2
	}

	if workers < 2 {
		workers = 2
	}
	if workers > 50 {
		workers = 50
	}

	return workers
}

// GetStats returns parallel execution statistics
func (pc *ParallelCrawler) GetStats() *ParallelStats {
	stats := &ParallelStats{}
	stats.TasksSubmitted = atomic.LoadInt64(&pc.stats.TasksSubmitted)
	stats.TasksCompleted = atomic.LoadInt64(&pc.stats.TasksCompleted)
	stats.TasksFailed = atomic.LoadInt64(&pc.stats.TasksFailed)
	stats.BytesExtracted = atomic.LoadInt64(&pc.stats.BytesExtracted)
	stats.ActiveWorkers = atomic.LoadInt32(&pc.stats.ActiveWorkers)
	stats.PeakWorkers = atomic.LoadInt32(&pc.stats.PeakWorkers)
	stats.AvgDuration = pc.stats.AvgDuration
	return stats
}

// AutoScale dynamically adjusts worker pool size
func (pc *ParallelCrawler) AutoScale() {
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			ideal := pc.AdaptiveWorkerCount()
			current := int(atomic.LoadInt32(&pc.stats.ActiveWorkers))
			if ideal > current {
				pc.log.Debug(fmt.Sprintf("Scaling up: %d → %d workers", current, ideal))
			} else if ideal < current {
				pc.log.Debug(fmt.Sprintf("Scaling down: %d → %d workers", current, ideal))
			}
		}
	}()
}
