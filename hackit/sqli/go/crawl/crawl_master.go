package crawl

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"hackit/sqli/go/utils"
)

// CrawlMaster orchestrates all crawling operations
type CrawlMaster struct {
	engine   EngineInterface
	log      *utils.Logger
	config   *CrawlConfig
	stats    *CrawlStats
	results  *CrawlResults
	mu       sync.Mutex
}

// CrawlConfig configures the crawling behavior
type CrawlConfig struct {
	MaxDepth          int
	MaxThreads        int
	Timeout           time.Duration
	ExtractData       bool
	ExtractSensitive  bool
	ExtractProcs      bool
	ExtractViews      bool
	ExtractIndexes    bool
	ExtractSystem     bool
	BatchSize         int
	DelayBetweenReq   time.Duration
	StopOnError       bool
	SavePartial       bool
	OutputDir         string
}

// CrawlStats tracks crawling progress
type CrawlStats struct {
	DatabasesScanned int32
	TablesScanned    int32
	ColumnsScanned   int32
	RowsExtracted    int32
	Errors           int32
	SensitiveFound   int32
	StartTime        time.Time
	Elapsed          time.Duration
	Progress         float64
}

// CrawlResults stores all crawled data
type CrawlResults struct {
	Databases   map[string]*DatabaseInfo
	Sensitive   []SensitiveFinding
	Relations   []string
	SystemInfo  map[string]string
	Summary     *CrawlSummary
}

// DatabaseInfo holds complete info about a database
type DatabaseInfo struct {
	Name         string
	Size         string
	Collation    string
	Charset      string
	Tables       map[string]*TableInfo
	Procs        []StoredProcInfo
	Views        []ViewInfo
	Indexes      []IndexInfo
}

// TableInfo holds complete info about a table
type TableInfo struct {
	Name       string
	Engine     string
	Collation  string
	RowCount   int64
	Columns    []ColumnInfo
	Indexes    []IndexInfo
	Data       [][]string
	IsSystem   bool
}

// ColumnInfo holds detailed column info
type ColumnInfo struct {
	Name       string
	Type       string
	Length     string
	Nullable   bool
	Default    string
	Comment    string
	IsPK       bool
	IsFK       bool
	IsIdentity bool
	IsSensitive bool
	SensitivityScore float64
}

// IndexInfo holds index information
type IndexInfo struct {
	Name       string
	Columns    []string
	IsPK       bool
	IsUnique   bool
	IsFK       bool
	RefTable   string
	RefColumn  string
}

// StoredProcInfo holds stored procedure info
type StoredProcInfo struct {
	Name       string
	Type       string
	Definition string
	Params     []string
	Returns    string
}

// ViewInfo holds view information
type ViewInfo struct {
	Name       string
	Definition string
	Columns    []string
	IsUpdatable bool
}

// SensitiveFinding stores a sensitive data discovery
type SensitiveFinding struct {
	Database   string  `json:"database"`
	Table      string  `json:"table"`
	Column     string  `json:"column"`
	DataType   string  `json:"data_type"`
	Sample     string  `json:"sample"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
	Risk       string  `json:"risk"`
}

// CrawlSummary provides a summary of the crawl
type CrawlSummary struct {
	TotalDatabases int
	TotalTables    int
	TotalColumns   int
	TotalRows      int
	TotalSensitive int
	TotalErrors    int
	Duration       string
	Databases      []string
	TablesByDB     map[string][]string
	SensitiveByDB  map[string][]SensitiveFinding
}

// CrawlProgress is sent to progress channel
type CrawlProgress struct {
	Percent  float64
	Message  string
	Current  string
	Speed    string
}

// EngineInterface defines what we need from the core engine
type EngineInterface interface {
	Request(payload string, param string) (string, int, http.Header, error)
	GetLogger() *utils.Logger
}

func DefaultCrawlConfig() *CrawlConfig {
	return &CrawlConfig{
		MaxDepth:         5,
		MaxThreads:       10,
		Timeout:          30 * time.Second,
		ExtractData:      true,
		ExtractSensitive: true,
		ExtractProcs:     true,
		ExtractViews:     true,
		ExtractIndexes:   true,
		ExtractSystem:    true,
		BatchSize:        100,
		DelayBetweenReq:  0,
		StopOnError:      false,
		SavePartial:      true,
		OutputDir:        "crawl_output",
	}
}

func NewCrawlMaster(e EngineInterface, cfg *CrawlConfig) *CrawlMaster {
	if cfg == nil {
		cfg = DefaultCrawlConfig()
	}
	return &CrawlMaster{
		engine:  e,
		log:     e.GetLogger(),
		config:  cfg,
		stats:   &CrawlStats{StartTime: time.Now()},
		results: &CrawlResults{
			Databases:  make(map[string]*DatabaseInfo),
			Sensitive:  []SensitiveFinding{},
			SystemInfo: make(map[string]string),
		},
	}
}

// Run executes the complete crawl
func (cm *CrawlMaster) Run(param, dbms string, progressCh chan<- CrawlProgress) (*CrawlResults, error) {
	cm.log.Success("=== EXPERT CRAWLING ENGINE v2.0 ===")
	cm.log.Info(fmt.Sprintf("Target DBMS: %s | Threads: %d | Depth: %d", dbms, cm.config.MaxThreads, cm.config.MaxThreads))

	// Phase 1: Database Discovery
	cm.sendProgress(progressCh, 0, "Phase 1/5: Discovering databases...", "", "")
	databases := cm.discoverDatabases(param, dbms)
	cm.log.Success(fmt.Sprintf("Found %d databases", len(databases)))
	atomic.StoreInt32(&cm.stats.DatabasesScanned, int32(len(databases)))

	// Phase 2: Schema Crawling
	cm.sendProgress(progressCh, 20, "Phase 2/5: Crawling schemas...", "", "")
	cm.crawlSchemas(param, dbms, databases, progressCh)

	// Phase 3: Data Extraction
	if cm.config.ExtractData {
		cm.sendProgress(progressCh, 45, "Phase 3/5: Extracting data...", "", "")
		cm.extractAllData(param, dbms, progressCh)
	}

	// Phase 4: Sensitive Data Discovery
	if cm.config.ExtractSensitive {
		cm.sendProgress(progressCh, 70, "Phase 4/5: Scanning for sensitive data...", "", "")
		cm.scanSensitiveData(param, dbms, progressCh)
	}

	// Phase 5: Deep System Analysis
	cm.sendProgress(progressCh, 90, "Phase 5/5: Deep system analysis...", "", "")
	cm.analyzeSystem(param, dbms, progressCh)

	// Build summary
	cm.buildSummary()
	cm.stats.Elapsed = time.Since(cm.stats.StartTime)
	cm.sendProgress(progressCh, 100, "Crawl complete!", "", "")

	cm.log.Success(fmt.Sprintf("Crawl finished in %s", cm.stats.Elapsed.Round(time.Second)))
	return cm.results, nil
}

func (cm *CrawlMaster) discoverDatabases(param, dbms string) []string {
	ext := NewSchemaCrawler(cm.engine)
	databases := ext.DiscoverDatabases(param, dbms)

	// Default databases if discovery fails
	if len(databases) == 0 {
		databases = []string{"information_schema", "mysql", "performance_schema", "sys"}
	}
	return databases
}

func (cm *CrawlMaster) crawlSchemas(param, dbms string, databases []string, progressCh chan<- CrawlProgress) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, cm.config.MaxThreads)
	var mu sync.Mutex
	totalTables := 0

	for _, db := range databases {
		sem <- struct{}{}
		wg.Add(1)
		go func(dbName string) {
			defer wg.Done()
			defer func() { <-sem }()

			dbInfo := &DatabaseInfo{
				Name:   dbName,
				Tables: make(map[string]*TableInfo),
			}

			ext := NewSchemaCrawler(cm.engine)
			tables := ext.CrawlTables(param, dbms, dbName)
			atomic.AddInt32(&cm.stats.TablesScanned, int32(len(tables)))

			for _, tbl := range tables {
				tableInfo := ext.CrawlTableDetail(param, dbms, dbName, tbl)
				mu.Lock()
				dbInfo.Tables[tbl] = tableInfo
				mu.Unlock()
				atomic.AddInt32(&cm.stats.ColumnsScanned, int32(len(tableInfo.Columns)))
			}

			// Extract indexes
			if cm.config.ExtractIndexes {
				idxExt := NewIndexCrawler(cm.engine)
				dbInfo.Indexes = idxExt.ExtractIndexes(param, dbms, dbName, tables)
			}

			// Extract stored procs
			if cm.config.ExtractProcs && !isSystemDBSilent(dbName) {
				procExt := NewProcCrawler(cm.engine)
				dbInfo.Procs = procExt.ExtractProcedures(param, dbms, dbName)
				dbInfo.Views = procExt.ExtractViews(param, dbms, dbName)
			}

			mu.Lock()
			cm.results.Databases[dbName] = dbInfo
			totalTables += len(tables)
			mu.Unlock()
		}(db)
	}
	wg.Wait()
}

func (cm *CrawlMaster) extractAllData(param, dbms string, progressCh chan<- CrawlProgress) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, cm.config.MaxThreads)

	for dbName, dbInfo := range cm.results.Databases {
		if isSystemDBSilent(dbName) && !cm.config.ExtractSystem {
			continue
		}
		for tblName, tblInfo := range dbInfo.Tables {
			sem <- struct{}{}
			wg.Add(1)
			go func(db, tbl string, info *TableInfo) {
				defer wg.Done()
				defer func() { <-sem }()

				dataExt := NewDataCrawler(cm.engine)
				data, err := dataExt.ExtractTableData(param, dbms, db, tbl, info.Columns, cm.config.BatchSize)
				if err == nil {
					info.Data = data
					atomic.AddInt32(&cm.stats.RowsExtracted, int32(len(data)))
				}
			}(dbName, tblName, tblInfo)
		}
	}
	wg.Wait()
}

func (cm *CrawlMaster) scanSensitiveData(param, dbms string, progressCh chan<- CrawlProgress) {
	scanner := NewSensitiveCrawler(cm.engine)
	totalCols := int(atomic.LoadInt32(&cm.stats.ColumnsScanned))
	processed := 0

	for dbName, dbInfo := range cm.results.Databases {
		if isSystemDBSilent(dbName) {
			continue
		}
		for _, tblInfo := range dbInfo.Tables {
			for _, col := range tblInfo.Columns {
				findings := scanner.ScanColumn(dbName, tblInfo.Name, col)
				if len(findings) > 0 {
					cm.mu.Lock()
					cm.results.Sensitive = append(cm.results.Sensitive, findings...)
					col.IsSensitive = true
					atomic.AddInt32(&cm.stats.SensitiveFound, int32(len(findings)))
					cm.mu.Unlock()

					cm.sendProgress(progressCh, 70+float64(processed)/float64(totalCols)*20,
						fmt.Sprintf("Sensitive: %s.%s.%s → %s", dbName, tblInfo.Name, col.Name, findings[0].Category),
						fmt.Sprintf("%s.%s.%s", dbName, tblInfo.Name, col.Name), "")
				}
				processed++
			}
		}
	}
}

func (cm *CrawlMaster) analyzeSystem(param, dbms string, progressCh chan<- CrawlProgress) {
	sys := NewSystemCrawler(cm.engine)
	sysInfo := sys.ExtractSystemInfo(param, dbms)

	cm.mu.Lock()
	for k, v := range sysInfo {
		cm.results.SystemInfo[k] = v
	}
	cm.mu.Unlock()

	// Find relations
	if len(cm.results.Databases) > 1 {
		rels := findCrossRelations(cm.results.Databases)
		cm.results.Relations = rels
	}
}

func (cm *CrawlMaster) buildSummary() {
	summary := &CrawlSummary{
		Databases:     make([]string, 0),
		TablesByDB:    make(map[string][]string),
		SensitiveByDB: make(map[string][]SensitiveFinding),
	}

	for dbName, dbInfo := range cm.results.Databases {
		summary.Databases = append(summary.Databases, dbName)
		summary.TotalTables += len(dbInfo.Tables)
		for tblName := range dbInfo.Tables {
			summary.TablesByDB[dbName] = append(summary.TablesByDB[dbName], tblName)
		}
	}

	for _, find := range cm.results.Sensitive {
		summary.SensitiveByDB[find.Database] = append(summary.SensitiveByDB[find.Database], find)
	}

	for _, dbInfo := range cm.results.Databases {
		for _, tblInfo := range dbInfo.Tables {
			summary.TotalColumns += len(tblInfo.Columns)
			if tblInfo.Data != nil {
				summary.TotalRows += len(tblInfo.Data)
			}
		}
	}

	summary.TotalDatabases = len(cm.results.Databases)
	summary.TotalSensitive = len(cm.results.Sensitive)
	summary.TotalErrors = int(atomic.LoadInt32(&cm.stats.Errors))
	summary.Duration = time.Since(cm.stats.StartTime).Round(time.Second).String()

	cm.results.Summary = summary
}

func (cm *CrawlMaster) sendProgress(ch chan<- CrawlProgress, pct float64, msg, current, speed string) {
	if ch != nil {
		select {
		case ch <- CrawlProgress{Percent: pct, Message: msg, Current: current, Speed: speed}:
		default:
		}
	}
}

func isSystemDBSilent(name string) bool {
	lower := strings.ToLower(name)
	return lower == "information_schema" || lower == "performance_schema" ||
		lower == "sys" || lower == "mysql" || lower == "pg_catalog" ||
		lower == "template0" || lower == "template1"
}

func findCrossRelations(dbs map[string]*DatabaseInfo) []string {
	var rels []string
	for dbName, dbInfo := range dbs {
		for _, tblInfo := range dbInfo.Tables {
			for _, idx := range tblInfo.Indexes {
				if idx.IsFK {
					rel := fmt.Sprintf("%s.%s.%s → %s.%s (%s)",
						dbName, tblInfo.Name, strings.Join(idx.Columns, ","),
						idx.RefTable, idx.RefColumn, idx.Name)
					rels = append(rels, rel)
				}
			}
		}
	}
	return rels
}

// GetStats returns current crawl statistics
func (cm *CrawlMaster) GetStats() *CrawlStats { return cm.stats }

// GetResults returns crawl results
func (cm *CrawlMaster) GetResults() *CrawlResults { return cm.results }
