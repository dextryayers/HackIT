package modules

import (
	"fmt"
	"strings"
	"sync"
	"hackit/sqli/go/utils"
)

// CrossReferencer maps relationships between database objects
type CrossReferencer struct {
	engine EngineInterface
	log    *utils.Logger
	mu     sync.Mutex
}

// Relation describes a relationship between tables
type Relation struct {
	SourceDB      string `json:"source_db"`
	SourceTable   string `json:"source_table"`
	SourceColumn  string `json:"source_column"`
	TargetDB      string `json:"target_db"`
	TargetTable   string `json:"target_table"`
	TargetColumn  string `json:"target_column"`
	RelationType  string `json:"relation_type"`
	Confidence    float64 `json:"confidence"`
}

func NewCrossReferencer(e EngineInterface) *CrossReferencer {
	return &CrossReferencer{engine: e, log: e.GetLogger()}
}

// AnalyzeRelationships finds FK-like relationships between tables
func (cr *CrossReferencer) AnalyzeRelationships(param, dbms string, databases []string) []Relation {
	var relations []Relation
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Common FK naming patterns
	fkPatterns := []struct {
		suffix string
		target string
	}{
		{"_id", "id"},
		{"_fk", "id"},
		{"id_", "id"},
		{"user_id", "users.id"},
		{"customer_id", "customers.id"},
		{"product_id", "products.id"},
		{"order_id", "orders.id"},
		{"category_id", "categories.id"},
		{"parent_id", "id"},
	}

	cr.log.Info("Analyzing cross-table relationships...")

	for _, db := range databases {
		if isSystemDBSilent(db) {
			continue
		}
		wg.Add(1)
		go func(dbName string) {
			defer wg.Done()
			enums := NewDeepCrawler(cr.engine)
			tables := enums.crawlTables(param, dbms, dbName)

			for _, tbl := range tables {
				cols := enums.crawlColumns(param, dbms, dbName, tbl)
				for _, col := range cols {
					lower := strings.ToLower(col)
					for _, pat := range fkPatterns {
						if strings.Contains(lower, pat.suffix) {
							relation := Relation{
								SourceDB:     dbName,
								SourceTable:  tbl,
								SourceColumn: col,
								TargetColumn: pat.target,
								RelationType: "foreign-key",
								Confidence:   0.7,
							}
							// Try to identify target table
							base := strings.Replace(lower, "_id", "", 1)
							base = strings.Replace(base, "_fk", "", 1)
							base = strings.Replace(base, "id_", "", 1)
							if base != "" && base != col {
								// Pluralize common patterns
								if !strings.HasSuffix(base, "s") {
									relation.TargetTable = base + "s"
								} else {
									relation.TargetTable = base
								}
								relation.Confidence = 0.8
							}
							mu.Lock()
							relations = append(relations, relation)
							mu.Unlock()
						}
					}
				}
			}
		}(db)
	}
	wg.Wait()

	cr.log.Success(fmt.Sprintf("Found %d potential relationships", len(relations)))
	return relations
}

// BuildSchemaMap creates a hierarchical schema structure
func (cr *CrossReferencer) BuildSchemaMap(param, dbms string, databases []string) map[string]map[string][]string {
	schema := make(map[string]map[string][]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, db := range databases {
		if isSystemDBSilent(db) {
			continue
		}
		wg.Add(1)
		go func(dbName string) {
			defer wg.Done()
			enums := NewDeepCrawler(cr.engine)
			tables := enums.crawlTables(param, dbms, dbName)

			tableCols := make(map[string][]string)
			for _, tbl := range tables {
				cols := enums.crawlColumns(param, dbms, dbName, tbl)
				tableCols[tbl] = cols
			}

			mu.Lock()
			schema[dbName] = tableCols
			mu.Unlock()
		}(db)
	}
	wg.Wait()

	return schema
}

// FindJoinPaths identifies possible JOIN paths between tables
func (cr *CrossReferencer) FindJoinPaths(relations []Relation) [][]string {
	var paths [][]string
	graph := make(map[string][]string)

	for _, r := range relations {
		key := r.SourceDB + "." + r.SourceTable
		target := r.TargetDB
		if target == "" {
			target = r.SourceDB
		}
		targetKey := target + "." + r.TargetTable
		graph[key] = append(graph[key], targetKey)
	}

	// BFS to find paths
	for start := range graph {
		visited := make(map[string]bool)
		queue := [][]string{{start}}
		for len(queue) > 0 {
			path := queue[0]
			queue = queue[1:]
			last := path[len(path)-1]
			if len(path) > 1 && len(path) <= 4 {
				paths = append(paths, path)
			}
			if len(path) >= 5 {
				continue
			}
			for _, neighbor := range graph[last] {
				if !visited[neighbor] {
					visited[neighbor] = true
					newPath := make([]string, len(path)+1)
					copy(newPath, path)
					newPath[len(path)] = neighbor
					queue = append(queue, newPath)
				}
			}
		}
	}
	return paths
}

// RelationsToCore formats relations as core results
func (cr *CrossReferencer) RelationsToCore(relations []Relation) []Result {
	var out []Result
	for _, r := range relations {
		details := fmt.Sprintf("%s.%s.%s → %s.%s.%s (%.0f%%)",
			r.SourceDB, r.SourceTable, r.SourceColumn,
			r.TargetDB, r.TargetTable, r.TargetColumn,
			r.Confidence*100)
		out = append(out, Result{
			Parameter:  "cross-ref",
			Type:       "relationship",
			Payload:    fmt.Sprintf("%s.%s", r.SourceDB, r.SourceTable),
			DBMS:       r.RelationType,
			Details:    details,
			Confidence: r.Confidence,
		})
	}
	return out
}

// SchemaToResults formats schema as core results
func (cr *CrossReferencer) SchemaToResults(schema map[string]map[string][]string) []Result {
	var out []Result
	for db, tables := range schema {
		for tbl, cols := range tables {
			colStr := strings.Join(cols, ",")
			if len(colStr) > 200 {
				colStr = colStr[:200] + "..."
			}
			out = append(out, Result{
				Parameter:  "schema-map",
				Type:       "schema",
				Payload:    fmt.Sprintf("%s.%s", db, tbl),
				Details:    colStr,
				Confidence: 1.0,
			})
		}
	}
	return out
}
