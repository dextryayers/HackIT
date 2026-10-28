package core

import (
	"strings"
	"testing"
	"time"
)

func TestSimilarityIdentical(t *testing.T) {
	if got := similarity("hello world", "hello world"); got != 1 {
		t.Fatalf("identical responses should score 1, got %v", got)
	}
	if got := similarity("", "abc"); got != 0 {
		t.Fatalf("empty response should score 0, got %v", got)
	}
}

func TestSimilarityIgnoresWhitespace(t *testing.T) {
	a := "<html>\n<body>alpha beta gamma</body>\n</html>"
	b := "<html>   <body>alpha   beta gamma</body>   </html>"
	if got := similarity(a, b); got != 1 {
		t.Fatalf("whitespace-only changes should normalize to 1, got %v", got)
	}
}

func TestSimilaritySeparatesDifferentPages(t *testing.T) {
	a := "<html><body>user profile for alice with account details</body></html>"
	b := "<html><body>completely unrelated database error page</body></html>"
	if !responsesDiffer(a, b) {
		t.Fatalf("different pages should be detected as different")
	}
	if responsesSimilar(a, b) {
		t.Fatalf("different pages should not be reported as similar")
	}
}

func TestNormalizeResponseMasksDynamicTokens(t *testing.T) {
	normalized := normalizeResponse("csrf_token=abcdefgh12345 welcome")
	if strings.Contains(normalized, "abcdefgh12345") {
		t.Fatalf("dynamic token was not masked: %q", normalized)
	}
	if !strings.Contains(normalized, "csrf_token") {
		t.Fatalf("dynamic token key should be preserved: %q", normalized)
	}
}

func TestIsErrorLike(t *testing.T) {
	cases := []struct {
		body string
		dbms string
		want bool
	}{
		{"You have an error in your SQL syntax near '1'", "MySQL", true},
		{"ORA-01756: quoted string not properly terminated", "Oracle", true},
		{"SQLite error: no such table: users", "SQLite", true},
		{"everything looks normal here", "", false},
	}
	for _, c := range cases {
		if got := isErrorLike(c.body, c.dbms); got != c.want {
			t.Errorf("isErrorLike(%q, %q) = %v, want %v", c.body, c.dbms, got, c.want)
		}
	}
}

func TestBestErrorMatch(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{"ORA-01756: quoted string not properly terminated", "Oracle"},
		{"SQLite error: no such table: users", "SQLite"},
		{"You have an error in your SQL syntax near '1'", "MySQL"},
	}
	for _, c := range cases {
		if got := bestErrorMatch(c.body); got != c.want {
			t.Errorf("bestErrorMatch(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}

func TestGetDialectAliases(t *testing.T) {
	cases := map[string]string{
		"mysql":      "MySQL",
		"MariaDB":    "MySQL",
		"postgres":   "PostgreSQL",
		"postgresql": "PostgreSQL",
		"mssql":      "MSSQL",
		"sqlite3":    "SQLite",
		"oracle":     "Oracle",
		"clickhouse": "ClickHouse",
		"duckdb":     "DuckDB",
		"bigquery":   "BigQuery",
	}
	for name, want := range cases {
		dialect := GetDialect(name)
		if dialect == nil {
			t.Fatalf("GetDialect(%q) returned nil", name)
		}
		if dialect.Name != want {
			t.Errorf("GetDialect(%q).Name = %q, want %q", name, dialect.Name, want)
		}
	}
	if GetDialect("unknown") != nil || GetDialect("") != nil || GetDialect("auto") != nil {
		t.Fatalf("placeholder dialect names should return nil")
	}
}

func TestDialectsAreComplete(t *testing.T) {
	dialects := Dialects()
	if len(dialects) < 13 {
		t.Fatalf("expected at least 13 dialects, got %d", len(dialects))
	}
	for _, dialect := range dialects {
		if dialect.Name == "" {
			t.Fatalf("dialect without a name")
		}
		if dialect.Quote == nil || dialect.Str == nil || dialect.Concat == nil ||
			dialect.Length == nil || dialect.Substr == nil || dialect.ASCII == nil ||
			dialect.Marker == nil || dialect.SleepExpr == nil || dialect.TimeCondition == nil ||
			dialect.Version == nil || dialect.Databases == nil || dialect.Tables == nil ||
			dialect.Columns == nil || dialect.DumpRow == nil {
			t.Fatalf("dialect %s is missing required functions", dialect.Name)
		}
	}
}

func TestQuotingAndLiterals(t *testing.T) {
	if got := literal("O'Brien"); got != "'O''Brien'" {
		t.Errorf("literal escaping = %q", got)
	}
	if got := quoteBacktick("a`b"); got != "`a``b`" {
		t.Errorf("backtick escaping = %q", got)
	}
	if got := quoteDouble(`a"b`); got != `"a""b"` {
		t.Errorf("double quote escaping = %q", got)
	}
	if got := quoteBracket("a]b"); got != "[a]]b]" {
		t.Errorf("bracket escaping = %q", got)
	}
	if got := mysqlLiteral(`a\b'c`); got != `'a\\b''c'` {
		t.Errorf("mysql literal escaping = %q", got)
	}
}

func TestConcatAndMarkers(t *testing.T) {
	if got := concatPipe("a", "b"); got != "(a||b)" {
		t.Errorf("concatPipe = %q", got)
	}
	if got := concatPipe(); got != "''" {
		t.Errorf("concatPipe with no parts = %q", got)
	}
	if got := concatFunc("CONCAT")("a", "b", "c"); got != "CONCAT(a,b,c)" {
		t.Errorf("concatFunc = %q", got)
	}
	if got := concatFunc("CONCAT")("a"); got != "a" {
		t.Errorf("concatFunc with one part = %q", got)
	}
	if got := markerFunc("x"); got != "CONCAT('~',x,'~')" {
		t.Errorf("markerFunc = %q", got)
	}
	if got := markerPipe("x"); got != "('~'||x||'~')" {
		t.Errorf("markerPipe = %q", got)
	}
}

func TestSQLiteSleepScales(t *testing.T) {
	if got := sqliteSleep(2); !strings.Contains(got, "x<3000000") {
		t.Errorf("sqliteSleep(2) should scale to three million rows, got %q", got)
	}
	if sqliteSleep(0) != sqliteSleep(1) {
		t.Errorf("sqliteSleep should clamp values below one second")
	}
	if !strings.Contains(sqliteSleep(1), "WITH RECURSIVE") {
		t.Errorf("sqliteSleep should use a recursive CTE")
	}
}

func TestTimeConditions(t *testing.T) {
	mysql := GetDialect("mysql")
	if got := mysql.TimeCondition("1=1", 2); !strings.Contains(got, "SLEEP(2)") {
		t.Errorf("mysql time condition = %q", got)
	}
	postgres := GetDialect("postgres")
	if got := postgres.TimeCondition("1=1", 2); !strings.Contains(got, "pg_sleep(2)") {
		t.Errorf("postgres time condition = %q", got)
	}
	sqlite := GetDialect("sqlite")
	if got := sqlite.TimeCondition("1=1", 2); !strings.Contains(got, "WITH RECURSIVE") {
		t.Errorf("sqlite time condition = %q", got)
	}
}

func TestExtractMarker(t *testing.T) {
	cases := map[string]string{
		"prefix ~alpha~ middle ~longer_value~ suffix": "longer_value",
		"no markers here":          "",
		"empty marker ~~":          "",
		`prefix ~a\u001eb~ suffix`: "a\x1eb",
	}
	for body, want := range cases {
		if got := extractMarker(body); got != want {
			t.Errorf("extractMarker(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestDecodeSeparators(t *testing.T) {
	if got := decodeSeparators(`a\u001eb`); got != "a\x1eb" {
		t.Errorf("decodeSeparators lowercase = %q", got)
	}
	if got := decodeSeparators(`a\u001Fb`); got != "a\x1fb" {
		t.Errorf("decodeSeparators uppercase = %q", got)
	}
	if got := decodeSeparators("plain"); got != "plain" {
		t.Errorf("decodeSeparators should leave plain text unchanged")
	}
}

func TestScalarExpr(t *testing.T) {
	if got := scalarExpr("  SELECT 1  "); got != "(SELECT 1)" {
		t.Errorf("scalarExpr = %q", got)
	}
	if got := scalarExpr("   "); got != "" {
		t.Errorf("scalarExpr on blank input = %q", got)
	}
}

func TestSplitRowValues(t *testing.T) {
	got := splitRowValues("a\nb\na\n\n")
	want := []string{"a", "b"}
	if len(got) != len(want) {
		t.Fatalf("splitRowValues = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitRowValues = %v, want %v", got, want)
		}
	}
	got = splitRowValues("\x1ealpha\x1ebeta")
	if len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Fatalf("splitRowValues control separator = %v", got)
	}
}

func TestDelayThreshold(t *testing.T) {
	cases := []struct {
		delay int
		want  time.Duration
	}{
		{0, 700 * time.Millisecond},
		{1, 700 * time.Millisecond},
		{2, 1400 * time.Millisecond},
		{3, 2100 * time.Millisecond},
		{10, 7 * time.Second},
	}
	for _, c := range cases {
		if got := delayThreshold(c.delay); got != c.want {
			t.Errorf("delayThreshold(%d) = %v, want %v", c.delay, got, c.want)
		}
	}
}

func TestTimePayload(t *testing.T) {
	exec := &Executor{
		S:       &Session{Boundary: Boundary{Prefix: "'", Suffix: "-- -"}},
		Dialect: GetDialect("mssql"),
	}
	got := exec.timePayload("1=1", 2)
	if !strings.Contains(got, "WAITFOR DELAY '0:0:2'") {
		t.Errorf("mssql time payload = %q", got)
	}
	if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "-- -") {
		t.Errorf("mssql time payload should use the boundary: %q", got)
	}

	exec.Dialect = GetDialect("mysql")
	got = exec.timePayload("1=1", 2)
	if !strings.Contains(got, " AND ") || !strings.Contains(got, "SLEEP(2)") {
		t.Errorf("mysql time payload = %q", got)
	}
}

func TestBoundaryCandidates(t *testing.T) {
	candidates := BoundaryCandidates()
	if len(candidates) < 15 {
		t.Fatalf("expected at least 15 boundary candidates, got %d", len(candidates))
	}
	if candidates[0].Prefix != "'" || candidates[0].Suffix != "-- -" {
		t.Fatalf("first candidate should be the common string context, got %+v", candidates[0])
	}
	foundEmpty := false
	for _, candidate := range candidates {
		if candidate.Prefix == "" && candidate.Suffix == "" {
			foundEmpty = true
		}
	}
	if !foundEmpty {
		t.Fatalf("numeric context candidate is missing")
	}
}

func TestLooksLikeVersion(t *testing.T) {
	cases := map[string]bool{
		"8.0.36":                    true,
		"3.46.1":                    true,
		"PostgreSQL 16.2 on x86_64": true,
		"abc":                       false,
		"syntax error near 12":      false,
		strings.Repeat("1", 201):    false,
	}
	for value, want := range cases {
		if got := looksLikeVersion(value); got != want {
			t.Errorf("looksLikeVersion(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestMedianDuration(t *testing.T) {
	if got := medianDuration(nil); got != 0 {
		t.Errorf("medianDuration(nil) = %v", got)
	}
	if got := medianDuration([]time.Duration{3 * time.Second, 1 * time.Second, 2 * time.Second}); got != 2*time.Second {
		t.Errorf("medianDuration odd = %v", got)
	}
	if got := medianDuration([]time.Duration{4 * time.Second, 1 * time.Second, 3 * time.Second, 2 * time.Second}); got != 3*time.Second {
		t.Errorf("medianDuration even = %v", got)
	}
}

func TestSystemAndInterestingTables(t *testing.T) {
	for _, name := range []string{"information_schema", "mysql", "PG_CATALOG", "sys"} {
		if !isSystemDB(name) {
			t.Errorf("%q should be a system database", name)
		}
	}
	if isSystemDB("main") {
		t.Errorf("main should not be a system database")
	}
	for _, name := range []string{"users", "admin_accounts", "api_keys", "wp_users"} {
		if !isInterestingTable(name) {
			t.Errorf("%q should be interesting", name)
		}
	}
	if isInterestingTable("products") {
		t.Errorf("products should not be interesting")
	}
}

func TestDiscoverInjectionPoints(t *testing.T) {
	opts := &Options{
		URL:    "http://example.test/vuln?id=1&name=alice",
		Data:   "username=alice&password=secret",
		Method: "POST",
		Cookie: "uid=1; theme=dark",
		Header: []string{"X-User-Id: 1"},
		Level:  3,
	}
	points, err := DiscoverInjectionPoints(opts)
	if err != nil {
		t.Fatalf("DiscoverInjectionPoints failed: %v", err)
	}
	locations := map[Location]int{}
	for _, point := range points {
		locations[point.Location]++
	}
	if locations[LocationQuery] != 2 {
		t.Errorf("query points = %d, want 2", locations[LocationQuery])
	}
	if locations[LocationBody] != 2 {
		t.Errorf("body points = %d, want 2", locations[LocationBody])
	}
	if locations[LocationCookie] != 2 {
		t.Errorf("cookie points = %d, want 2", locations[LocationCookie])
	}
	if locations[LocationHeader] != 1 {
		t.Errorf("header points = %d, want 1", locations[LocationHeader])
	}
}

func TestDiscoverInjectionPointsFiltersAndLevels(t *testing.T) {
	opts := &Options{
		URL:       "http://example.test/vuln?id=1&name=alice",
		Cookie:    "uid=1",
		Header:    []string{"X-User-Id: 1"},
		Level:     1,
		Param:     "id,name",
		SkipParam: "name",
	}
	points, err := DiscoverInjectionPoints(opts)
	if err != nil {
		t.Fatalf("DiscoverInjectionPoints failed: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("expected one point after filtering, got %d", len(points))
	}
	if points[0].Name != "id" {
		t.Errorf("expected id, got %q", points[0].Name)
	}
}

func TestDiscoverInjectionPointsJSON(t *testing.T) {
	opts := &Options{
		URL:    "http://example.test/json",
		Data:   `{"id":1,"profile":{"name":"alice"}}`,
		Method: "POST",
		Level:  1,
	}
	points, err := DiscoverInjectionPoints(opts)
	if err != nil {
		t.Fatalf("DiscoverInjectionPoints failed: %v", err)
	}
	if len(points) != 2 {
		t.Fatalf("expected two JSON points, got %d", len(points))
	}
	paths := map[string]bool{}
	for _, point := range points {
		paths[point.Path] = true
	}
	if !paths["id"] || !paths["profile.name"] {
		t.Errorf("unexpected JSON paths: %v", paths)
	}
}

func TestDiscoverInjectionPointsRequiresInput(t *testing.T) {
	opts := &Options{URL: "http://example.test/"}
	if _, err := DiscoverInjectionPoints(opts); err == nil {
		t.Fatalf("expected an error when no injectable input exists")
	}
}
