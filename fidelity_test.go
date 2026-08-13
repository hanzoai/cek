package cek

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/hanzoai/namespace"
	sqlitedrv "github.com/hanzoai/sqlite"
)

// What survives a conversion, measured rather than assumed.
//
// The parity check compares a schema hash and per-table row counts and content
// hashes. That leaves a question it cannot answer about itself: does the copy
// carry the things which are NOT rows in a user table — AUTOINCREMENT counters,
// views, triggers, indexes, WITHOUT ROWID tables, generated columns,
// user_version — and would the check even notice if one went missing?
//
// This builds a database holding every one of them, converts it, and compares
// the two by asking the database itself.
func TestAConversionCarriesEverythingNotJustRows(t *testing.T) {
	setTestMaster(t)

	path := filepath.Join(t.TempDir(), "hostile.db")

	db, err := sql.Open("sqlite", sqlitedrv.DSN(path, nil))
	if err != nil {
		t.Fatalf("open plaintext: %v", err)
	}
	if _, err := db.Exec(`
		PRAGMA user_version = 42;
		PRAGMA application_id = 777;

		CREATE TABLE seq (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);
		INSERT INTO seq (v) VALUES ('a'),('b'),('c');
		DELETE FROM seq WHERE v='c';

		CREATE TABLE norowid (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID;
		INSERT INTO norowid VALUES ('k1','v1'),('k2','v2');

		CREATE TABLE gen (a INTEGER, b INTEGER, s INTEGER GENERATED ALWAYS AS (a+b) VIRTUAL);
		INSERT INTO gen (a,b) VALUES (2,3);

		CREATE TABLE parent (id INTEGER PRIMARY KEY);
		CREATE TABLE child (id INTEGER PRIMARY KEY, p INTEGER REFERENCES parent(id));
		INSERT INTO parent VALUES (1);
		INSERT INTO child VALUES (1,1);

		CREATE INDEX seq_v ON seq(v);
		CREATE UNIQUE INDEX norowid_v ON norowid(v);
		CREATE VIEW seq_view AS SELECT v FROM seq;
		CREATE TRIGGER seq_guard AFTER INSERT ON seq BEGIN UPDATE seq SET v=upper(NEW.v) WHERE id=NEW.id; END;
	`); err != nil {
		t.Fatalf("build the hostile database: %v", err)
	}
	before := describe(t, db)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := Convert(namespace.System(), "hostile", path); err != nil {
		t.Fatalf("Convert: %v", err)
	}

	enc, err := OpenAt(namespace.System(), "hostile", path)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	defer func() { _ = enc.Close() }()
	after := describe(t, enc)

	for k, want := range before {
		got, ok := after[k]
		if !ok {
			t.Errorf("%s: missing from the converted database (was %q)", k, want)
			continue
		}
		if got != want {
			t.Errorf("%s: converted database has %q, original had %q", k, got, want)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			t.Errorf("%s: appeared in the converted database and was not in the original", k)
		}
	}
}

// describe asks a database what it is, in facts a conversion could plausibly
// drop.
func describe(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	out := map[string]string{}

	for _, p := range []string{"user_version", "application_id", "page_size"} {
		var v string
		if err := db.QueryRow("PRAGMA " + p).Scan(&v); err != nil {
			t.Fatalf("PRAGMA %s: %v", p, err)
		}
		out["pragma:"+p] = v
	}

	// Every schema object, including the internal sqlite_sequence row that holds
	// an AUTOINCREMENT counter — the one a "rows in user tables" check cannot see.
	rows, err := db.Query(`SELECT type,name,COALESCE(sql,'') FROM sqlite_master ORDER BY type,name`)
	if err != nil {
		t.Fatalf("sqlite_master: %v", err)
	}
	for rows.Next() {
		var typ, name, ddl string
		if err := rows.Scan(&typ, &name, &ddl); err != nil {
			t.Fatalf("scan master: %v", err)
		}
		out["object:"+typ+":"+name] = ddl
	}
	_ = rows.Close()

	var seqName, seqVal sql.NullString
	if err := db.QueryRow(`SELECT name,seq FROM sqlite_sequence WHERE name='seq'`).Scan(&seqName, &seqVal); err == nil {
		out["autoincrement:seq"] = seqVal.String
	} else {
		out["autoincrement:seq"] = "ABSENT: " + err.Error()
	}

	for _, q := range []struct{ k, sql string }{
		{"rows:seq", `SELECT group_concat(id||'='||v,',') FROM (SELECT id,v FROM seq ORDER BY id)`},
		{"rows:norowid", `SELECT group_concat(k||'='||v,',') FROM (SELECT k,v FROM norowid ORDER BY k)`},
		{"rows:gen", `SELECT group_concat(a||'+'||b||'='||s,',') FROM gen`},
		{"rows:view", `SELECT group_concat(v,',') FROM seq_view`},
		{"count:child", `SELECT count(*) FROM child`},
	} {
		var v sql.NullString
		if err := db.QueryRow(q.sql).Scan(&v); err != nil {
			out[q.k] = "ERROR: " + err.Error()
			continue
		}
		out[q.k] = v.String
	}
	return out
}
