package cek

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/namespace"
	sqlitedrv "github.com/hanzoai/sqlite"
)

// seedPlaintext writes an ordinary, unencrypted SQLite database holding values
// of every storage class — including the ones a careless copy loses: a NULL, an
// empty string, a zero, a blob and a float.
func seedPlaintext(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", sqlitedrv.DSN(path, nil))
	if err != nil {
		t.Fatalf("open plaintext: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, secret BLOB, score REAL, note TEXT);
		CREATE TABLE certs (kid TEXT PRIMARY KEY, pem TEXT NOT NULL);
		CREATE INDEX users_name ON users(name);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	for _, r := range []struct {
		name   string
		secret []byte
		score  float64
		note   any
	}{
		{"z", []byte{0x00, 0xff, 0x10}, 1.5, "first"},
		{"", []byte{}, 0, nil},
		{"unicode ✓", []byte("blob"), -2.25, ""},
	} {
		if _, err := db.Exec(`INSERT INTO users (name,secret,score,note) VALUES (?,?,?,?)`,
			r.name, r.secret, r.score, r.note); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if _, err := db.Exec(`INSERT INTO certs VALUES ('kid-1','-----BEGIN CERTIFICATE-----')`); err != nil {
		t.Fatalf("insert cert: %v", err)
	}
}

// readBack is what the store holds, in a form a test can compare across a
// conversion.
func readBack(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT id,name,secret,score,note FROM users ORDER BY id`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var id int64
		var name string
		var secret []byte
		var score float64
		var note sql.NullString
		if err := rows.Scan(&id, &name, &secret, &score, &note); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, string(rune(id))+"|"+name+"|"+string(secret)+"|"+
			sql.NullString{String: note.String, Valid: note.Valid}.String+"|"+
			map[bool]string{true: "set", false: "null"}[note.Valid])
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

func header(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	var h [headerLen]byte
	if _, err := f.ReadAt(h[:], 0); err != nil {
		t.Fatalf("read header: %v", err)
	}
	return h[:]
}

func setTestMaster(t *testing.T) {
	t.Helper()
	k := make([]byte, KeyLen)
	for i := range k {
		k[i] = byte(i + 1)
	}
	if err := SetMaster(k); err != nil {
		t.Fatalf("SetMaster: %v", err)
	}
}

// TestConvertEncryptsAnExistingPlaintextDatabase is the whole point: a database
// that was written in the clear ends up as ciphertext, opens under its derived
// key, and still holds every row.
func TestConvertEncryptsAnExistingPlaintextDatabase(t *testing.T) {
	setTestMaster(t)

	path := filepath.Join(t.TempDir(), "iam.db")
	seedPlaintext(t, path)

	if !bytes.Equal(header(t, path), []byte(sqliteMagic)) {
		t.Fatal("the seed is not a plaintext SQLite database")
	}
	plain, err := openPlain(path)
	if err != nil {
		t.Fatalf("open seed: %v", err)
	}
	want := readBack(t, plain)
	_ = plain.Close()
	if len(want) != 3 {
		t.Fatalf("seed holds %d rows, want 3", len(want))
	}

	if err := Convert(namespace.System(), "iam", path); err != nil {
		t.Fatalf("Convert: %v", err)
	}

	if bytes.Equal(header(t, path), []byte(sqliteMagic)) {
		t.Fatal("still a plaintext SQLite database after Convert")
	}
	for _, leftover := range []string{plainBakSuffix, tmpSuffix, sidecarSuffix} {
		if fileExists(path + leftover) {
			t.Errorf("%s was left behind", leftover)
		}
	}

	db, err := OpenAt(namespace.System(), "iam", path)
	if err != nil {
		t.Fatalf("OpenAt after Convert: %v", err)
	}
	defer func() { _ = db.Close() }()
	got := readBack(t, db)
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d: got %q, want %q", i, got[i], want[i])
		}
	}

	var pem string
	if err := db.QueryRow(`SELECT pem FROM certs WHERE kid='kid-1'`).Scan(&pem); err != nil {
		t.Fatalf("certs survived? %v", err)
	}
	if pem != "-----BEGIN CERTIFICATE-----" {
		t.Errorf("cert changed: %q", pem)
	}
}

// TestConvertIsIdempotent — a caller runs it on every boot, so the second run
// has to be a no-op that keeps the data readable.
func TestConvertIsIdempotent(t *testing.T) {
	setTestMaster(t)

	path := filepath.Join(t.TempDir(), "iam.db")
	seedPlaintext(t, path)

	if err := Convert(namespace.System(), "iam", path); err != nil {
		t.Fatalf("first Convert: %v", err)
	}
	first := header(t, path)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if err := Convert(namespace.System(), "iam", path); err != nil {
		t.Fatalf("second Convert: %v", err)
	}
	if !bytes.Equal(header(t, path), first) {
		t.Error("the second Convert rewrote the database")
	}
	if fi2, err := os.Stat(path); err != nil || fi2.Size() != fi.Size() {
		t.Errorf("size changed across a no-op convert: %v", err)
	}

	db, err := OpenAt(namespace.System(), "iam", path)
	if err != nil {
		t.Fatalf("OpenAt after two Converts: %v", err)
	}
	defer func() { _ = db.Close() }()
	if n := len(readBack(t, db)); n != 3 {
		t.Errorf("holds %d rows, want 3", n)
	}
}

// TestConvertedStoreRefusesAnotherSubsystemsKey proves the result is really
// keyed, and keyed to THIS store: the same master with a different subsystem
// derives a different key and must not open it.
func TestConvertedStoreRefusesAnotherSubsystemsKey(t *testing.T) {
	setTestMaster(t)

	path := filepath.Join(t.TempDir(), "iam.db")
	seedPlaintext(t, path)
	if err := Convert(namespace.System(), "iam", path); err != nil {
		t.Fatalf("Convert: %v", err)
	}

	db, err := OpenAt(namespace.System(), "billing", path)
	if err == nil {
		err = db.Ping()
		_ = db.Close()
	}
	if err == nil {
		t.Fatal("another subsystem's key opened the identity store")
	}
}

// TestConvertOnAnAbsentDatabaseIsNotAnError — there is nothing to convert, and
// Open will create one born encrypted.
func TestConvertOnAnAbsentDatabaseIsNotAnError(t *testing.T) {
	setTestMaster(t)
	path := filepath.Join(t.TempDir(), "absent.db")
	if err := Convert(namespace.System(), "iam", path); err != nil {
		t.Fatalf("Convert on an absent database: %v", err)
	}
	if fileExists(path) {
		t.Error("Convert created a database it was only asked to convert")
	}
}

// TestConvertWithoutAMasterRefuses — a missing key must never be the reason a
// store is left in the clear silently.
func TestConvertWithoutAMasterRefuses(t *testing.T) {
	masterMu.Lock()
	saved := master
	master = nil
	masterMu.Unlock()
	t.Cleanup(func() {
		masterMu.Lock()
		master = saved
		masterMu.Unlock()
	})

	path := filepath.Join(t.TempDir(), "iam.db")
	seedPlaintext(t, path)
	if err := Convert(namespace.System(), "iam", path); err == nil {
		t.Fatal("Convert without a master key did not refuse")
	}
	if !bytes.Equal(header(t, path), []byte(sqliteMagic)) {
		t.Error("a refused Convert still touched the database")
	}
}

// TestOpenAtIsOpenAtTheNamespacePath pins the delegation: the two doors reach
// the same file under the same key, so a store that names its own path is not a
// second scheme.
func TestOpenAtIsOpenAtTheNamespacePath(t *testing.T) {
	setTestMaster(t)

	dir := t.TempDir()
	ns, sub := namespace.System(), "widgets"

	db, err := Open(ns, sub, dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE t (v TEXT)`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t VALUES ('through Open')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	_ = db.Close()

	path, err := namespace.Path(dir, ns, sub)
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	at, err := OpenAt(ns, sub, path)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	defer func() { _ = at.Close() }()
	var v string
	if err := at.QueryRow(`SELECT v FROM t`).Scan(&v); err != nil {
		t.Fatalf("read through OpenAt: %v", err)
	}
	if v != "through Open" {
		t.Errorf("got %q", v)
	}
}

// TestInterruptedSwapIsFinished — the process died between the rename that set
// the plaintext aside and the rename that put the encrypted copy in place. The
// derived key opens the copy, so the right move is to finish.
func TestInterruptedSwapIsFinished(t *testing.T) {
	setTestMaster(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "iam.db")
	seedPlaintext(t, path)
	if err := Convert(namespace.System(), "iam", path); err != nil {
		t.Fatalf("Convert: %v", err)
	}

	// Stage the crash: the encrypted database is at <path>.cek.tmp, a stale
	// plaintext sits at <path>.plain.bak, and <path> itself is gone.
	if err := os.Rename(path, path+tmpSuffix); err != nil {
		t.Fatalf("stage tmp: %v", err)
	}
	if err := os.WriteFile(path+plainBakSuffix, []byte(sqliteMagic), 0o600); err != nil {
		t.Fatalf("stage bak: %v", err)
	}

	// Convert is what a boot calls: it recovers, then settles.
	if err := Convert(namespace.System(), "iam", path); err != nil {
		t.Fatalf("Convert after an interrupted swap: %v", err)
	}
	if !fileExists(path) {
		t.Fatal("the swap was not finished")
	}
	if fileExists(path + tmpSuffix) {
		t.Error("the temporary copy is still there")
	}
	if fileExists(path + plainBakSuffix) {
		t.Error("the plaintext backup was not shredded after the store proved readable")
	}

	db, err := OpenAt(namespace.System(), "iam", path)
	if err != nil {
		t.Fatalf("open the finished database: %v", err)
	}
	defer func() { _ = db.Close() }()
	if n := len(readBack(t, db)); n != 3 {
		t.Errorf("holds %d rows, want 3", n)
	}
}

// TestUncommittedSwapIsRolledBack — the process died after the plaintext was
// set aside and before anything replaced it. The plaintext is the source of
// truth and must come back.
func TestUncommittedSwapIsRolledBack(t *testing.T) {
	setTestMaster(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "iam.db")
	seedPlaintext(t, path)
	if err := os.Rename(path, path+plainBakSuffix); err != nil {
		t.Fatalf("stage: %v", err)
	}

	if err := recoverInterrupted(path); err != nil {
		t.Fatalf("recoverInterrupted: %v", err)
	}
	if !fileExists(path) {
		t.Fatal("the plaintext was not restored")
	}
	if !bytes.Equal(header(t, path), []byte(sqliteMagic)) {
		t.Error("what came back is not the plaintext original")
	}
	if fileExists(path + plainBakSuffix) {
		t.Error("the backup is still there after being restored")
	}
}

// The backup is released by a PROOF, never by an absence of evidence.
//
// These pin the failure the shredding used to key on: "this file does not have a
// plaintext SQLite header" was read as "it is the encrypted store, so the copy
// beside it can go". An empty file, a truncated one and a database under another
// master all answer that question the same way, and every one of them would have
// destroyed the last readable identity graph while returning success.

func TestATruncatedStoreIsRefusedAndKeepsItsBackup(t *testing.T) {
	setTestMaster(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "iam.db")

	// The shape an unclean stop leaves behind: a zero-length file where the
	// database was, with the pre-migration plaintext still beside it.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("stage empty: %v", err)
	}
	seedPlaintext(t, path+plainBakSuffix)

	if err := Convert(namespace.System(), "iam", path); err == nil {
		t.Fatal("Convert accepted a zero-length store instead of refusing it")
	}
	if !fileExists(path + plainBakSuffix) {
		t.Fatal("the plaintext backup was shredded for a store that was never opened")
	}
}

func TestAStoreUnderAnotherMasterKeepsItsBackup(t *testing.T) {
	setTestMaster(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "iam.db")

	// Encrypted, and NOT under the key this process derives.
	other := make([]byte, KeyLen)
	for i := range other {
		other[i] = byte(255 - i)
	}
	db, err := openKeyed(path, other)
	if err != nil {
		t.Fatalf("seed a store under another key: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE t (v TEXT)`); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = db.Close()
	seedPlaintext(t, path+plainBakSuffix)

	if err := Convert(namespace.System(), "iam", path); err == nil {
		t.Fatal("Convert reported success for a store it cannot read")
	}
	if !fileExists(path + plainBakSuffix) {
		t.Fatal("the plaintext backup was shredded for a store that does not open under this master")
	}
}

func TestConvertDoesNotCreateAStoreThatIsNotThere(t *testing.T) {
	setTestMaster(t)
	path := filepath.Join(t.TempDir(), "iam.db")
	if err := Convert(namespace.System(), "iam", path); err != nil {
		t.Fatalf("Convert on an absent store: %v", err)
	}
	if fileExists(path) {
		t.Fatal("Convert created a store, which is how an empty identity service gets served")
	}
}

// TestConvertRefusesAVirtualTable draws the boundary of a logical copy.
//
// A virtual table brings shadow tables SQLite maintains for it, holding an index
// layout rather than rows. Recreating the virtual table regenerates them, so their
// bytes need not match — and verify compares content per table, which would then
// report a difference nothing in the data explains. Refusing names the reason
// instead, and leaves the plaintext exactly where it was.
func TestConvertRefusesAVirtualTable(t *testing.T) {
	setTestMaster(t)

	path := filepath.Join(t.TempDir(), "fts.db")
	db, err := sql.Open("sqlite", sqlitedrv.DSN(path, nil))
	if err != nil {
		t.Fatalf("open plaintext: %v", err)
	}
	// Whichever module this build compiled in — the refusal is about virtual
	// tables, not about any one of them.
	made := ""
	for ddl, seed := range map[string]string{
		`CREATE VIRTUAL TABLE notes USING fts5(body)`:      `INSERT INTO notes(body) VALUES ('hello')`,
		`CREATE VIRTUAL TABLE notes4 USING fts4(body)`:     `INSERT INTO notes4(body) VALUES ('hello')`,
		`CREATE VIRTUAL TABLE boxes USING rtree(id,x0,x1)`: `INSERT INTO boxes VALUES (1,0.0,1.0)`,
	} {
		if _, err := db.Exec(ddl); err == nil {
			if _, err := db.Exec(seed); err != nil {
				_ = db.Close()
				t.Fatalf("seed the virtual table: %v", err)
			}
			made = ddl
			break
		}
	}
	if made == "" {
		_ = db.Close()
		t.Skip("this build compiled in no virtual table module, so there is none to refuse")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close the seed: %v", err)
	}

	err = Convert(namespace.System(), "iam", path)
	if err == nil {
		t.Fatal("Convert accepted a virtual table; a logical copy cannot promise its shadow tables")
	}
	if !strings.Contains(err.Error(), "virtual table") {
		t.Fatalf("the refusal must name what it refused, got: %v", err)
	}
	// The original is untouched, which is the promise that makes refusing safe.
	if !bytes.Equal(header(t, path), []byte(sqliteMagic)) {
		t.Fatal("the plaintext original was not left as it was")
	}
}
