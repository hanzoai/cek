package cek

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hanzoai/namespace"
	sqlitedrv "github.com/hanzoai/sqlite"
)

// hexKey renders a raw key in the x'…' form SQLCipher reads as key material
// rather than as a passphrase to stretch. Bound as a parameter, never formatted
// into a statement.
func hexKey(key []byte) string { return fmt.Sprintf("x'%x'", key) }

// openPlain opens a database with NO key, which is what a file written before
// cek is. It exists so the one place that reads plaintext says so out loud.
func openPlain(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", sqlitedrv.DSN(path, nil))
	if err != nil {
		return nil, fmt.Errorf("cek: open the plaintext %q: %w", path, err)
	}
	return db, nil
}

// openKeyed opens a database under a raw key. The error never carries the DSN,
// because the DSN carries the key.
func openKeyed(path string, key []byte) (*sql.DB, error) {
	db, err := sqlitedrv.OpenDB(path, key)
	if err != nil {
		return nil, fmt.Errorf("cek: open the encrypted %q: %w", path, err)
	}
	return db, nil
}

// Converting a database that was written before it had a key.
//
// A database born under cek is encrypted from its first page, so nothing here
// runs for it. What this is for is the other kind: a file some earlier process
// wrote in the clear, which now has to become the encrypted store without
// losing a row. That is a migration, and a migration is exactly the thing the
// derived-key scheme does not need for its OWN files — so it is a separate verb
// a caller asks for, not something Open does behind one.
//
// It is CRASH-SAFE and FAIL-SECURE, in that order:
//
//   - The plaintext file remains the source of truth until an atomic rename
//     commits the encrypted copy. Every failure before that leaves the original
//     exactly as it was.
//   - The swap happens only after the copy has reproduced the source's schema,
//     per-table row count and per-table content hash, passed integrity_check,
//     and been RE-OPENED under the same keyed path the application will use. A
//     key that cannot open the result is therefore caught while the plaintext is
//     still there, rather than after it is gone.
//   - A crash between the commit steps is resolved from the files alone
//     (recoverInterrupted), because a derived key is reproducible: unlike a
//     random per-file key, there is no sidecar that can be lost or get out of
//     step with the database it belongs to.
//
// The transient plaintext copy the commit leaves behind is SHREDDED as soon as
// the encrypted database opens, so the window in which two readable copies exist
// is the swap itself and nothing longer.

const (
	tmpSuffix      = ".cek.tmp"   // in-progress encrypted target; same volume, so the rename is atomic
	plainBakSuffix = ".plain.bak" // transient pre-migration plaintext, shredded after a verified open
	lockSuffix     = ".cek.lock"  // per-database flock, so two processes cannot convert at once

	sqliteMagic = "SQLite format 3\x00" // the 16-byte header of an UNENCRYPTED database
	headerLen   = 16

	// convertTimeout bounds the copy and the verification. Both are proportional
	// to the database, and a store this runs on is one that fits on a volume.
	convertTimeout = 30 * time.Minute
)

// Convert makes the database at path encrypted under the key ns and subsystem
// derive, in place, without losing a row.
//
// It is IDEMPOTENT and cheap to repeat: a database that is already ciphertext is
// left untouched and the call costs a stat, so a caller can run it on every boot
// and stop thinking about which run is the first one.
//
// An absent database is not an error — there is nothing to convert, and Open
// will create one born encrypted.
func Convert(ns namespace.Namespace, subsystem, path string) error {
	masterMu.RLock()
	m := master
	masterMu.RUnlock()

	key, err := DeriveKey(m, ns, subsystem)
	if err != nil {
		return err
	}
	defer zero(key)

	unlock, err := flock(path)
	if err != nil {
		return err
	}
	defer unlock()

	if err := recoverInterrupted(path); err != nil {
		return err
	}

	switch classify(path) {
	case absent:
		// Nothing to convert. Open will create one born encrypted, and this must
		// not create it here — a file made by the converter is a file with no
		// identities in it.
		return nil
	case plaintext:
		return convert(path, key)
	case truncated:
		// Too small to be a database. This is NOT "already encrypted": a store is
		// never two bytes long, and reading it as done is how a delayed
		// allocation after an unclean stop becomes a shredded backup and an empty
		// identity service. Refuse and let recoverInterrupted's backup, or a
		// human, settle it.
		return fmt.Errorf("cek: %q is too small to be a database, so this refuses to treat it as one", path)
	default:
		// Encrypted already — or something this cannot read. Which of those it is
		// decides whether the plaintext beside it may go, so ASK the file.
		return settle(path, key)
	}
}

// settle proves the store at path opens and decrypts under key, and only then
// releases the plaintext copy a commit left beside it.
//
// The proof is the whole function. "Not a plaintext SQLite header" is not proof
// of anything — an empty file, a truncated one, and a database encrypted under a
// DIFFERENT master all look identical through that lens, and every one of them
// would otherwise shred the last readable copy of the identity graph while
// reporting success.
func settle(path string, key []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), convertTimeout)
	defer cancel()

	db, err := openKeyed(path, key)
	if err != nil {
		return fmt.Errorf("cek: open %q: %w", path, err)
	}
	defer func() { _ = db.Close() }()

	// Reading the schema is what forces SQLCipher to take the key to the pages.
	// Opening a handle proves nothing: database/sql connects lazily, so a wrong
	// key surfaces at the first read and not before.
	var n int64
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&n); err != nil {
		return fmt.Errorf("cek: %q does not read under its key (wrong master key, or a damaged store): %w", path, err)
	}
	shredPlainBak(path)
	return nil
}

// convert holds the whole of the one-way trip, with the lock already held and
// the file known to be plaintext.
func convert(path string, key []byte) error {
	tmp := path + tmpSuffix
	removeDBFiles(tmp) // a previous attempt that did not commit

	srcInv, err := export(path, tmp, key)
	if err != nil {
		removeDBFiles(tmp)
		return err
	}
	if classify(tmp) != sealed {
		removeDBFiles(tmp)
		return fmt.Errorf("cek: converting %q did not produce an encrypted file — this build has no SQLCipher codec, so it cannot encrypt anything", path)
	}
	if err := verify(tmp, key, srcInv); err != nil {
		removeDBFiles(tmp)
		return fmt.Errorf("cek: the encrypted copy of %q does not match it, so the original is untouched: %w", path, err)
	}

	// Only the main file is renamed below, so the copy has to be COMPLETE in it.
	// Closing the last connection checkpoints and removes a WAL or a rollback
	// journal, so one still here means the close did not finish — and renaming
	// the main file alone would drop whatever that file still holds. The journal
	// is the one that actually turns up: the attached target runs in DELETE mode,
	// because journal_mode applies to main and not to what ATTACH opens.
	// Refusing costs a retry on the next boot; renaming anyway costs the rows.
	for _, sidefile := range []string{"-wal", "-journal"} {
		if fileExists(tmp + sidefile) {
			removeDBFiles(tmp)
			return fmt.Errorf("cek: the encrypted copy of %q still has a %s file beside it, so it is not complete in one file; the original is untouched", path, sidefile)
		}
	}

	// Get the copy's BYTES to the disk before the plaintext stops being the
	// source of truth. syncDir below makes the RENAME durable, which is a
	// different promise: without this the encrypted pages can still be in the
	// page cache when the original is released, and a power loss inside the
	// writeback window leaves a torn database and no plaintext to rebuild it.
	if err := syncFile(tmp); err != nil {
		removeDBFiles(tmp)
		return fmt.Errorf("cek: flush the encrypted copy of %q to disk: %w", path, err)
	}

	// Commit, in the order a crash can be read back from:
	//  1. plaintext → <db>.plain.bak, so the original still exists,
	//  2. drop the orphaned plaintext -wal/-shm (the WAL was folded into the main
	//     file before the copy, so the backup is complete and leaving them would
	//     put a plaintext WAL beside an encrypted database),
	//  3. atomic rename tmp → path.
	if err := os.Rename(path, path+plainBakSuffix); err != nil {
		removeDBFiles(tmp)
		return fmt.Errorf("cek: set the plaintext %q aside: %w", path, err)
	}
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Rename(path+plainBakSuffix, path) // put it back
		return fmt.Errorf("cek: swap the encrypted copy into %q: %w", path, err)
	}
	syncDir(filepath.Dir(path))

	// Prove the real path opens under the real key before the plaintext goes.
	db, err := openKeyed(path, key)
	if err != nil {
		return fmt.Errorf("cek: the converted %q does not open (its plaintext is beside it as %s): %w", path, plainBakSuffix, err)
	}
	if err := db.Close(); err != nil {
		return fmt.Errorf("cek: close the converted %q: %w", path, err)
	}
	shredPlainBak(path)
	return nil
}

// export folds the source's WAL into its main file, records what it holds, and
// copies every object and every row into a fresh encrypted database at tmp. The
// source is only ever read.
//
// THE COPY IS LOGICAL AND IT RUNS IN GO, on two ordinary handles: the plaintext
// source opened with no key, the encrypted target opened with one. It was
// SQLCipher's sqlcipher_export, which is a SQL function only the C library
// defines — so a build without that library could not convert a database at all,
// and the store it was pointed at stayed unopenable. Nothing else here needed the
// C engine: github.com/hanzoai/sqlite encrypts on every build (the pure-Go
// SQLCipher codec envelope, byte-compatible with the C one), so the conversion
// was the only place the dependency survived, and it did not have to.
//
// A byte-level encrypt of the source is not available for this: SQLCipher needs 80
// reserved bytes per page for its IV and tag, an ordinary plaintext database
// reserves none, and no pragma retrofits that into an existing file. A fresh keyed
// database has the reserve from its first page, so the rows move logically — which
// is what sqlcipher_export did too, and why verify compares content rather than
// bytes.
func export(path, tmp string, key []byte) (inventory, error) {
	ctx, cancel := context.WithTimeout(context.Background(), convertTimeout)
	defer cancel()

	src, err := openPlain(path)
	if err != nil {
		return inventory{}, err
	}
	defer func() { _ = src.Close() }()
	src.SetMaxOpenConns(1)

	conn, err := src.Conn(ctx)
	if err != nil {
		return inventory{}, fmt.Errorf("cek: take a connection to %q: %w", path, err)
	}
	defer func() { _ = conn.Close() }()

	// A live store carries megabytes of WAL. Fold it in first, so the copy and
	// the backup both hold every committed row.
	//
	// The RESULT has to be read, not just the error. wal_checkpoint reports a
	// refusal in its first column and still returns success, so an unchecked call
	// is indistinguishable from one that did nothing — and the plaintext -wal is
	// deleted a few lines later, on the strength of this having worked.
	var busy, logFrames, checkpointed int64
	if err := conn.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed); err != nil {
		return inventory{}, fmt.Errorf("cek: checkpoint %q: %w", path, err)
	}
	if busy != 0 {
		return inventory{}, fmt.Errorf("cek: %q has a write-ahead log this could not fold in — something else is holding the database open, and converting it now would strand those rows", path)
	}
	srcInv, err := readInventory(ctx, conn)
	if err != nil {
		return inventory{}, fmt.Errorf("cek: read what %q holds: %w", path, err)
	}
	objs, err := schemaObjects(ctx, conn)
	if err != nil {
		return inventory{}, fmt.Errorf("cek: read the schema of %q: %w", path, err)
	}

	dst, err := openKeyed(tmp, key)
	if err != nil {
		return inventory{}, err
	}
	dst.SetMaxOpenConns(1)
	if err := copyInto(ctx, conn, dst, objs, srcInv); err != nil {
		_ = dst.Close()
		return inventory{}, err
	}
	// CLOSE IT HERE, not on a defer. The encrypted file is written when the last
	// handle closes — that is what the envelope's seal is — and convert() reads
	// the file straight after this returns, to classify it and to refuse a copy
	// that still has a journal beside it.
	if err := dst.Close(); err != nil {
		return inventory{}, fmt.Errorf("cek: close the encrypted copy of %q: %w", path, err)
	}
	return srcInv, nil
}

// object is one row of sqlite_master worth recreating.
type object struct{ typ, name, ddl string }

// schemaObjects reads every object the copy has to recreate, in creation order.
//
// It REFUSES a virtual table. One brings shadow tables that SQLite maintains for
// it, whose contents are an index layout rather than rows; recreating the virtual
// table regenerates them, and no logical copy can promise the same bytes. The C
// function did this from inside the engine. Nothing cek converts has one, and a
// refusal names the reason rather than producing a database that verify would
// reject for a difference it cannot explain.
func schemaObjects(ctx context.Context, conn *sql.Conn) ([]object, error) {
	rows, err := conn.QueryContext(ctx,
		`SELECT type,name,COALESCE(sql,'') FROM sqlite_master `+
			`WHERE name NOT LIKE 'sqlite_%' ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []object
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.typ, &o.name, &o.ddl); err != nil {
			return nil, err
		}
		if o.ddl == "" {
			continue // an index SQLite made for a constraint; it comes back with the table
		}
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(o.ddl)), "CREATE VIRTUAL TABLE") {
			return nil, fmt.Errorf("cek: %q is a virtual table, whose shadow tables a logical copy cannot reproduce byte for byte", o.name)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// copyInto creates the schema in the target, moves every row, and carries the two
// header fields a fresh database starts at zero.
//
// TABLES FIRST, THEN ROWS, THEN EVERYTHING ELSE. An index built as the rows arrive
// is built once per insert; a trigger present while they arrive would fire on them
// and write rows the source never had. So both wait until the data is in.
func copyInto(ctx context.Context, src *sql.Conn, dst *sql.DB, objs []object, inv inventory) error {
	conn, err := dst.Conn(ctx)
	if err != nil {
		return fmt.Errorf("cek: take a connection to the encrypted copy: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// A foreign key can point at a table that has not been created yet, and the
	// rows arrive table by table, so a row can reference one that is still empty.
	// The source already satisfies its own constraints; re-checking them mid-copy
	// only makes the order of the copy a correctness question.
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return fmt.Errorf("cek: hold off foreign keys on the copy: %w", err)
	}

	for _, o := range objs {
		if o.typ != "table" {
			continue
		}
		if _, err := conn.ExecContext(ctx, o.ddl); err != nil {
			return fmt.Errorf("cek: create %q in the copy: %w", o.name, err)
		}
	}
	for _, o := range objs {
		if o.typ != "table" {
			continue
		}
		if err := copyRows(ctx, src, conn, o.name); err != nil {
			return fmt.Errorf("cek: copy the rows of %q: %w", o.name, err)
		}
	}
	for _, o := range objs {
		if o.typ == "table" {
			continue
		}
		if _, err := conn.ExecContext(ctx, o.ddl); err != nil {
			return fmt.Errorf("cek: create %s %q in the copy: %w", o.typ, o.name, err)
		}
	}

	// AUTOINCREMENT counters live in sqlite_sequence, which SQLite creates with the
	// first such table and fills from the rows it is given — so after a copy it
	// holds the highest rowid COPIED, which is the same number, unless a table's
	// top rows were deleted. Then the next insert would reuse an id the source had
	// already handed out. The source's own counters settle it.
	if err := copySequence(ctx, src, conn); err != nil {
		return err
	}

	// The header fields sqlcipher_export did not carry either. Integers this
	// process just read out of the source, and PRAGMA takes no parameters.
	for i, p := range headerPragmas {
		v := [2]int64{inv.userVersion, inv.applicationID}[i]
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA %s = %d", p, v)); err != nil {
			return fmt.Errorf("cek: carry %s onto the copy: %w", p, err)
		}
	}
	return nil
}

// copyRows moves one table, naming its columns explicitly.
//
// SELECT * would also read a GENERATED column, which cannot be inserted into, and
// would bind columns by position — so a table whose DDL SQLite normalised into a
// different order would be copied into the wrong columns. table_xinfo reports the
// generated ones (hidden 2 and 3) and it reports them in the target's order too,
// since both sides created the table from the same DDL.
func copyRows(ctx context.Context, src *sql.Conn, dst *sql.Conn, table string) error {
	cols, err := userColumns(ctx, src, table)
	if err != nil {
		return err
	}
	if len(cols) == 0 {
		return nil // every column is generated: there is nothing to write
	}
	quoted := make([]string, len(cols))
	marks := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = quoteIdent(c)
		marks[i] = "?"
	}
	list := strings.Join(quoted, ",")

	rows, err := src.QueryContext(ctx, "SELECT "+list+" FROM "+quoteIdent(table))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	ins := "INSERT INTO " + quoteIdent(table) + " (" + list + ") VALUES (" + strings.Join(marks, ",") + ")"
	tx, err := dst.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, ins)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := stmt.ExecContext(ctx, vals...); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// userColumns names the columns of table that hold stored values, in order.
func userColumns(ctx context.Context, conn *sql.Conn, table string) ([]string, error) {
	rows, err := conn.QueryContext(ctx, "SELECT name,hidden FROM pragma_table_xinfo(?)", table)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		var hidden int
		if err := rows.Scan(&name, &hidden); err != nil {
			return nil, err
		}
		if hidden == 2 || hidden == 3 {
			continue // VIRTUAL and STORED generated columns: computed, never written
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// copySequence carries the AUTOINCREMENT counters, for the tables that have one.
func copySequence(ctx context.Context, src *sql.Conn, dst *sql.Conn) error {
	var present int
	if err := src.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'`).Scan(&present); err != nil {
		return fmt.Errorf("cek: look for the sequence table: %w", err)
	}
	if present == 0 {
		return nil
	}
	rows, err := src.QueryContext(ctx, "SELECT name,seq FROM sqlite_sequence")
	if err != nil {
		return fmt.Errorf("cek: read the sequence table: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		var seq int64
		if err := rows.Scan(&name, &seq); err != nil {
			return err
		}
		// The row exists already when the copy inserted into that table, and does
		// not when it was empty — so REPLACE it rather than upsert: sqlite_sequence
		// carries no primary key and no unique index, which is what makes an
		// ON CONFLICT target invalid on it.
		if _, err := dst.ExecContext(ctx, "DELETE FROM sqlite_sequence WHERE name = ?", name); err != nil {
			return fmt.Errorf("cek: clear the sequence of %q: %w", name, err)
		}
		if _, err := dst.ExecContext(ctx,
			"INSERT INTO sqlite_sequence(name,seq) VALUES(?,?)", name, seq); err != nil {
			return fmt.Errorf("cek: carry the sequence of %q: %w", name, err)
		}
	}
	return rows.Err()
}

// quoteIdent renders an identifier for a statement, doubling any embedded quote.
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// verify re-opens the encrypted copy exactly as the application will and asserts
// that it holds the same database: integrity_check ok, the same schema, and per
// table the same row count AND the same content hash.
//
// The content hash is what backs the claim that nothing was lost. It is a
// commutative sum over per-row hashes of the USER columns, so it catches a
// changed value, a coerced NULL or an added or dropped row — all of which a row
// count and integrity_check miss — while ignoring the implicit-rowid
// renumbering sqlcipher_export legitimately does.
func verify(tmp string, key []byte, src inventory) error {
	ctx, cancel := context.WithTimeout(context.Background(), convertTimeout)
	defer cancel()

	db, err := openKeyed(tmp, key)
	if err != nil {
		return fmt.Errorf("reopen the encrypted copy: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("the encrypted copy does not answer under its key: %w", err)
	}

	var ic string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&ic); err != nil {
		return fmt.Errorf("integrity_check: %w", err)
	}
	if ic != "ok" {
		return fmt.Errorf("integrity_check returned %q", ic)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("take a connection to the encrypted copy: %w", err)
	}
	defer func() { _ = conn.Close() }()
	dst, err := readInventory(ctx, conn)
	if err != nil {
		return fmt.Errorf("read what the encrypted copy holds: %w", err)
	}

	if dst.userVersion != src.userVersion {
		return fmt.Errorf("user_version is %d in the source and %d in the copy", src.userVersion, dst.userVersion)
	}
	if dst.applicationID != src.applicationID {
		return fmt.Errorf("application_id is %d in the source and %d in the copy", src.applicationID, dst.applicationID)
	}
	if dst.schema != src.schema {
		return fmt.Errorf("the schemas differ")
	}
	if len(dst.tables) != len(src.tables) {
		return fmt.Errorf("the source has %d tables, the copy %d", len(src.tables), len(dst.tables))
	}
	for tbl, s := range src.tables {
		d, ok := dst.tables[tbl]
		if !ok {
			return fmt.Errorf("table %q is missing from the copy", tbl)
		}
		if d.count != s.count {
			return fmt.Errorf("table %q has %d rows in the source and %d in the copy", tbl, s.count, d.count)
		}
		if d.content != s.content {
			return fmt.Errorf("table %q has the same number of rows in the copy but different values in them", tbl)
		}
	}
	return nil
}

// inventory is what a database holds, in the form two of them can be compared:
// the header fields an application sets, a schema hash, and per table a row
// count and a content hash.
type inventory struct {
	userVersion   int64
	applicationID int64
	schema        [32]byte
	tables        map[string]tableStat
}

// headerPragmas are the values a database carries in its HEADER rather than in a
// table: an application's own schema version and its file-format tag. A copy
// does not inherit them — measured, not assumed (fidelity_test.go) — and losing
// user_version silently is how a store comes back with a migration framework
// convinced it is looking at version 0.
var headerPragmas = []string{"user_version", "application_id"}

type tableStat struct {
	count   int64
	content [32]byte // commutative sum of per-row hashes over the user columns
}

func readInventory(ctx context.Context, conn *sql.Conn) (inventory, error) {
	var header [2]int64
	for i, p := range headerPragmas {
		if err := conn.QueryRowContext(ctx, "PRAGMA "+p).Scan(&header[i]); err != nil {
			return inventory{}, fmt.Errorf("read %s: %w", p, err)
		}
	}

	rows, err := conn.QueryContext(ctx,
		`SELECT type,name,COALESCE(tbl_name,''),COALESCE(sql,'') FROM sqlite_master `+
			`WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name`)
	if err != nil {
		return inventory{}, err
	}
	var schemaLines, tables []string
	for rows.Next() {
		var typ, name, tbl, ddl string
		if err := rows.Scan(&typ, &name, &tbl, &ddl); err != nil {
			_ = rows.Close()
			return inventory{}, err
		}
		schemaLines = append(schemaLines, typ+"\x1f"+name+"\x1f"+tbl+"\x1f"+ddl)
		if typ == "table" {
			tables = append(tables, name)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return inventory{}, err
	}
	_ = rows.Close()

	sort.Strings(schemaLines)
	h := sha256.New()
	for _, l := range schemaLines {
		writeLP(h, []byte(l))
	}
	inv := inventory{
		userVersion:   header[0],
		applicationID: header[1],
		tables:        make(map[string]tableStat, len(tables)),
	}
	copy(inv.schema[:], h.Sum(nil))

	for _, tbl := range tables {
		st, err := tableContent(ctx, conn, tbl)
		if err != nil {
			return inventory{}, fmt.Errorf("table %q: %w", tbl, err)
		}
		inv.tables[tbl] = st
	}
	return inv, nil
}

// tableContent streams every row and folds a per-row hash into a commutative
// 256-bit sum. Order-independent, so a different scan order does not register as
// a difference; addition rather than XOR, so duplicate rows do not cancel. O(1)
// memory per table.
func tableContent(ctx context.Context, conn *sql.Conn, tbl string) (tableStat, error) {
	q := `SELECT * FROM "` + strings.ReplaceAll(tbl, `"`, `""`) + `"`
	rows, err := conn.QueryContext(ctx, q)
	if err != nil {
		return tableStat{}, err
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return tableStat{}, err
	}
	var st tableStat
	scan := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range scan {
		ptrs[i] = &scan[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return tableStat{}, err
		}
		rh := sha256.New()
		for _, v := range scan {
			encodeValue(rh, v)
		}
		var row [32]byte
		copy(row[:], rh.Sum(nil))
		addInto(&st.content, row)
		st.count++
	}
	return st, rows.Err()
}

// encodeValue writes a type-tagged, length-prefixed encoding of a scanned value,
// so two equal rows hash the same and a NULL never collides with "" or 0.
func encodeValue(h hash.Hash, v any) {
	switch x := v.(type) {
	case nil:
		h.Write([]byte{0})
	case int64:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(x))
		h.Write([]byte{1})
		h.Write(b[:])
	case float64:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], math.Float64bits(x))
		h.Write([]byte{2})
		h.Write(b[:])
	case bool:
		h.Write([]byte{3})
		if x {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
	case []byte:
		h.Write([]byte{4})
		writeLP(h, x)
	case string:
		h.Write([]byte{5})
		writeLP(h, []byte(x))
	case time.Time:
		h.Write([]byte{6})
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(x.UnixNano()))
		h.Write(b[:])
	default:
		h.Write([]byte{9})
		writeLP(h, []byte(fmt.Sprintf("%v", x)))
	}
}

// writeLP writes an 8-byte big-endian length and then the bytes, so a
// concatenation of them is unambiguous.
func writeLP(h hash.Hash, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	h.Write(n[:])
	h.Write(b)
}

// addInto computes acc = (acc + row) mod 2^256, big-endian.
func addInto(acc *[32]byte, row [32]byte) {
	var carry uint16
	for i := 31; i >= 0; i-- {
		s := uint16(acc[i]) + uint16(row[i]) + carry
		acc[i] = byte(s)
		carry = s >> 8
	}
}

// recoverInterrupted resumes a conversion that crashed between the commit steps,
// from the files alone.
//
// A derived key is what makes this readable: the key for a database is a
// function of its owner, so a copy left behind by a crash can always be opened
// and there is no per-file key material that could have been lost with it.
func recoverInterrupted(path string) error {
	tmp := path + tmpSuffix
	if fileExists(path) {
		// The live file is there, so nothing is mid-swap. A leftover tmp is a dead
		// attempt either way. The BACKUP is deliberately left alone: whether it may
		// go depends on the live file opening under its key, which is settle's
		// question and not one that can be answered from the file names.
		if classify(path) != plaintext {
			removeDBFiles(tmp)
		}
		return nil
	}
	switch {
	case fileExists(tmp):
		// Crashed during the swap. tmp is the verified encrypted copy and it
		// opens under the derived key, so finishing is the right move.
		if err := os.Rename(tmp, path); err != nil {
			return fmt.Errorf("cek: finish the interrupted swap into %q: %w", path, err)
		}
		_ = os.Remove(path + "-wal")
		_ = os.Remove(path + "-shm")
		syncDir(filepath.Dir(path))
		// The backup stays until settle has opened what is now in place.
	case fileExists(path + plainBakSuffix):
		// The swap never happened. Put the plaintext back and let it be redone.
		if err := os.Rename(path+plainBakSuffix, path); err != nil {
			return fmt.Errorf("cek: restore the plaintext of %q: %w", path, err)
		}
		removeDBFiles(tmp)
	}
	return nil
}

// state is what a file at a path IS, and it has four answers rather than two on
// purpose. A boolean "is this plaintext" folds absent, empty, truncated and
// encrypted into one false, and a caller that reads that false as "already
// encrypted, my work here is done" will delete the backup for three of them.
type state int

const (
	absent    state = iota // nothing there
	truncated              // there, but too small to be a database
	plaintext              // an UNENCRYPTED SQLite database
	sealed                 // something else: encrypted, or unreadable
)

func classify(path string) state {
	fi, err := os.Stat(path)
	if err != nil {
		return absent
	}
	if fi.Size() < headerLen {
		return truncated
	}
	f, err := os.Open(path)
	if err != nil {
		return sealed
	}
	defer func() { _ = f.Close() }()
	var hdr [headerLen]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return sealed
	}
	if string(hdr[:]) == sqliteMagic {
		return plaintext
	}
	return sealed
}

// shredPlainBak overwrites and removes the transient plaintext left by a commit.
// The overwrite is defence in depth — best effort on a copy-on-write or
// journalling filesystem, where the volume's own encryption is the real control.
// A no-op when there is nothing there.
func shredPlainBak(path string) {
	bak := path + plainBakSuffix
	fi, err := os.Stat(bak)
	if err != nil {
		return
	}
	if f, err := os.OpenFile(bak, os.O_WRONLY, 0); err == nil {
		overwrite(f, fi.Size())
		_ = f.Sync()
		_ = f.Close()
	}
	_ = os.Remove(bak)
}

func overwrite(f *os.File, size int64) {
	const chunk = 1 << 20
	buf := make([]byte, chunk)
	for remaining := size; remaining > 0; {
		n := int64(chunk)
		if remaining < n {
			n = remaining
		}
		if _, err := rand.Read(buf[:n]); err != nil {
			return
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return
		}
		remaining -= n
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// removeDBFiles removes a database and every file SQLite keeps beside it. The
// rollback journal belongs in this list: an ATTACHed target journals in DELETE
// mode, so a crash mid-export leaves one, and clearing the database without it
// would leave a hot journal beside the NEXT attempt's fresh file.
func removeDBFiles(base string) {
	for _, s := range []string{"", "-wal", "-shm", "-journal"} {
		_ = os.Remove(base + s)
	}
}

// syncFile forces a file's contents to the disk. A rename is only as durable as
// what it points at.
func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// syncDir fsyncs a directory so a rename is durable. Best effort: a filesystem
// that refuses the open has already made the rename durable itself.
func syncDir(dir string) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
}

// flock takes an exclusive lock beside the database, so two processes cannot
// convert the same file at once. The lock file is its own path and is never the
// database, so a lost lock cannot damage anything.
func flock(path string) (func(), error) {
	lockPath := path + lockSuffix
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("cek: make room for the lock beside %q: %w", path, err)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cek: open the lock beside %q: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cek: take the lock beside %q: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
