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
	if !isPlaintext(path) {
		// Already encrypted, or not there at all. Either way this has nothing to
		// do, and saying so costs one stat.
		shredPlainBak(path)
		return nil
	}
	return convert(path, key)
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
	if isPlaintext(tmp) {
		removeDBFiles(tmp)
		return fmt.Errorf("cek: converting %q produced a plaintext file — this build has no SQLCipher codec, so it cannot encrypt anything", path)
	}
	if err := verify(tmp, key, srcInv); err != nil {
		removeDBFiles(tmp)
		return fmt.Errorf("cek: the encrypted copy of %q does not match it, so the original is untouched: %w", path, err)
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
// copies every page into a fresh encrypted database at tmp with SQLCipher's own
// sqlcipher_export. The source is only ever read.
func export(path, tmp string, key []byte) (inventory, error) {
	ctx, cancel := context.WithTimeout(context.Background(), convertTimeout)
	defer cancel()

	src, err := openPlain(path)
	if err != nil {
		return inventory{}, err
	}
	defer func() { _ = src.Close() }()
	src.SetMaxOpenConns(1) // ATTACH and sqlcipher_export must meet on ONE connection

	conn, err := src.Conn(ctx)
	if err != nil {
		return inventory{}, fmt.Errorf("cek: take a connection to %q: %w", path, err)
	}
	defer func() { _ = conn.Close() }()

	// A live store carries megabytes of WAL. Fold it in first, so the copy and
	// the backup both hold every committed row.
	if _, err := conn.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return inventory{}, fmt.Errorf("cek: checkpoint %q: %w", path, err)
	}
	srcInv, err := readInventory(ctx, conn)
	if err != nil {
		return inventory{}, fmt.Errorf("cek: read what %q holds: %w", path, err)
	}

	// The key is crypto/rand-derived hex, so it carries no injection surface; the
	// path is a bound parameter. The reopen in convert is what actually settles
	// that the copy is readable under the application's own keyed open.
	attach := fmt.Sprintf(`ATTACH DATABASE ? AS enc KEY "x'%x'"`, key)
	if _, err := conn.ExecContext(ctx, attach, tmp); err != nil {
		return inventory{}, fmt.Errorf("cek: attach the encrypted target: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "SELECT sqlcipher_export('enc')"); err != nil {
		_, _ = conn.ExecContext(ctx, "DETACH DATABASE enc")
		return inventory{}, fmt.Errorf("cek: copy %q into the encrypted target: %w", path, err)
	}
	if _, err := conn.ExecContext(ctx, "DETACH DATABASE enc"); err != nil {
		return inventory{}, fmt.Errorf("cek: detach the encrypted target: %w", err)
	}
	return srcInv, nil
}

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
// a schema hash, and per table a row count and a content hash.
type inventory struct {
	schema [32]byte
	tables map[string]tableStat
}

type tableStat struct {
	count   int64
	content [32]byte // commutative sum of per-row hashes over the user columns
}

func readInventory(ctx context.Context, conn *sql.Conn) (inventory, error) {
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
	inv := inventory{tables: make(map[string]tableStat, len(tables))}
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
		// The live file is there. If it is already encrypted then a leftover tmp
		// is a dead attempt and the backup has served its purpose; a plaintext
		// live file is a conversion that never committed, and convert clears tmp
		// itself before it starts again.
		if !isPlaintext(path) {
			removeDBFiles(tmp)
			shredPlainBak(path)
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
		shredPlainBak(path)
	case fileExists(path + plainBakSuffix):
		// The swap never happened. Put the plaintext back and let it be redone.
		if err := os.Rename(path+plainBakSuffix, path); err != nil {
			return fmt.Errorf("cek: restore the plaintext of %q: %w", path, err)
		}
		removeDBFiles(tmp)
	}
	return nil
}

// isPlaintext reports whether path is an UNENCRYPTED SQLite database — the one
// question that decides whether there is anything to convert. An absent or
// too-small file is not one.
func isPlaintext(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var hdr [headerLen]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return false
	}
	return string(hdr[:]) == sqliteMagic
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

// removeDBFiles removes a database and the two files SQLite keeps beside it.
func removeDBFiles(base string) {
	for _, s := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(base + s)
	}
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
