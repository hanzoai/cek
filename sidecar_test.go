package cek

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/namespace"
	sqlitedrv "github.com/hanzoai/sqlite"
)

// wrapForTest seals a DEK the way the original scheme did. It lives in the test
// because cek only ever READS a sidecar — production mints none, so a wrap in
// the package itself would be a capability nothing needs. The golden vectors in
// sidecar_golden_test.go are what prove this agrees with the original; this only
// has to build fixtures.
func wrapForTest(t *testing.T, kek, dek, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	out := append([]byte{wrapVersion}, nonce...)
	return gcm.Seal(out, nonce, dek, append([]byte{wrapVersion}, aad...))
}

// writeWrappedDEKStore builds a database exactly the way the wrapped-DEK scheme
// did: a DEK from crypto/rand, wrapped under a key derived from the owner and a
// random file id, stored in a sidecar beside the database. It returns the path.
//
// It uses the same public primitives the old scheme used, so this is the real
// on-disk format and not an approximation of it.
func writeWrappedDEKStore(t *testing.T, master []byte, ns namespace.Namespace, subsystem, dir string) string {
	t.Helper()

	path, err := namespace.Path(dir, ns, subsystem)
	if err != nil {
		t.Fatalf("namespace.Path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	fileID := make([]byte, fileIDLen)
	if _, err := rand.Read(fileID); err != nil {
		t.Fatalf("file id: %v", err)
	}
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("dek: %v", err)
	}

	ptype, id := wrapIdentity(ns, fileID)
	kek, err := wrapKey(master, ptype, id)
	if err != nil {
		t.Fatalf("wrapKey: %v", err)
	}
	wrapped := wrapForTest(t, kek, dek, principalInfo(ptype, id))
	if err := os.WriteFile(path+sidecarSuffix, append(append([]byte{}, fileID...), wrapped...), 0o600); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}

	db, err := sqlitedrv.OpenDB(path, dek)
	if err != nil {
		t.Fatalf("open under the wrapped DEK: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE secret (k TEXT PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO secret VALUES ('UNIVERSE_PIN_TOKEN','written-before-derived-keys')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return path
}

// A database written under the wrapped-DEK scheme must still open, and its rows
// must still be there. Its pages are encrypted under a key from crypto/rand that
// lives only in the sidecar, so a derived key cannot read them — and the files
// exist, in production, per org and per subsystem. Deriving a key for them and
// shipping is the data becoming unreadable at the moment of a deploy.
func TestAWrappedDEKDatabaseStillOpens(t *testing.T) {
	master := mk(7)
	if err := SetMaster(master); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ns := mustNS(t, "hanzo", "")
	writeWrappedDEKStore(t, master, ns, "kms", dir)

	db, err := Open(ns, "kms", dir)
	if err != nil {
		t.Fatalf("Open on a wrapped-DEK database: %v", err)
	}
	defer db.Close()

	var v string
	if err := db.QueryRow(`SELECT v FROM secret WHERE k = 'UNIVERSE_PIN_TOKEN'`).Scan(&v); err != nil {
		t.Fatalf("read a row written before derived keys: %v", err)
	}
	if v != "written-before-derived-keys" {
		t.Fatalf("read %q, want the row that was there", v)
	}
}

// The system namespace wrapped under the platform identity with a bare file id,
// not under an owner — a different derivation, and it has to be read too.
func TestAWrappedDEKSystemDatabaseStillOpens(t *testing.T) {
	master := mk(9)
	if err := SetMaster(master); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ns := namespace.System()
	writeWrappedDEKStore(t, master, ns, "treasury", dir)

	db, err := Open(ns, "treasury", dir)
	if err != nil {
		t.Fatalf("Open on a wrapped-DEK system database: %v", err)
	}
	defer db.Close()

	var n int
	if err := db.QueryRow(`SELECT count(*) FROM secret`).Scan(&n); err != nil {
		t.Fatalf("read the system store: %v", err)
	}
	if n != 1 {
		t.Fatalf("row count %d, want 1", n)
	}
}

// No sidecar means the key is derived, which is how every new database is born.
// The read path must not disturb that.
func TestWithoutASidecarTheKeyIsStillDerived(t *testing.T) {
	if err := SetMaster(mk(3)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ns := mustNS(t, "acme", "")

	db, err := Open(ns, "treasury", dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE t (x INT)`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	path, _ := namespace.Path(dir, ns, "treasury")
	if _, err := os.Stat(path + sidecarSuffix); !os.IsNotExist(err) {
		t.Fatalf("a derived-key database minted a sidecar (%v) — the read path must not write one", err)
	}
	// And it reopens, which is the property derivation exists for.
	again, err := Open(ns, "treasury", dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer again.Close()
	if _, err := again.Exec(`INSERT INTO t VALUES (1)`); err != nil {
		t.Fatalf("reopened store is not the same store: %v", err)
	}
}

// A damaged sidecar is an error, never a quiet fallthrough to the derived key.
// Falling through reports the database as corrupt when the key material is what
// is damaged, which sends the reader to the wrong file.
func TestADamagedSidecarIsAnError(t *testing.T) {
	master := mk(11)
	if err := SetMaster(master); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ns := mustNS(t, "hanzo", "")
	path := writeWrappedDEKStore(t, master, ns, "kms", dir)

	blob, err := os.ReadFile(path + sidecarSuffix)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0xff // break the GCM tag
	if err := os.WriteFile(path+sidecarSuffix, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(ns, "kms", dir); err == nil {
		t.Fatal("a damaged sidecar opened anyway")
	}
}

// The wrong master key must not be reported as a corrupt database.
func TestTheWrongMasterDoesNotOpenAWrappedDEKDatabase(t *testing.T) {
	written := mk(13)
	if err := SetMaster(written); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ns := mustNS(t, "hanzo", "")
	writeWrappedDEKStore(t, written, ns, "kms", dir)

	if err := SetMaster(mk(14)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ns, "kms", dir); err == nil {
		t.Fatal("a wrapped-DEK database opened under the wrong master key")
	}
}
