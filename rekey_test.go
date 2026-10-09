package cek

import (
	"os"
	"testing"

	sqlitedrv "github.com/hanzoai/sqlite"
)

func readSecret(t *testing.T, path string, key []byte) string {
	t.Helper()
	db, err := sqlitedrv.OpenDB(path, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow(`SELECT v FROM secret WHERE k = 'UNIVERSE_PIN_TOKEN'`).Scan(&v); err != nil {
		t.Fatalf("read: %v", err)
	}
	return v
}

// A database with its key beside it ends up under its derived key, with every
// row, and with no sidecar: the file alone is now readable by any process that
// holds the master, which is what a durable snapshot of it needs.
func TestRekeyMovesASidecarDatabaseToItsDerivedKey(t *testing.T) {
	master := mk(11)
	if err := SetMaster(master); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ns := mustNS(t, "acme", "")
	path := writeWrappedDEKStore(t, master, ns, "finance", dir)

	if err := Rekey(ns, "finance", path); err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	for _, left := range []string{path + sidecarSuffix, path + rekeyBakSuffix, path + rekeyBakSuffix + sidecarSuffix, path + tmpSuffix} {
		if fileExists(left) {
			t.Fatalf("%s is still there after a rekey", left)
		}
	}
	key, err := DeriveKey(master, ns, "finance")
	if err != nil {
		t.Fatal(err)
	}
	if v := readSecret(t, path, key); v != "written-before-derived-keys" {
		t.Fatalf("read %q under the derived key, want the row that was there", v)
	}
	db, err := Open(ns, "finance", dir)
	if err != nil {
		t.Fatalf("Open after rekey: %v", err)
	}
	db.Close()

	// Again: nothing to do, and nothing changes.
	before, _ := os.ReadFile(path)
	if err := Rekey(ns, "finance", path); err != nil {
		t.Fatalf("second Rekey: %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("a second rekey rewrote a database that had no sidecar")
	}
}

// A database with no sidecar is not touched and nothing is made beside it.
func TestRekeyWithoutASidecarDoesNothing(t *testing.T) {
	setTestMaster(t)
	dir := t.TempDir()
	ns := mustNS(t, "acme", "")
	db, err := Open(ns, "plain", dir)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	path := dir + "/orgs/acme/plain.db"
	if err := Rekey(ns, "plain", path); err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	if fileExists(path + lockSuffix) {
		t.Fatal("a rekey with nothing to do took a lock file beside the database")
	}
}

// Stopped after the original and its sidecar were set aside and before the copy
// moved in: the verified copy finishes the swap, and the original goes once it
// reads.
func TestAnInterruptedRekeyIsFinished(t *testing.T) {
	master := mk(12)
	if err := SetMaster(master); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ns := mustNS(t, "acme", "")
	path := writeWrappedDEKStore(t, master, ns, "books", dir)
	key, _ := DeriveKey(master, ns, "books")
	dek, err := sidecarKey(master, ns, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := export(path, path+tmpSuffix, dek, key); err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := os.Rename(path, path+rekeyBakSuffix); err != nil {
		t.Fatal(err)
	}
	// The sidecar is still beside the absent path: stopped between steps 1 and 2.

	if err := Rekey(ns, "books", path); err != nil {
		t.Fatalf("Rekey after a stop: %v", err)
	}
	if fileExists(path+sidecarSuffix) || fileExists(path+rekeyBakSuffix) || fileExists(path+rekeyBakSuffix+sidecarSuffix) {
		t.Fatal("the finished rekey left the original or a sidecar behind")
	}
	if v := readSecret(t, path, key); v != "written-before-derived-keys" {
		t.Fatalf("read %q, want the row that was there", v)
	}
}

// Stopped after the original was set aside with no copy to put in its place: the
// original and its sidecar go back, and still open as they did.
func TestARekeyWithNoCopyIsRolledBack(t *testing.T) {
	master := mk(13)
	if err := SetMaster(master); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ns := mustNS(t, "acme", "")
	path := writeWrappedDEKStore(t, master, ns, "kms", dir)
	if err := os.Rename(path, path+rekeyBakSuffix); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+sidecarSuffix, path+rekeyBakSuffix+sidecarSuffix); err != nil {
		t.Fatal(err)
	}

	if err := recoverRekey(path); err != nil {
		t.Fatalf("recover: %v", err)
	}
	db, err := Open(ns, "kms", dir)
	if err != nil {
		t.Fatalf("Open after rollback: %v", err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow(`SELECT v FROM secret WHERE k = 'UNIVERSE_PIN_TOKEN'`).Scan(&v); err != nil || v != "written-before-derived-keys" {
		t.Fatalf("the rolled-back original read %q, %v", v, err)
	}
}
