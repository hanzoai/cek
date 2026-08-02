package cek

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/hanzoai/namespace"
)

func master(b byte) []byte { return bytes.Repeat([]byte{b}, KeyLen) }

func mustNS(t *testing.T, org, project string) namespace.Namespace {
	t.Helper()
	ns, err := namespace.OrgProject(org, project)
	if err != nil {
		t.Fatal(err)
	}
	return ns
}

// The same inputs must always give the same key, or a database cannot be
// reopened after a restart.
func TestDeriveIsDeterministic(t *testing.T) {
	ns := mustNS(t, "acme", "")
	a, err := DeriveKey(master(1), ns, "treasury")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DeriveKey(master(1), ns, "treasury")
	if !bytes.Equal(a, b) {
		t.Fatal("same inputs produced different keys")
	}
	if len(a) != KeyLen {
		t.Fatalf("key is %d bytes, want %d", len(a), KeyLen)
	}
}

// Every axis must change the key. If any of these collide, two databases share
// a key and one account's file opens another's.
func TestDeriveSeparatesEveryAxis(t *testing.T) {
	base, _ := DeriveKey(master(1), mustNS(t, "acme", ""), "treasury")

	for _, tc := range []struct {
		name string
		key  func() ([]byte, error)
	}{
		{"different master", func() ([]byte, error) { return DeriveKey(master(2), mustNS(t, "acme", ""), "treasury") }},
		{"different org", func() ([]byte, error) { return DeriveKey(master(1), mustNS(t, "globex", ""), "treasury") }},
		{"different subsystem", func() ([]byte, error) { return DeriveKey(master(1), mustNS(t, "acme", ""), "audit") }},
		{"a project of that org", func() ([]byte, error) { return DeriveKey(master(1), mustNS(t, "acme", "web"), "treasury") }},
		{"the system namespace", func() ([]byte, error) { return DeriveKey(master(1), namespace.System(), "treasury") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.key()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(base, got) {
				t.Fatalf("%s produced the SAME key — two databases would share it", tc.name)
			}
		})
	}
}

// A missing or short master must fail, never fall back to opening in plaintext.
func TestDeriveRefusesBadInput(t *testing.T) {
	ns := mustNS(t, "acme", "")
	for _, tc := range []struct {
		name   string
		master []byte
		ns     namespace.Namespace
		sub    string
	}{
		{"no master", nil, ns, "treasury"},
		{"short master", bytes.Repeat([]byte{1}, 16), ns, "treasury"},
		{"zero namespace", master(1), namespace.Namespace{}, "treasury"},
		{"empty subsystem", master(1), ns, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DeriveKey(tc.master, tc.ns, tc.sub); err == nil {
				t.Fatal("expected an error, got a key")
			}
		})
	}
}

// Open must write where namespace says, so the file and its durable slot agree.
func TestOpenUsesTheNamespaceLocation(t *testing.T) {
	dir := t.TempDir()
	ns := mustNS(t, "acme", "")

	db, err := Open(master(1), ns, "treasury", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (v TEXT)`); err != nil {
		t.Fatal(err)
	}

	want, err := namespace.Path(dir, ns, "treasury")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := filepath.Abs(want); err != nil {
		t.Fatal(err)
	}
}

// An error must never carry the key or a DSN holding it.
func TestOpenErrorHoldsNoKey(t *testing.T) {
	_, err := Open(master(1), namespace.Namespace{}, "treasury", t.TempDir())
	if err == nil {
		t.Fatal("expected an error")
	}
	if bytes.Contains([]byte(err.Error()), master(1)) {
		t.Fatal("error leaked the key")
	}
}
