package cek

import (
	"bytes"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hanzoai/namespace"
)

func mk(b byte) []byte { return bytes.Repeat([]byte{b}, KeyLen) }

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
	a, err := DeriveKey(mk(1), ns, "treasury")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DeriveKey(mk(1), ns, "treasury")
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
	base, _ := DeriveKey(mk(1), mustNS(t, "acme", ""), "treasury")

	for _, tc := range []struct {
		name string
		key  func() ([]byte, error)
	}{
		{"different master", func() ([]byte, error) { return DeriveKey(mk(2), mustNS(t, "acme", ""), "treasury") }},
		{"different org", func() ([]byte, error) { return DeriveKey(mk(1), mustNS(t, "globex", ""), "treasury") }},
		{"different subsystem", func() ([]byte, error) { return DeriveKey(mk(1), mustNS(t, "acme", ""), "audit") }},
		{"a project of that org", func() ([]byte, error) { return DeriveKey(mk(1), mustNS(t, "acme", "web"), "treasury") }},
		{"the system namespace", func() ([]byte, error) { return DeriveKey(mk(1), namespace.System(), "treasury") }},
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

// The key itself, pinned as literal bytes.
//
// Separating every axis says only that these keys differ from each other. It
// holds just as well for a derivation that has moved, and a derivation that has
// moved is every database of that scheme unopenable. So the bytes are stated,
// and stated for the namespace as it RENDERS: the rendering is part of the
// input, so a drift there would move the key just as surely as a change here.
//
// The values come from an implementation of the scheme written separately from
// this one, in another language — the same reference that reproduces the sidecar
// vectors in sidecar_golden_test.go.
func TestTheDerivedKey(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ns        namespace.Namespace
		renders   string
		subsystem string
		key       string
	}{
		{
			name: "an org", ns: namespace.MustOrg("acme"), renders: "org/acme",
			subsystem: "treasury",
			key:       "668a1f0dde67c9136c17731f0280a04aaf316ee5566e61e1d91fb2f586d50e54",
		},
		{
			name: "a project of that org", ns: namespace.MustOrgProject("acme", "web"), renders: "org/acme/web",
			subsystem: "treasury",
			key:       "470113df9f803d2fe4f42427eaff8acdb00b6f8c1a21ac19e00d826e5394ab11",
		},
		{
			name: "the platform", ns: namespace.System(), renders: "system",
			subsystem: "iam",
			key:       "eb8305eb852bca0abf892d266e581b970d2eb26b3be0508ee57683c9d64ec9e0",
		},
		{
			name: "the platform, another subsystem", ns: namespace.System(), renders: "system",
			subsystem: "treasury",
			key:       "1ef752ea2e5ff0b2ef49d19405f0ebe31e874d8540c2ccdf4ba70fce8211b8ba",
		},
		{
			name: "an org id carrying the shape a folded name gets",
			ns:   namespace.MustOrg("acme-0123456789abcdef"), renders: "org/acme-0123456789abcdef",
			subsystem: "treasury",
			key:       "6660d61a4c4d41ef562a7e6565aa4a6d466767aca5a63786489ac0f945351165",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ns.String(); got != tc.renders {
				t.Fatalf("the namespace renders as %q, want %q — the key is derived from this", got, tc.renders)
			}
			key, err := DeriveKey(goldenMaster(), tc.ns, tc.subsystem)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(key); got != tc.key {
				t.Fatalf("the derived key drifted from the one every database of this scheme was written under:\n got %s\nwant %s", got, tc.key)
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
		{"zero namespace", mk(1), namespace.Namespace{}, "treasury"},
		{"empty subsystem", mk(1), ns, ""},
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
	if err := SetMaster(mk(1)); err != nil {
		t.Fatal(err)
	}

	db, err := Open(ns, "treasury", dir)
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
	if err := SetMaster(mk(1)); err != nil {
		t.Fatal(err)
	}
	_, err := Open(namespace.Namespace{}, "treasury", t.TempDir())
	if err == nil {
		t.Fatal("expected an error")
	}
	if bytes.Contains([]byte(err.Error()), mk(1)) {
		t.Fatal("error leaked the key")
	}
}

// Open must refuse rather than write an unencrypted file when no key is set.
func TestOpenRefusesWithoutAMaster(t *testing.T) {
	masterMu.Lock()
	master = nil
	masterMu.Unlock()

	if HasMaster() {
		t.Fatal("master should be unset")
	}
	if _, err := Open(mustNS(t, "acme", ""), "treasury", t.TempDir()); !errorIs(err, ErrNoMaster) {
		t.Fatalf("got %v, want ErrNoMaster — a missing key must never open plaintext", err)
	}
}

// A dev master must actually key the database, not skip encryption.
func TestDevMasterKeys(t *testing.T) {
	k, err := SetDevMaster()
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != KeyLen || !HasMaster() {
		t.Fatal("dev master not installed")
	}
	db, err := Open(mustNS(t, "acme", ""), "treasury", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
}

func errorIs(err, target error) bool { return err != nil && errors.Is(err, target) }

// Open picks the path, so Open must make it exist. When it did not, the open
// succeeded and Close failed with "envelope seal: no such file or directory" —
// the caller was handed a database and lost every write in it.
func TestOpenCreatesItsDirectoryAndSurvivesClose(t *testing.T) {
	if _, err := SetDevMaster(); err != nil {
		t.Fatal(err)
	}
	// A dir that exists but has none of the namespace subdirectories under it.
	dir := t.TempDir()
	ns := mustNS(t, "acme", "web")

	db, err := Open(ns, "treasury", dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE t (v TEXT)`); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v — writes were lost", err)
	}

	// It must reopen and still have the table: proof the bytes reached disk.
	db2, err := Open(ns, "treasury", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	var n int
	if err := db2.QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil {
		t.Fatalf("the table did not survive: %v", err)
	}
}
