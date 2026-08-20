package cek

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/namespace"
	sqlitedrv "github.com/hanzoai/sqlite"
)

// The identity a sidecar's key was derived under, pinned as literal bytes.
//
// sidecar_golden_test.go pins wrapKey and unwrapDEK for identities written out by
// hand. That leaves the function that BUILDS an identity from a namespace and a
// file id unpinned, and it is the one carrying the owner: change how the owner
// and the file are joined and every sidecar on disk derives a different key,
// while a suite that hands the pieces in already joined stays green.
//
// So these state the composition itself. Every expected value below is a literal
// produced by an implementation of the scheme written separately from this one,
// in another language, from the original source — hanzoai/sqlite v0.4.0's
// lengthPrefixedInfo/DeriveKey/WrapDEK and hanzoai/cloud v1.801.360's
// derivationID and nsPrincipal. That implementation reproduces the vectors in
// sidecar_golden_test.go exactly, which is what makes it a reference rather than
// a second opinion.

// fileID is the 16 random bytes a sidecar opens with. Fixed here so the
// identities below are literals rather than something a test computes.
func fileID() []byte {
	f := make([]byte, fileIDLen)
	for i := range f {
		f[i] = byte(i)
	}
	return f
}

const fileIDHex = "000102030405060708090a0b0c0d0e0f"

// The owner and the file, in that order. A system namespace owns its files as
// the platform and carries the bare file id; every other namespace carries its
// own id ahead of it.
func TestTheIdentityAFileIsWrappedUnder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ns    namespace.Namespace
		ptype string
		id    string
	}{
		{
			name:  "an org",
			ns:    namespace.MustOrg("hanzo"),
			ptype: "org",
			id:    "hanzo/" + fileIDHex,
		},
		{
			// The group names which of an org's files this is; the file id already
			// tells one file from another, so the group is not part of the identity.
			name:  "a project of that org",
			ns:    namespace.MustOrgProject("acme", "web"),
			ptype: "org",
			id:    "acme/" + fileIDHex,
		},
		{
			name:  "the platform",
			ns:    namespace.System(),
			ptype: "global",
			id:    fileIDHex,
		},
		{
			name:  "a group of the platform's own files",
			ns:    namespace.System().WithGroup(namespace.MustGroup("notices")),
			ptype: "global",
			id:    fileIDHex,
		},
		{
			name:  "an org named like the platform",
			ns:    namespace.MustOrg("global"),
			ptype: "org",
			id:    "global/" + fileIDHex,
		},
		{
			// A name chosen to read as a bare file id. It stays an org.
			name:  "an org named like a file id",
			ns:    namespace.MustOrg("0011223344556677889aabbccddeeff0"),
			ptype: "org",
			id:    "0011223344556677889aabbccddeeff0/" + fileIDHex,
		},
		{
			name:  "an org id carrying the shape a folded name gets",
			ns:    namespace.MustOrg("acme-0123456789abcdef"),
			ptype: "org",
			id:    "acme-0123456789abcdef/" + fileIDHex,
		},
		{
			name:  "the longest org id there is",
			ns:    namespace.MustOrg("a" + strings.Repeat("b", 63)),
			ptype: "org",
			id:    "a" + strings.Repeat("b", 63) + "/" + fileIDHex,
		},
		{
			// Not a shape any store has, but it is the branch every namespace that
			// is not the platform takes, and it is what the original mapped too.
			name:  "a namespace that names some other entity",
			ns:    namespace.MustRepo("r1"),
			ptype: "org",
			id:    "r1/" + fileIDHex,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ptype, id := wrapIdentity(tc.ns, fileID())
			if ptype != tc.ptype || id != tc.id {
				t.Fatalf("the identity drifted from the one on disk:\n got (%q, %q)\nwant (%q, %q)", ptype, id, tc.ptype, tc.id)
			}
		})
	}
}

// Two file ids under one owner, to pin that the file is rendered as hex of
// exactly the 16 bytes it is and nothing else is folded in.
func TestTheFileIsRenderedAsItself(t *testing.T) {
	for _, tc := range []struct{ name, raw, id string }{
		{"a zero file id", strings.Repeat("00", fileIDLen), "hanzo/" + strings.Repeat("00", fileIDLen)},
		{"an all-ones file id", strings.Repeat("ff", fileIDLen), "hanzo/" + strings.Repeat("ff", fileIDLen)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			ptype, id := wrapIdentity(namespace.MustOrg("hanzo"), raw)
			if ptype != principalOrg || id != tc.id {
				t.Fatalf("got (%q, %q), want (%q, %q)", ptype, id, principalOrg, tc.id)
			}
		})
	}
}

// The bytes an identity renders to, pinned literally.
func TestThePrincipalEncoding(t *testing.T) {
	for _, tc := range []struct{ name, ptype, id, want string }{
		{
			name:  "an org's file",
			ptype: "org",
			id:    "hanzo/" + fileIDHex,
			want:  "036f72672668616e7a6f2f3030303130323033303430353036303730383039306130623063306430653066",
		},
		{
			name:  "the platform's own file",
			ptype: "global",
			id:    fileIDHex,
			want:  "06676c6f62616c203030303130323033303430353036303730383039306130623063306430653066",
		},
		{
			name:  "the longest identity a namespace can produce",
			ptype: "org",
			id:    strings.Repeat("a", 64) + "/" + fileIDHex,
			want:  "036f726761616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161612f3030303130323033303430353036303730383039306130623063306430653066",
		},
		{
			// The pair that shows the length prefix earning its place: run these
			// together without one and both read "abc".
			name:  "a type that ends where the id begins",
			ptype: "ab",
			id:    "c",
			want:  "0261620163",
		},
		{
			name:  "the same letters split the other way",
			ptype: "a",
			id:    "bc",
			want:  "0161026263",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hex.EncodeToString(principalInfo(tc.ptype, tc.id)); got != tc.want {
				t.Fatalf("the encoding drifted:\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

// read is a reader for the encoding, written from its definition rather than
// from the encoder. principalInfo has no decoder in the package, so this is a
// second implementation and not the first one run backwards: it is what lets
// "these bytes mean exactly one identity" be tested at all.
func read(t *testing.T, b []byte) (ptype, id string) {
	t.Helper()
	field := func(b []byte) ([]byte, []byte) {
		n, w := binary.Uvarint(b)
		if w <= 0 {
			t.Fatalf("no length at the front of %x", b)
		}
		b = b[w:]
		if uint64(len(b)) < n {
			t.Fatalf("length says %d, only %d bytes left", n, len(b))
		}
		return b[:n], b[n:]
	}
	tb, rest := field(b)
	ib, rest := field(rest)
	if len(rest) != 0 {
		t.Fatalf("%d bytes left over", len(rest))
	}
	return string(tb), string(ib)
}

// One identity, one encoding, and the encoding says which. Lengths run across
// 128, where the prefix grows a second byte, and across 16384, where it grows a
// third: those are the two places a length prefix stops being one byte and a
// reader that assumed otherwise would start reading an identity as another.
func TestThePrincipalEncodingSaysWhichIdentityItIs(t *testing.T) {
	lengths := []int{1, 2, 3, 126, 127, 128, 129, 130, 16382, 16383, 16384, 16385}

	seen := map[string][2]int{}
	for _, lt := range []int{1, 2, 3, 127, 128, 129} {
		for _, li := range lengths {
			ptype, id := strings.Repeat("t", lt), strings.Repeat("i", li)
			enc := principalInfo(ptype, id)

			gotType, gotID := read(t, enc)
			if gotType != ptype || gotID != id {
				t.Fatalf("a type of %d and an id of %d read back as %d and %d", lt, li, len(gotType), len(gotID))
			}
			if was, ok := seen[string(enc)]; ok {
				t.Fatalf("(%d, %d) encodes the same as (%d, %d)", lt, li, was[0], was[1])
			}
			seen[string(enc)] = [2]int{lt, li}
		}
	}
}

// An org id and a file id must not run together into a string that could be read
// as some other pair. Two things keep them apart: a namespace id is
// [a-z0-9][a-z0-9_-]* and so carries no separator, and the file is always the
// last 32 characters because it is always 16 bytes. Either alone settles it, so
// this checks both hold for names a person can choose.
func TestTheOwnerAndTheFileStayApart(t *testing.T) {
	names := []string{
		"acme",
		"global",
		"acme/0011223344556677889aabbccddeeff",
		"acme/" + fileIDHex,
		"/" + fileIDHex,
		"a/b/c",
		"ACME",
		"acme.",
		"acme-0123456789abcdef",
		"0011223344556677889aabbccddeeff0",
		strings.Repeat("z", 64),
		"org",
		"système",
		"acme:" + fileIDHex,
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			ns, err := namespace.OrgProject(name, "")
			if err != nil {
				t.Skipf("%q is not a name a namespace can be built from: %v", name, err)
			}
			ptype, id := wrapIdentity(ns, fileID())
			if ptype != principalOrg {
				t.Fatalf("an org rendered as %q", ptype)
			}
			if strings.Contains(ns.ID(), "/") {
				t.Fatalf("the org id %q carries a separator, so the owner no longer ends where the file begins", ns.ID())
			}

			// Read the pair back the two independent ways, and require both to
			// return the owner and the file that went in.
			owner, file, ok := strings.Cut(id, "/")
			if !ok || owner != ns.ID() || file != fileIDHex {
				t.Fatalf("splitting %q at its first separator gave (%q, %q), want (%q, %q)", id, owner, file, ns.ID(), fileIDHex)
			}
			if len(id) < len(fileIDHex)+1 || id[len(id)-len(fileIDHex)-1] != '/' {
				t.Fatalf("%q does not end in a separator and 32 hex characters", id)
			}
			if got := id[len(id)-len(fileIDHex):]; got != fileIDHex {
				t.Fatalf("the last %d characters of %q are %q, want the file id", len(fileIDHex), id, got)
			}
			if got := id[:len(id)-len(fileIDHex)-1]; got != ns.ID() {
				t.Fatalf("what is left of %q is %q, want the owner %q", id, got, ns.ID())
			}
		})
	}
}

// The platform is not a tenant, and no org can be named into becoming it. The
// type is the first field of the encoding and it is length-prefixed, so the two
// forms differ at byte zero however the rest is chosen.
func TestNoOrgCanBeNamedIntoThePlatform(t *testing.T) {
	platform := principalInfo(wrapIdentity(namespace.System(), fileID()))

	for _, name := range []string{
		"global",
		fileIDHex,
		"global-" + fileIDHex,
		"0011223344556677889aabbccddeeff0",
	} {
		t.Run(name, func(t *testing.T) {
			ns, err := namespace.OrgProject(name, "")
			if err != nil {
				t.Skipf("not a usable name: %v", err)
			}
			org := principalInfo(wrapIdentity(ns, fileID()))
			if string(org) == string(platform) {
				t.Fatalf("the org %q encodes exactly as the platform does", name)
			}
			if org[0] == platform[0] {
				t.Fatalf("the org %q and the platform start with the same byte %#x", name, org[0])
			}
		})
	}
}

// The wrapping key for an identity this package COMPOSED, pinned to the key the
// original derived. This is the composition and the derivation in one statement:
// a change to either end fails here.
func TestTheWrappingKeyForAComposedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		ns   namespace.Namespace
		kek  string
	}{
		{"an org", namespace.MustOrg("hanzo"), "ab95e9935e6a8e430c579b0189a1ce7b438ba3a68f0d3c6ec49b99f5194eb265"},
		{"the platform", namespace.System(), "7d66331c88e1d7a2344ca752590c80deb88ad6d73c19ef14c2065c33fc431487"},
		{"another org", namespace.MustOrg("acme-2"), "ccf8ba20b8f73b9a33cfed386805cbfbcfae2e506facba312006e6bc49c12e9a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ptype, id := wrapIdentity(tc.ns, fileID())
			kek, err := wrapKey(goldenMaster(), ptype, id)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(kek); got != tc.kek {
				t.Fatalf("the wrapping key drifted:\n got %s\nwant %s", got, tc.kek)
			}
		})
	}
}

// A sidecar sealed by the other implementation, opened by this one.
//
// Nothing here tells the reader which identity to use: it is handed a namespace
// and a file on disk, and has to arrive at the same owner-and-file the sealer
// used. That is the property the composition exists for, and the reason these
// blobs are literals — sealing them here with the same function that reads them
// would agree with itself whatever it did.
func TestASidecarSealedElsewhereOpensHere(t *testing.T) {
	const dek = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"

	for _, tc := range []struct {
		name      string
		ns        namespace.Namespace
		subsystem string
		blob      string
	}{
		{
			name:      "an org's file",
			ns:        namespace.MustOrg("hanzo"),
			subsystem: "kms",
			blob:      "01a1b2c3d4e5f60718293a4b5cde06ded7ee709daf4af9689176bb794a13c2640f5a04c14088bcf6fef6b46a2d309d1e8dfa898b147bba7fb7e19002a3",
		},
		{
			name:      "the platform's own file",
			ns:        namespace.System(),
			subsystem: "treasury",
			blob:      "01a1b2c3d4e5f60718293a4b5c715726d14491a936bf930fe407fe32c1253e96ead3d4df7963e07111f127d3ba8978f5011d041c8dd85be9ad4cc72a09",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			master := goldenMaster()
			if err := SetMaster(master); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path, err := namespace.Path(dir, tc.ns, tc.subsystem)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}

			key, err := hex.DecodeString(dek)
			if err != nil {
				t.Fatal(err)
			}
			db, err := sqlitedrv.OpenDB(path, key)
			if err != nil {
				t.Fatalf("write a database under the sealed key: %v", err)
			}
			if _, err := db.Exec(`CREATE TABLE secret (v TEXT)`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO secret VALUES ('sealed elsewhere')`); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			blob, err := hex.DecodeString(tc.blob)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+sidecarSuffix, append(fileID(), blob...), 0o600); err != nil {
				t.Fatal(err)
			}

			opened, err := Open(tc.ns, tc.subsystem, dir)
			if err != nil {
				t.Fatalf("open a database whose key was sealed by the other implementation: %v", err)
			}
			defer opened.Close()

			var v string
			if err := opened.QueryRow(`SELECT v FROM secret`).Scan(&v); err != nil {
				t.Fatalf("read the row: %v", err)
			}
			if v != "sealed elsewhere" {
				t.Fatalf("read %q", v)
			}
		})
	}
}
