package cek

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Golden vectors produced by the ORIGINAL implementation — hanzoai/sqlite
// v0.4.0's DeriveKey / PrincipalAAD / WrapDEK, the code that wrote every sidecar
// on disk today. sidecar.go reproduces that scheme rather than importing it,
// because the driver has since dropped its crypto while the bytes it wrote
// remain. These pin the reproduction to the original, byte for byte.
//
// A drift in the HKDF info, the AAD composition, the version byte or the nonce
// split fails HERE, at `go test`, instead of on a volume holding 211 orgs.
//
// master is 32 bytes of i*7; the DEK is 32 bytes of 255-i.
var goldenSidecars = []struct {
	name  string
	ptype string
	id    string
	kek   string // expected wrapping key
	blob  string // wrapped DEK as stored
	dek   string // expected key after unwrap
}{
	{
		name:  "an org's file",
		ptype: principalOrg,
		id:    "hanzo/0011223344556677889aabbccddeeff",
		kek:   "ff3899c56317d16b84954f2b3be171bc4d1f013d7febbf83a7d49d8812148239",
		blob:  "0109910f7370de21d05566a4f35440e9cdbb0a4702d8e23fba6faccc041cb2205b6b93052973df3ed75f76c2f145f25f03ce9b3df0a213bc33a751fb16",
		dek:   "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
	},
	{
		name:  "the platform's own file",
		ptype: principalGlobal,
		id:    "0011223344556677889aabbccddeeff0",
		kek:   "006910cbbcfac247d7fb17ac188ee571fd0e80c34de6b7ef469b2d0b4c6f9b76",
		blob:  "016c891901185f031cae6f64c6054482196c8941c83b121dae47c679e718d0b185592c511948ca11a94157827afbee645410332c0a8fbd2675a183bffd",
		dek:   "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
	},
}

func goldenMaster() []byte {
	m := make([]byte, KeyLen)
	for i := range m {
		m[i] = byte(i * 7)
	}
	return m
}

// The wrapping key this derives must be the one the original derived, or every
// sidecar on disk is unreadable while every test that builds its own passes.
func TestWrapKeyMatchesTheOriginal(t *testing.T) {
	for _, g := range goldenSidecars {
		t.Run(g.name, func(t *testing.T) {
			kek, err := wrapKey(goldenMaster(), g.ptype, g.id)
			if err != nil {
				t.Fatalf("wrapKey: %v", err)
			}
			if got := hex.EncodeToString(kek); got != g.kek {
				t.Fatalf("wrapping key drifted from the scheme on disk:\n got %s\nwant %s", got, g.kek)
			}
		})
	}
}

// And the wrapped key opens to exactly the DEK that was sealed.
func TestUnwrapMatchesTheOriginal(t *testing.T) {
	for _, g := range goldenSidecars {
		t.Run(g.name, func(t *testing.T) {
			kek, err := wrapKey(goldenMaster(), g.ptype, g.id)
			if err != nil {
				t.Fatalf("wrapKey: %v", err)
			}
			blob, err := hex.DecodeString(g.blob)
			if err != nil {
				t.Fatal(err)
			}
			dek, err := unwrapDEK(kek, blob, principalInfo(g.ptype, g.id))
			if err != nil {
				t.Fatalf("unwrap a sidecar the original wrote: %v", err)
			}
			want, _ := hex.DecodeString(g.dek)
			if !bytes.Equal(dek, want) {
				t.Fatalf("unwrapped %x, want %x", dek, want)
			}
		})
	}
}

// The version byte is authenticated, not merely checked, so a blob renumbered to
// a scheme this does not read cannot be opened by stripping the check.
func TestTheWrapVersionIsAuthenticated(t *testing.T) {
	g := goldenSidecars[0]
	kek, err := wrapKey(goldenMaster(), g.ptype, g.id)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := hex.DecodeString(g.blob)
	blob[0] = 2
	if _, err := unwrapDEK(kek, blob, principalInfo(g.ptype, g.id)); err == nil {
		t.Fatal("a renumbered wrapped key opened anyway")
	}
}

// A sidecar is bound to its principal: the same bytes under another identity
// must not open, or a file carried into another tenant's directory would.
func TestASidecarIsBoundToItsPrincipal(t *testing.T) {
	g := goldenSidecars[0]
	kek, err := wrapKey(goldenMaster(), g.ptype, g.id)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := hex.DecodeString(g.blob)
	if _, err := unwrapDEK(kek, blob, principalInfo(principalOrg, "someone-else/0011223344556677889aabbccddeeff")); err == nil {
		t.Fatal("a wrapped key opened under another principal's binding")
	}
}
