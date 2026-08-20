package cek

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/hanzoai/namespace"
	"golang.org/x/crypto/hkdf"
)

// Reading a database whose key is beside it.
//
// Before derived keys, every database was born with a DEK from crypto/rand,
// wrapped under a key derived from its owner and a random file id, and stored
// beside it as "<database>.dek". The pages are encrypted under that random DEK
// and under nothing else — so no derivation reproduces it, and a derived key
// meets those pages as SQLCipher meets a wrong key: "wrong key or corrupted
// page", at the first statement rather than at open.
//
// Those files exist, per org and per subsystem. Deriving a key for them and
// calling it a day would not be a migration, it would be the data becoming
// unreadable at the moment of a deploy. So Open asks the one question that
// decides which key a file has: is there a sidecar next to it. A sidecar means
// the key is in the sidecar. No sidecar means the key is derived. The file says
// which scheme it belongs to, which is the only thing that can say it.
//
// THE SCHEME IS REPRODUCED HERE, NOT IMPORTED. It used to come from the sqlite
// driver, which has since dropped its crypto — correctly: a driver opens a file
// under a key it is handed and has no business deriving one. But a format is not
// retired by the code that used to write it, because the bytes on disk still
// have it. Key material is cek's concern, so cek states it. It is HKDF and GCM,
// pinned by golden vectors produced under the original implementation, so a
// silent drift fails a test rather than a volume.
//
// This is a READ path and deliberately nothing more. It mints no sidecar, wraps
// no key and rewrites no file, so a database opened here stays exactly as it is
// and can be converted later by something whose job that is. New databases are
// born with derived keys and no sidecar, so this governs a set that only
// shrinks, and it can be deleted with the last of them.

const (
	// sidecarSuffix is the sidecar's name beside the database it holds a key for.
	sidecarSuffix = ".dek"
	// fileIDLen is the random file id the sidecar opens with. It binds the
	// wrapping key to this one file: sidecar = fileID(16) || wrapped-DEK.
	fileIDLen = 16
	// wrapVersion is byte 0 of a wrapped DEK, and also leads the GCM additional
	// data, so a downgrade cannot authenticate.
	wrapVersion = 1
	// dekLen is the length of an unwrapped DEK.
	dekLen = 32
)

// The principal a file was wrapped under. These strings went into the HKDF info
// that already exists on disk, so they are format, not naming.
const (
	principalGlobal = "global"
	principalOrg    = "org"
)

// sidecarKey returns the DEK held beside path, or nil when there is no sidecar
// and the key is therefore derived.
//
// An unreadable or malformed sidecar is an ERROR, never a fallthrough to the
// derived key. Falling through would turn "this store's key material is damaged"
// into "wrong key or corrupted page" three frames later, which reads as
// corruption of the database rather than of the sidecar and sends the reader to
// the wrong file. It also refuses to be the path by which a store silently
// reopens under a key that cannot possibly decrypt it.
func sidecarKey(master []byte, ns namespace.Namespace, path string) ([]byte, error) {
	blob, err := os.ReadFile(path + sidecarSuffix)
	if os.IsNotExist(err) {
		return nil, nil // no sidecar: the key is derived
	}
	if err != nil {
		return nil, fmt.Errorf("cek: read key sidecar: %w", err)
	}
	if len(blob) <= fileIDLen {
		return nil, fmt.Errorf("cek: key sidecar is %d bytes, too short to hold a file id and a wrapped key", len(blob))
	}

	fileID, wrapped := blob[:fileIDLen], blob[fileIDLen:]
	ptype, id := wrapIdentity(ns, fileID)

	kek, err := wrapKey(master, ptype, id)
	if err != nil {
		return nil, err
	}
	defer zero(kek)

	dek, err := unwrapDEK(kek, wrapped, principalInfo(ptype, id))
	if err != nil {
		// SAY WHICH IDENTITY. The wrapping key is HKDF over the master AND the
		// principal, so three different things make this fail and only one of them
		// is the master. Naming the identity this open derived is what separates
		// them: compare it with the identity that sealed the file and a mismatch
		// is visible, where "wrong key or damaged sidecar" sends the reader to
		// hunt for a lost master that was never lost.
		return nil, fmt.Errorf("cek: the key beside this database does not open under %s %q — the master, the identity, or the sidecar itself differs from the one that sealed it: %w", ptype, id, err)
	}
	return dek, nil
}

// wrapIdentity is the identity a sidecar's wrapping key was derived under: the
// owner and the file, in that order, so neither alone determines the key. A
// system namespace owned its files as the platform and carries the bare file id;
// every other namespace carries its own id ahead of it.
func wrapIdentity(ns namespace.Namespace, fileID []byte) (ptype, id string) {
	f := hex.EncodeToString(fileID)
	if ns.Kind() == namespace.KindSystem {
		return principalGlobal, f
	}
	return principalOrg, ns.ID() + "/" + f
}

// principalInfo is the injective HKDF info, and the GCM additional data, for one
// (type, id):
//
//	uvarint(len(type)) || type || uvarint(len(id)) || id
//
// The length prefixes make it injective across the type/id boundary, so no two
// identities render to the same bytes.
func principalInfo(ptype, id string) []byte {
	t, i := []byte(ptype), []byte(id)
	out := make([]byte, 0, 2*binary.MaxVarintLen64+len(t)+len(i))
	var n [binary.MaxVarintLen64]byte
	out = append(out, n[:binary.PutUvarint(n[:], uint64(len(t)))]...)
	out = append(out, t...)
	out = append(out, n[:binary.PutUvarint(n[:], uint64(len(i)))]...)
	return append(out, i...)
}

// wrapKey derives the key a sidecar's DEK was wrapped under: HKDF-SHA256 over
// the master, no salt, bound to the principal.
func wrapKey(master []byte, ptype, id string) ([]byte, error) {
	if len(master) != KeyLen {
		return nil, ErrNoMaster
	}
	kek := make([]byte, KeyLen)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, principalInfo(ptype, id)), kek); err != nil {
		return nil, fmt.Errorf("cek: derive the sidecar's wrapping key: %w", err)
	}
	return kek, nil
}

// unwrapDEK opens a wrapped DEK — version(1) || nonce(12) || ciphertext||tag,
// AES-256-GCM — with the version byte leading the additional data.
//
// A failure here is "this key does not open this envelope", and that is all it
// is: the caller holds the identity the key was derived under and says which one
// it tried. GCM authenticates before it returns anything, so there is no partial
// key to hand back.
func unwrapDEK(kek, blob, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("cek: aes-256: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cek: aes-256-gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(blob) < 1+ns+gcm.Overhead() {
		return nil, fmt.Errorf("cek: wrapped key is %d bytes, too short", len(blob))
	}
	if blob[0] != wrapVersion {
		return nil, fmt.Errorf("cek: wrapped key version %d is not one this reads", blob[0])
	}
	dek, err := gcm.Open(nil, blob[1:1+ns], blob[1+ns:], append([]byte{wrapVersion}, aad...))
	if err != nil {
		return nil, fmt.Errorf("cek: the wrapped key does not authenticate: %w", err)
	}
	if len(dek) != dekLen {
		return nil, fmt.Errorf("cek: unwrapped key is %d bytes, not %d", len(dek), dekLen)
	}
	return dek, nil
}

// zero clears key material once it is no longer needed. It is not a guarantee
// against a determined memory reader; it shortens the window.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
