package cek

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/hanzoai/namespace"
	sqlitedrv "github.com/hanzoai/sqlite"
)

// Reading a database written by the wrapped-DEK scheme.
//
// Before derived keys, every database was born with a DEK from crypto/rand,
// wrapped under a key derived from its owner and a random file id, and stored
// beside it as "<database>.dek". The pages are encrypted under that random DEK
// and under nothing else — so no derivation reproduces it, and a derived key
// meets those pages as SQLCipher meets a wrong key: "file is not a database",
// at the first statement rather than at open.
//
// Those files exist. Deriving a key for them and calling it a day would not be
// a migration, it would be the data becoming unreadable at the moment of a
// deploy. So Open asks the one question that decides which key a file has: is
// there a sidecar next to it? A sidecar means the key is in the sidecar. No
// sidecar means the key is derived. The file says which scheme it belongs to,
// which is the only thing that can say it.
//
// This is a READ path and deliberately nothing more. It mints no sidecar, wraps
// no key and rewrites no file, so a database opened here stays exactly as it is
// and can be converted later by something whose job that is. New databases are
// born with derived keys and no sidecar, so this code governs a set that only
// shrinks and can be deleted with the last of them.

// sidecarSuffix is the sidecar's name beside the database it holds the key for.
const sidecarSuffix = ".dek"

// fileIDLen is the length of the random file id the sidecar opens with. It binds
// the wrapping key to this one file: sidecar = fileID(16) || wrapped-DEK.
const fileIDLen = 16

// sidecarKey returns the DEK held beside path, or nil when there is no sidecar
// and the key is therefore derived.
//
// An unreadable or malformed sidecar is an ERROR, never a fallthrough to the
// derived key. Falling through would turn "this store's key material is damaged"
// into "file is not a database" three frames later, which reads like corruption
// of the database rather than of the sidecar and sends the reader to the wrong
// file. It also refuses to be the path by which a store silently reopens under a
// key that cannot possibly decrypt it.
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

	kek, err := sqlitedrv.DeriveKey(master, ptype, id)
	if err != nil {
		return nil, fmt.Errorf("cek: derive the sidecar's wrapping key: %w", err)
	}
	defer zero(kek)

	dek, err := sqlitedrv.UnwrapDEK(kek, wrapped, sqlitedrv.PrincipalAAD(ptype, id))
	if err != nil {
		// GCM authenticated the blob and it did not verify: a different master
		// key, or a damaged sidecar. Both are "the key is not here", and neither
		// yields a partial key.
		return nil, fmt.Errorf("cek: unwrap the key beside this database (wrong master key or damaged sidecar): %w", err)
	}
	return dek, nil
}

// wrapIdentity is the identity the sidecar's wrapping key was derived under:
// the owner and the file, in that order, so neither alone determines the key.
// A system namespace owned its files as the platform and carries the bare file
// id; every other namespace carries its own id ahead of it.
//
// This has to reproduce the old scheme EXACTLY — it is reading key material that
// already exists, not choosing a convention.
func wrapIdentity(ns namespace.Namespace, fileID []byte) (sqlitedrv.PrincipalType, string) {
	id := hex.EncodeToString(fileID)
	if ns.Kind() == namespace.KindSystem {
		return sqlitedrv.PrincipalGlobal, id
	}
	return sqlitedrv.PrincipalOrg, ns.ID() + "/" + id
}

// zero clears key material once it is no longer needed. It is not a guarantee
// against a determined memory reader; it shortens the window.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
