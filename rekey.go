package cek

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hanzoai/namespace"
)

// Moving a database off a key beside it.
//
// A database with a sidecar (sidecar.go) is encrypted under a random DEK that
// only the sidecar holds, so the file alone is unreadable: a copy of it taken
// without its sidecar — a durable snapshot, a backup of the database file, a
// new pod hydrating one — is lost the day the disk holding the sidecar is. Rekey
// moves such a database to the key its owner and subsystem derive, which every
// process that holds the master can reproduce, and then the sidecar goes.
//
// It is Convert's commit discipline with one more file to carry. The copy is
// logical (export, under the DEK, into a fresh database under the derived key),
// verified row for row before anything moves, and committed in an order a crash
// can be read back from (recoverRekey). Until the commit the original and its
// sidecar are the source of truth, and until the copy has been read under its
// derived key the original is kept beside it with its sidecar.

const rekeyBakSuffix = ".rekey.bak" // the original under its DEK, until the copy settles

// Rekey moves the database at path from the key in its sidecar to the key ns and
// subsystem derive, in place, without losing a row.
//
// It is idempotent and cheap to repeat: a database with no sidecar and no
// interrupted rekey costs two stats, so a caller runs it before every open.
func Rekey(ns namespace.Namespace, subsystem, path string) error {
	bak := path + rekeyBakSuffix
	if !fileExists(path+sidecarSuffix) && !fileExists(bak) {
		return nil
	}

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

	if err := recoverRekey(path); err != nil {
		return err
	}
	if !fileExists(path + sidecarSuffix) {
		if fileExists(bak) {
			return settleRekey(path, key) // committed, not yet proven
		}
		return nil
	}
	dek, err := sidecarKey(m, ns, path)
	if err != nil {
		return err
	}
	defer zero(dek)
	return rekey(path, dek, key)
}

// rekey holds the one-way trip, with the lock held and a sidecar beside path.
func rekey(path string, dek, key []byte) error {
	tmp := path + tmpSuffix
	bak := path + rekeyBakSuffix
	removeDBFiles(tmp)

	srcInv, err := export(path, tmp, dek, key)
	if err != nil {
		removeDBFiles(tmp)
		return err
	}
	if classify(tmp) != sealed {
		removeDBFiles(tmp)
		return fmt.Errorf("cek: rekeying %q did not produce an encrypted file — this build cannot encrypt", path)
	}
	if err := verify(tmp, key, srcInv); err != nil {
		removeDBFiles(tmp)
		return fmt.Errorf("cek: the rekeyed copy of %q does not match it, so the original is untouched: %w", path, err)
	}
	for _, sidefile := range []string{"-wal", "-journal"} {
		if fileExists(tmp + sidefile) {
			removeDBFiles(tmp)
			return fmt.Errorf("cek: the rekeyed copy of %q still has a %s file beside it; the original is untouched", path, sidefile)
		}
	}
	if err := syncFile(tmp); err != nil {
		removeDBFiles(tmp)
		return fmt.Errorf("cek: flush the rekeyed copy of %q to disk: %w", path, err)
	}

	// Commit, in the order recoverRekey reads back:
	//  1. the original → bak (its -wal was folded in by export, so it is whole),
	//  2. its sidecar → bak's sidecar, so the pair stays readable together,
	//  3. tmp → path, which now opens under the derived key with no sidecar.
	if err := os.Rename(path, bak); err != nil {
		removeDBFiles(tmp)
		return fmt.Errorf("cek: set the original %q aside: %w", path, err)
	}
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
	if err := os.Rename(path+sidecarSuffix, bak+sidecarSuffix); err != nil {
		_ = os.Rename(bak, path)
		removeDBFiles(tmp)
		return fmt.Errorf("cek: set the sidecar of %q aside: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Rename(bak+sidecarSuffix, path+sidecarSuffix)
		_ = os.Rename(bak, path)
		return fmt.Errorf("cek: swap the rekeyed copy into %q: %w", path, err)
	}
	syncDir(filepath.Dir(path))
	return settleRekey(path, key)
}

// settleRekey proves the database at path reads under its derived key, and only
// then lets the original and its sidecar go.
func settleRekey(path string, key []byte) error {
	if err := settle(path, key); err != nil {
		return fmt.Errorf("cek: the rekeyed %q did not verify (the original is beside it as %s, with its sidecar): %w", path, rekeyBakSuffix, err)
	}
	bak := path + rekeyBakSuffix
	removeDBFiles(bak)
	_ = os.Remove(bak + sidecarSuffix)
	syncDir(filepath.Dir(path))
	return nil
}

// recoverRekey resumes a rekey that stopped between its commit steps, from the
// files alone. With path present the commit either never started (a leftover tmp
// is dead) or finished (the original waits beside it for settleRekey). With path
// absent the original was set aside: a verified copy at tmp finishes the swap,
// and no copy puts the original and its sidecar back.
func recoverRekey(path string) error {
	tmp := path + tmpSuffix
	bak := path + rekeyBakSuffix
	if fileExists(path) {
		if fileExists(path + sidecarSuffix) {
			removeDBFiles(tmp)
		}
		return nil
	}
	if !fileExists(bak) {
		return nil
	}
	if fileExists(tmp) {
		if fileExists(path + sidecarSuffix) {
			if err := os.Rename(path+sidecarSuffix, bak+sidecarSuffix); err != nil {
				return fmt.Errorf("cek: finish setting the sidecar of %q aside: %w", path, err)
			}
		}
		if err := os.Rename(tmp, path); err != nil {
			return fmt.Errorf("cek: finish the interrupted rekey of %q: %w", path, err)
		}
		syncDir(filepath.Dir(path))
		return nil
	}
	if fileExists(bak + sidecarSuffix) {
		if err := os.Rename(bak+sidecarSuffix, path+sidecarSuffix); err != nil {
			return fmt.Errorf("cek: restore the sidecar of %q: %w", path, err)
		}
	}
	if err := os.Rename(bak, path); err != nil {
		return fmt.Errorf("cek: restore the original %q: %w", path, err)
	}
	syncDir(filepath.Dir(path))
	return nil
}
