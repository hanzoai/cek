// Package cek opens a namespace's SQLite database encrypted at rest.
//
// There is one way to do it:
//
//	cek.SetMaster(k)                          // once, at boot, from KMS
//	db, err := cek.Open(ns, "treasury", dir)   // everywhere else
//
// The key is derived from the master and the namespace. It is not generated,
// not wrapped, not stored, and not rotated in place — so there is no unwrap
// step, no rewrap step, no per-file key material to lose, and no migration
// path to maintain. A database is born encrypted or it does not exist. Losing
// the master loses the data, which is the property you want from encryption at
// rest and the reason the master lives in KMS.
//
// The master is process state because that is what it is: one key, injected at
// boot, for every database this process opens. Threading it through every
// caller would not make it less global, only harder to see.
//
// The split of responsibilities is deliberate:
//
//	namespace  names the entity and where its file lives
//	cek        turns the master + that name into the file's key, and opens it
//	sqlite     opens a file under a raw key and knows nothing about who owns it
//	kms        holds the master
//
// Nothing here knows about orgs, users, billing or plugins. It knows a
// namespace, a subsystem, and a master key.
package cek

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/hanzoai/namespace"
	sqlitedrv "github.com/hanzoai/sqlite"
	"golang.org/x/crypto/hkdf"
)

// KeyLen is the length of the master key and of every key derived from it.
const KeyLen = 32

// infoPrefix binds a derived key to this scheme. The version is part of it so
// a future scheme is a new prefix rather than a silent reinterpretation of the
// same bytes.
const infoPrefix = "hanzo/cek/v1/"

// ErrNoMaster reports that no master key has been set, or that one of the
// wrong length was offered.
//
// Open fails with it rather than falling back to an unencrypted file: a
// service that comes up in plaintext because a key was missing has failed
// silently at the only thing this package does.
var ErrNoMaster = errors.New("cek: no master key; call SetMaster with 32 bytes from KMS")

var (
	masterMu sync.RWMutex
	master   []byte
)

// SetMaster installs the master key every database of this process is keyed
// from. Call it once at boot, before the first Open, with the key resolved
// from KMS.
func SetMaster(k []byte) error {
	if len(k) != KeyLen {
		return ErrNoMaster
	}
	masterMu.Lock()
	defer masterMu.Unlock()
	master = append([]byte(nil), k...)
	return nil
}

// SetDevMaster installs a random master for a process with no KMS — tests, and
// a laptop. It reports the key it generated so a caller can log that this is
// what happened. Nothing it writes survives the process, by construction: a
// new random master cannot open the previous run's files.
func SetDevMaster() ([]byte, error) {
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("cek: generate dev master: %w", err)
	}
	if err := SetMaster(k); err != nil {
		return nil, err
	}
	return k, nil
}

// HasMaster reports whether a master key has been installed.
func HasMaster() bool {
	masterMu.RLock()
	defer masterMu.RUnlock()
	return len(master) == KeyLen
}

// DeriveKey returns the key for one database: the master, bound to the
// namespace that owns it and the subsystem it holds.
//
// It is a pure function of its inputs, so the same namespace and subsystem
// always produce the same key. A file therefore reopens after a restart with
// nothing persisted beside it, and two databases never share a key because the
// subsystem is part of the binding.
func DeriveKey(master []byte, ns namespace.Namespace, subsystem string) ([]byte, error) {
	if len(master) != KeyLen {
		return nil, ErrNoMaster
	}
	if ns.IsZero() {
		return nil, errors.New("cek: the zero namespace owns no database")
	}
	if subsystem == "" {
		return nil, errors.New("cek: empty subsystem")
	}

	key := make([]byte, KeyLen)
	info := []byte(infoPrefix + ns.String() + "/" + subsystem)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, info), key); err != nil {
		return nil, fmt.Errorf("cek: derive key: %w", err)
	}
	return key, nil
}

// Open opens the encrypted database holding subsystem for ns, under dir,
// creating it if it does not exist. The returned handle is already keyed;
// callers use it as an ordinary *sql.DB.
//
// The location comes from namespace, so a file and its durable slot are two
// renderings of one name and cannot drift apart.
//
// No error returned here contains the key or a DSN holding it.
func Open(ns namespace.Namespace, subsystem, dir string) (*sql.DB, error) {
	path, err := namespace.Path(dir, ns, subsystem)
	if err != nil {
		return nil, err
	}

	// Create the directory, because this function chose the path. Without it
	// the open SUCCEEDS and the failure surfaces at Close, as "envelope seal:
	// no such file or directory" — every write of that session is lost, after
	// the caller has been told it had a database. A function that picks where a
	// file goes has to make that place exist.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("cek: create directory for %s database: %w", subsystem, err)
	}
	return OpenAt(ns, subsystem, path)
}

// OpenAt opens the encrypted database at path, under the key ns and subsystem
// derive. It is Open for a store whose LOCATION is settled by something other
// than the namespace — a mounted volume that an operator points at a fixed
// place, say, where the file cannot move to suit a naming scheme.
//
// Open is this function over namespace.Path, so there is one derivation and one
// keyed open, and a store that names its own path gets exactly the encryption
// every other store gets.
//
// The caller owns the path, and with it the one thing namespace was protecting:
// two different files opened under the same (ns, subsystem) share a key. Give a
// store its own subsystem and that cannot arise.
func OpenAt(ns namespace.Namespace, subsystem, path string) (*sql.DB, error) {
	masterMu.RLock()
	m := master
	masterMu.RUnlock()

	key, err := DeriveKey(m, ns, subsystem)
	if err != nil {
		return nil, err
	}
	defer zero(key)

	// A database written by the wrapped-DEK scheme has its key beside it, and no
	// derivation reproduces that key — it came from crypto/rand. The sidecar's
	// presence is what says which scheme a file belongs to. See sidecar.go.
	if dek, err := sidecarKey(m, ns, path); err != nil {
		return nil, err
	} else if dek != nil {
		defer zero(dek)
		key = dek
	}

	db, err := sqlitedrv.OpenDB(path, key)
	if err != nil {
		return nil, fmt.Errorf("cek: open %s database for %s: %w", subsystem, ns, err)
	}
	return db, nil
}
