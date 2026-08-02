// Package cek opens a namespace's SQLite database encrypted at rest.
//
// There is one way to do it:
//
//	db, err := cek.Open(master, ns, "treasury", dataDir)
//
// The key is derived from the master and the namespace. It is not generated,
// not wrapped, not stored, and not rotated in place — so there is no unwrap
// step, no rewrap step, no per-file key material to lose, and no migration
// path to maintain. A database is born encrypted or it does not exist. Losing
// the master loses the data, which is the property you want from encryption at
// rest and the reason the master lives in KMS.
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
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"

	"github.com/hanzoai/namespace"
	sqlitedrv "github.com/hanzoai/sqlite"
	"golang.org/x/crypto/hkdf"
)

// KeyLen is the length of both the master key and every derived key.
const KeyLen = 32

// info binds a derived key to this scheme, this namespace and this subsystem.
// Changing any part of it changes every key, which is why the version is in
// it: a future scheme is a new prefix, not a silent reinterpretation of the
// same bytes.
const infoPrefix = "hanzo/cek/v1/"

// ErrNoMaster reports a master key that is missing or the wrong length. It is
// deliberately fatal to Open rather than falling back to plaintext: a service
// that starts unencrypted because a key was absent has failed silently at the
// only job this package has.
var ErrNoMaster = errors.New("cek: master key must be " + itoa(KeyLen) + " bytes")

// DeriveKey returns the key for one database: the master, bound to the
// namespace that owns it and the subsystem it holds.
//
// It is a pure function of its inputs. The same namespace and subsystem always
// produce the same key, so a file can be opened again after a restart with
// nothing persisted alongside it, and two different databases never share a
// key because the subsystem is part of the binding.
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
// The error never contains the key or a DSN that holds it.
func Open(master []byte, ns namespace.Namespace, subsystem, dir string) (*sql.DB, error) {
	key, err := DeriveKey(master, ns, subsystem)
	if err != nil {
		return nil, err
	}

	path, err := namespace.Path(dir, ns, subsystem)
	if err != nil {
		return nil, err
	}

	db, err := sqlitedrv.OpenDB(path, key)
	if err != nil {
		return nil, fmt.Errorf("cek: open %s database for %s: %w", subsystem, ns, err)
	}
	return db, nil
}

// itoa avoids importing strconv for one constant in an error string.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
