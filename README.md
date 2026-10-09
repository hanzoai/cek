# cek

Opens a namespace's SQLite database encrypted at rest.

```go
cek.SetMaster(k)                            // once, at boot, from KMS
db, err := cek.Open(ns, "treasury", dataDir) // everywhere else
```

The key is derived from the master and the namespace. It is not generated, not
wrapped, not stored, and not rotated in place — so there is no unwrap step, no
rewrap step, no per-file key material to lose, and no migration path to
maintain. A database is born encrypted or it does not exist.

Losing the master loses the data. That is the property you want from encryption
at rest, and the reason the master lives in KMS.

Two kinds of file predate that and are moved onto it in place, each verified row
for row before the original goes: `cek.Convert` encrypts a database written in the
clear, and `cek.Rekey` moves one written under a random key held in a `.dek`
sidecar beside it, which no copy of the database alone can open, to its derived
key. Both are idempotent, so a caller runs them before an open.

## Where it sits

| | |
|---|---|
| `hanzoai/namespace` | names the entity, and where its file lives |
| `hanzoai/cek` | turns the master + that name into the file's key, and opens it |
| `hanzoai/sqlite` | opens a file under a raw key; knows nothing about who owns it |
| `hanzoai/kms` | holds the master |

Nothing here knows about orgs, users, billing or plugins. It knows a namespace,
a subsystem, and a master key.
