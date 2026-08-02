# cek

Opens a namespace's SQLite database encrypted at rest.

```go
db, err := cek.Open(master, ns, "treasury", dataDir)
```

The key is derived from the master and the namespace. It is not generated, not
wrapped, not stored, and not rotated in place — so there is no unwrap step, no
rewrap step, no per-file key material to lose, and no migration path to
maintain. A database is born encrypted or it does not exist.

Losing the master loses the data. That is the property you want from encryption
at rest, and the reason the master lives in KMS.

## Where it sits

| | |
|---|---|
| `hanzoai/namespace` | names the entity, and where its file lives |
| `hanzoai/cek` | turns the master + that name into the file's key, and opens it |
| `hanzoai/sqlite` | opens a file under a raw key; knows nothing about who owns it |
| `hanzoai/kms` | holds the master |

Nothing here knows about orgs, users, billing or plugins. It knows a namespace,
a subsystem, and a master key.
