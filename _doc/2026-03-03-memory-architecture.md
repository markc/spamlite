# Memory Architecture: Why SQLite Changes Everything

## The spamprobe problem

spamprobe uses BerkeleyDB, which memory-maps the entire `sp_words` file.
When Dovecot's sieve plugin calls `spamprobe receive`, the process:

1. Opens BDB environment (`__db.*` files)
2. Memory-maps the entire `sp_words` file
3. Reads every token probability needed for classification
4. Closes and exits

For a mature mailbox like admin@renta.net with years of training:
- `sp_words`: 1.5 GB
- Virtual memory per invocation: 1.5 GB
- Physical pages faulted in: depends on OS page cache, but worst case = full file

On a server with 600 mailboxes receiving concurrent mail:
- 10 simultaneous classifications = 15 GB virtual memory
- OS page cache thrashes between different users' databases
- BDB's mmap doesn't release pages until process exits

## The SQLite solution

SQLite with a B-tree index on the `word` column:

1. Parse email → extract ~500-2000 unique tokens
2. `SELECT word, good, spam FROM tokens WHERE word IN (?,?,...)`
3. SQLite walks the B-tree index for each token = O(log n) per lookup
4. Only index pages + matching data pages are read from disk

For the same 1.5 GB database:
- Index size: ~50-100 MB (B-tree on TEXT PRIMARY KEY)
- Pages read per classification: ~2000 tokens × ~3 page reads = ~6000 pages = ~24 MB
- But most hot tokens are in the page cache: realistic I/O = ~1-5 MB
- Page cache bounded at 2 MB (`PRAGMA cache_size = 500`)
- Total RSS: ~5-8 MB regardless of database size

## Concurrency: WAL mode

BDB requires `__db.*` environment files shared between processes. If a process
crashes, these files become corrupt and ALL subsequent access deadlocks.

SQLite WAL (Write-Ahead Logging):
- Readers never block writers, writers never block readers
- Multiple concurrent `spamlite receive` processes = no contention
- If a writer crashes, SQLite auto-recovers on next open (WAL replay)
- No equivalent of BDB's `__db.*` corruption scenario

## Practical impact

| Scenario | spamprobe (BDB) | spamlite (SQLite) |
|----------|----------------|-------------------|
| New user (5 MB DB) | 5 MB mmap | ~2 MB RSS |
| Mature user (200 MB DB) | 200 MB mmap | ~5 MB RSS |
| Power user (1.5 GB DB) | 1.5 GB mmap | ~5 MB RSS |
| 10 concurrent classifies | 10× DB size | ~50-80 MB total |
| Process crash during train | BDB corruption, manual recovery | Auto-recovery on next open |
| OpenWrt (256 MB RAM) | Fails for any non-trivial DB | Works fine |

## Token access pattern

Email classification has a very favorable access pattern for SQLite:

1. **Read-heavy:** 99% of operations are classification (read), 1% training (write)
2. **Small working set:** Each message queries ~1000 tokens out of ~500K total
3. **Zipf distribution:** Common tokens (the, is, from) are always hot in cache
4. **Sequential writes:** Training adds/updates tokens one batch at a time

This is exactly the workload SQLite is optimized for.
