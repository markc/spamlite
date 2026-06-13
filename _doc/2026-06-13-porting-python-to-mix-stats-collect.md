# Porting spamlite-stats-collect from Python to Mix — evaluation & test case

**Status: evaluation only — no code written yet.** This doc is the journaled
test case for the general situation "a production python3 script needs to
become Mix" (the never-Python rule). Every claim below was verified against
mix 0.17.0 (`/opt/cosmix/bin/mix`, the binary now on both cachyos and mrn) or
against GNU coreutils/findutils on mrn itself. Probe scripts ran live; the
binary is the oracle.

## The subject

`mrn:/usr/local/bin/spamlite-stats-collect` — 292 lines of python3, the
nightly (04:15) per-user score-histogram and correction collector. Its own
header says "Python prototype — will be rewritten in Rust once the
methodology is validated"; the methodology has been validated for 2 months,
and the rewrite target is Mix, not Rust (it's glue, not a hot path). Design
rationale lives at `~/.ns/blsyd/bl01/b1/mrn/_journal/2026-04-11.md`.

What it does, per user with a `.spamlite/` dir (~211 on mrn):

1. Cursor = ctime of `~/.spamlite-stats.jsonl` (first run: now − 24h).
2. Scan `Maildir/{cur,new}` and `Maildir/.Junk/{cur,new}` for messages with
   ctime ≥ cursor, deduped by inode within the run.
3. From each message's first 8 KiB, regex out
   `X-Spam-Status: (SPAM|GOOD) <score>`; bin scores into 10 buckets of 0.1.
4. Count corrections: fn = in Junk but scored GOOD; fp = in Inbox but SPAM.
5. `spamlite counts` (subprocess, 30s timeout) for `[good, spam, tokens]`.
6. Append one compact JSONL line `{d, db, in, jk, corr, w}` to the stats
   file; chown it back to the mailbox owner, chmod 0644.
7. Skip-if-already-written-today (last line's `d` field), `--force`,
   `--user PATH`, `--dry-run` flags; warn-and-continue error model;
   `[done] users= ok= skip= err= elapsed=` summary. Last full run: 211
   users, 89s.

## Construct-by-construct mapping (verified)

| Python | Mix 0.17.0 | Status |
|---|---|---|
| `glob.glob("/srv/*/msg/*/.spamlite")` | `glob(...)` | ✓ |
| `re.compile(rb"^X-Spam-Status:...", I\|M)` w/ groups | `regex_find("(?im)^X-Spam-Status:\\s*(SPAM\|GOOD)\\s+([0-9.]+)", $s)` → `[{match, start, end, groups}]` | ✓ probed |
| `open(rb).read(8192)` | `read_file_bytes($p)` + `bytes_to_string` | ⚠ reads WHOLE file — no byte cap (gap 3) |
| `int(score * 10)` (bucket) | `to_number(fmt("%d", $score * 10))` — `%d` truncates (9.99→9, probed) | ✓ |
| `os.scandir` + `entry.stat()` ctime/inode | **no `stat()` builtin** (gap 1) — workaround: GNU find (below) | ✗→shell |
| ctime-vs-cursor filter | `find DIR -maxdepth 1 -type f -newercc STATSFILE` — exact ctime-vs-ctime cursor semantics, verified on mrn; first run: `-newerct "@<epoch>"` | ✓ via find |
| inode dedupe (`set()`) | `find -printf "%i\t%p\n"` + map-as-set `$seen["" .. $ino] = true` / `has_key` | ✓ probed |
| `os.stat().st_uid/st_gid` | **no builtin** — `run_rc("stat -c '%u %g' ...")`, once per user | ✗→shell |
| `os.chown` | **no `chown()` builtin** (gap 2) — `run_rc("chown UID:GID path")` | ✗→shell |
| `os.chmod(0o644)` | `chmod($p, 0o644)` native | ✓ |
| `subprocess.run([...], timeout=30)` | `run_rc("timeout 30 /usr/local/bin/spamlite -d ... counts")` — run_rc has no timeout opt; coreutils `timeout` does the job | ✓ |
| counts parsing (`split(":",1)`, startswith) | `split`/`trim`/`lower`/`starts_with`/`to_number` | ✓ |
| `json.dumps(separators=(",",":"))` | `json_encode` — compact, but **sorts keys alphabetically** (probed: `{d,db,corr}` → `{"corr":..,"d":..,"db":..}`); consumers (threshold-digest, tuner) use json_parse so order is irrelevant, but lines won't be byte-identical to python's | ✓ (cosmetic diff) |
| last-line `d` check | `read_lines($p)` + `$lines[-1]` + `json_parse(...)["d"]`. NB: stats files are 1 line/day — no need for python's seek-from-end trick. NB2: the `corr` map has a field named `fn` — **`fn` is reserved, must use `["fn"]` never `.fn`** (bit us in the digest port) | ✓ |
| `--force/--dry-run/--user P` argv | `getopt(args(), {"force": {}, "dry-run": {}, "user": {"arg": true}})` → `{opts, rest, errors}` (probed; spec values are maps, `{"arg": true}` for value opts) | ✓ |
| `dt.date.today().isoformat()`, window strings | `date_format(time(), "%Y-%m-%d")`, `date_format(time() - 86400, "%Y-%m-%dT%H:%M")` (probed) | ✓ |
| elapsed seconds | `time()` delta + `fmt("%.1f", ...)` | ✓ |
| warn to stderr | shell-dispatch `>&2` is for shell lines, not `print` — emit via `run_rc("echo ... >&2")` is ugly; simplest: print `warn:` lines to stdout (cron merges 2>&1 into the log anyway) or check for an `eprint` builtin at port time | ⚠ minor |
| try/except per user, continue | `try`/`catch $e` + `continue` | ✓ |
| `os.nice(19)` + self-ionice | drop — the cron entry already wraps with `ionice -c3 nice -n19`; belt-and-braces self-renice not worth a fork | ✓ (drop) |

## The three Mix gaps found (the test-case payoff)

Per the tooling policy, filesystem **primitives** belong in
`cosmix-lib-mix/src/builtins.rs`, not in shell-outs:

1. **`stat($path)`** → map `{uid, gid, size, mode, ino, ctime, mtime, atime,
   is_file, is_dir, is_symlink}` (epoch-seconds f64). Unlocks scandir-style
   loops without forking. THE missing primitive here.
2. **`chown($path, $uid, $gid)`** — natural sibling of the existing native
   `chmod`. Numeric uid/gid is enough (libc::chown; name resolution can wait).
3. **`read_file_bytes($path, $max)`** — optional second arg to cap the read
   (`File::open` + `take(n)`). Without it, header-sniffing a 20 MB attachment
   message reads all 20 MB to use 8 KiB.

None of these block the port (find/stat/chown shell-outs are sanctioned —
"the exception is when shelling out is genuinely the right tool (e.g. ssh,
find, getent)" — and `find` is doing real work here: ctime filtering +
inode printing in one fork per folder). But (1) and (2) are exactly the kind
of primitive the policy says to add rather than work around, and (3) is a
two-line builtin improvement.

## Port strategies

**A. Port now, zero Mix changes (~150–180 lines of Mix).**
Per user: 4 × `find -newercc` forks (folder scans), 1 × `stat -c '%u %g'`,
1 × `timeout 30 spamlite counts`, 1 × `chown` ≈ 7 forks/user ≈ 1,500 total —
the python original already forks `spamlite counts` 211× and the whole run
is ionice'd; elapsed should stay in the same 90s ballpark. Header reads via
`read_file_bytes` whole-file (slightly more IO than python's 8 KiB reads;
mostly irrelevant because the nightly delta is ~2.5k messages).

**B. Add the three builtins first, then port pure.**
~1–2h in `cosmix-lib-mix` (builtins.rs + unit tests + AGENTS.md update +
version bump in both Cargo.tomls), rebuild, redeploy `/opt/cosmix/bin/mix`
fleet-wide + mrn, then the port needs shell-outs only for `spamlite counts`
(genuine subprocess) — everything else native. Faster (no find forks) and
the fleet gets `stat`/`chown` forever.

**Recommendation: B-then-A-shaped hybrid.** Add `stat()` + `chown()` (+ the
`read_file_bytes` cap) to mix first — this IS the test case's point, mrn just
got current mix today so redeploying a 0.17.1 there is now trivial — then
write the port using `stat()` for uid/gid/inode/ctime but **keep
`find -newercc` for the folder scans** (one fork that filters thousands of
entries beats thousands of `stat()` evaluator calls; find is the right tool).
Cutover plan: run the Mix port with `--dry-run` against live /srv, diff its
would-write JSONL lines against the python run's actual lines for the same
day (field-by-field via json_parse, since key order differs), then swap the
cron target and keep the python original as `*.bak-py` for one cycle.

## Generalised lessons (for the next Python→Mix port)

- **Inventory the binary's builtins first** — grep the registry in
  `cosmix-lib-mix/src/builtins.rs` (`'"name" =>'`), don't guess from
  AGENTS.md alone; `append_file`, `getopt`, `regex_find` with groups, and
  `walk` all existed and weren't in the cheat-sheet's verified list.
- **Probe semantics, not just existence**: `fmt("%d")` truncation,
  `json_encode` key ordering, `getopt` spec shape were all
  probe-discovered in minutes with `mix -c` / a probe file.
- **`os.stat`-shaped code is the #1 friction point** — Python leans on
  cheap per-entry stat everywhere; Mix's answer is either a new `stat()`
  builtin or GNU find doing the filter server-side. Choose find when the
  filter discards most entries; choose stat() when you need the metadata
  of things you're keeping anyway.
- **Watch reserved words colliding with data fields**: `.fn` (and any
  future `.step`) in JSON-derived maps must be `["fn"]`-indexed.
- **Error-model translation**: python's try/except-warn-continue maps
  cleanly to `try`/`catch $e`/`continue`; `subprocess` timeout maps to
  coreutils `timeout N` inside `run_rc` (only `ssh_run` has native
  timeouts).
- The python reference stays at `mrn:/usr/local/bin/spamlite-stats-collect`
  (and `*.bak-py` after cutover) — it does NOT get committed to this repo.
