# Spamlite Improvement Plan

**Context:** spamlite is a Rust rebuild of Spamprobe-style Bayesian filtering, deployed on `mail.renta.net` serving ~216 users across the hosting cluster. Daily digest reports fn/fp counts per user against a global threshold of 0.6. This plan was developed after auditing spamlite against Spamprobe 1.4d source and analysing the 2026-04-14 digest.

**Goal:** Produce a best-of-breed Bayesian filter that exceeds Spamprobe's accuracy, not a faithful port. Where Spamprobe and modern techniques diverge, pick the better option.

**Success criterion:** Measurable improvement in the daily digest's fn/fp numbers, attributable to specific changes.

## Key findings from the audit and digest

1. **215 of 216 users are clustered near 5000/5000 good/spam corpus.** This is too tight to be organic. Two hypotheses: (a) bulk seed import from an older Spamprobe/Bogofilter dump, or (b) a message-count *cap* inherited from the original Spamprobe deployment's `maxHashTableSize`. **Confirming which it is is prerequisite to everything else** — a cap means "remove the cap and let corpora grow"; a seed means "refresh the seed." The two fixes are different.

2. **The cluster is healthy except for two specific users.** Removing `thenutfarm` (15 fp, corpus skewed 2243/11222) and `cam@ck20` (5 fp, balanced corpus) leaves 21 fn and 10 fp across 214 users in 24h. That's not an algorithm problem. thenutfarm is corpus imbalance — no classifier change fixes a 5× spam-to-ham prior. cam@ck20 is a debugging target requiring per-message token inspection.

3. **The Fisher vs Robinson decision from the audit is settled: keep Fisher.** Fisher chi-square combining is more principled than Robinson's geometric mean and benchmarks better. Spamprobe used Robinson because Burton wrote it before Fisher was popularised in spam filtering, not because Robinson is superior. Delete item 5 from the original audit.

4. **Spamprobe's `unknown_prob=0.3` and `good_bias=2` are cost-asymmetry hacks, not algorithmic improvements.** They encode "false positives hurt more than false negatives," which is correct for our setup — but they should be config-exposed, not hardcoded, and defaults should be tuned to the cluster's actual fp/fn ratio rather than copied from Spamprobe's 2004 values.

5. **24-hour live iteration is too short to distinguish signal from noise.** At ~21 fn and ~30 fp per day cluster-wide, normal variance swamps small accuracy improvements. We need shadow mode (run the new classifier alongside the old one, log decisions without acting on them) to evaluate changes in hours, and a minimum week-long observation window before drawing conclusions from live digest data.

## Plan

### Phase 0 — Findings (2026-04-14, RESOLVED)

Investigation done. The 5000/5000 cluster pattern is **neither a cap nor a refreshable seed** — it's the result of spamlite running in accidental read-only mode. Source evidence below.

**Not a cap (Spamprobe side):** `admin_maildir/.spamprobe.backup/sp_words` = 880 KB (Jul 2025) vs `.spamprobe/sp_words` = 67 MB (Mar 2026). 77× growth in 8 months under identical sieve wiring. A `maxHashTableSize` ceiling would have produced a flat file. Rejected.

**Not a cap (spamlite side):** `src/storage.rs` read top to bottom. `train()` is a straight `INSERT … ON CONFLICT DO UPDATE SET good/spam + 1`. No row limit, size ceiling, or ingestion guard. The only pruning is the explicit `cleanup()` CLI command. Rejected.

**Sieve wiring is identical for both classifiers.** `/etc/dovecot/sieve/global.sieve` on mrn calls `spamfilter ... receive` on inbound; `/etc/dovecot/sieve/retrain-as-{ham,spam}.sieve` are IMAP-triggered on user folder moves. Both classifiers see the same corrections stream. The wrapper at `/usr/local/bin/spamfilter` dispatches between them by checking for `.spamlite/` existence, calling `spamlite -d ... -t 0.6 receive` or `spamprobe -c -d ... receive`. `-c` on spamprobe is **not** training mode — it's `setShouldCreateDbDir(true)`, verified in `spamprobe.cc:625` (just `mkdir -p`).

**Root cause: `spamprobe receive` auto-trains, `spamlite receive` does not.** Verified from `spamprobe-1.4d/src/spamprobe/Command_receive.cc`:

> "receive — Scores message, prints score, and updates database accordingly. [...] Once the message has been scored the message is classified as either spam or non-spam and its word counts are written to the appropriate database."

And `Command_receive::processMessage` (lines 104-121) unconditionally calls `filter.classifyMessage(message, is_spam)` after scoring, which writes the token counts to disk. This is **classical TOE** — Train On Everything, using the classifier's own verdict as the training label.

Spamprobe exposes three sibling commands sharing the same scoring path:

| Command | Behaviour | Name |
|---|---|---|
| `receive` | Always trains based on self-score | TOE |
| `score` | Never trains | Pure classify |
| `train` | Trains only if "difficult to classify" | TONE |

**`spamlite receive` is currently implemented as spamprobe's `score`.** Pure classification, no DB update. That is the single biggest functional difference between the two classifiers on this cluster, and it explains every downstream observation:

- Why `sp_words` grew 77× while `db.sqlite` stayed flat at 9 MB
- Why admin's `.spamlite-stats.jsonl` shows corpus counts that only move on `corr.fn` / `corr.fp` events (corpus only grows on user corrections, never on inbound)
- Why 215 of 216 users are pinned near the import-time baseline

**Cluster-wide evidence from the 2026-04-14 digest:**

- **The 4929 plateau.** Multiple unrelated users across different domains show `spam=4929` (cam@ck20, leathergoods, walkenny) or within a few of it (shaws 4931, cooranhall 4937, wilira 4937). Identical spam counts across unrelated users is a fingerprint of a single bulk import event — not organic growth.
- **Asymmetric drift.** Cluster averages are ~3821 good / ~4786 spam per user. Good varies widely (2174, 3961, 4753, 5058, 29436) while spam clusters tightly at 4900–5000. Why asymmetric? Because the only training signal is user IMAP corrections, and users rescue false positives from Junk (fires `retrain-as-ham` → good grows) but rarely bother reporting missed spam (retrain-as-spam almost never fires → spam frozen). The mechanism is the sieve wiring combined with human behaviour; the effect is visible in the digest.
- **kingswaycomputers has 29,436 good / 4,965 spam.** Someone ran a bulk ham-training pass on this user (similar to admin@renta.net's `.ham-trained` pass on 2026-03-19, `trained=3000 sent=1445 inbox=1555`). Even with 6× the ham volume, the spam count is still on the 4900-5000 plateau. Decisive evidence that spam training is not happening anywhere except on user corrections.
- **thenutfarm is the opposite outlier** (2243/11222, fn=2 fp=15). Somebody trained it aggressively on spam at some point. Accounts for 15/30 cluster-wide fp alone. **Root cause identified via log harvest on 2026-04-14**: a bulk-training script on 2026-04-06 fired 5770 events in a single day, almost all against thenutfarm's `.Junk/cur/` (6294 total spam TRAIN events across 31 days, vs 524 if we remove the one-day bulk). The skew is an artefact of that intervention, not organic user behaviour. Phase 3.4 (bulk Maildir ham training) applies directly and urgently — raising the threshold in Phase 1.3 compensates for the skew but does not fix it.
- **cam@ck20 is the canonical diagnostic target.** Balanced corpus (5063/4929), 5/30 cluster fp. Not a corpus problem — needs per-token inspection via dump/explain.

**User-behaviour taxonomy (from the 31-day retrospective log harvest, 14,385 TRAIN events across 94 of 216 users):**

| Group | Count | Pattern | Consequence |
|---|---|---|---|
| Heavy ham-rescuers (kenelle, kate, brian, sandy, sky, lgq, jean, geckoarc, gympiegraphics, medicworx) | ~10 users | 50–1400 good events, 0–2 spam | Decision boundary drifts ham → these are the high-**fn** users in the digest |
| Heavy spam-flaggers (thenutfarm, jaz@ck20, coolasola) | ~3 users | 100–6300 spam events, 0–6 good | Decision boundary drifts spam → these are the high-**fp** users in the digest |
| Silent majority | 122 of 216 (57%) | Zero or near-zero events either way | Corpus frozen at migration baseline |

Causal chain is now explicit: user correction behaviour → per-user corpus skew → classifier drift → digest fn/fp. The Phase 1 operational fixes (per-user threshold config, skew-detection gate) compensate for this at the *output* stage, but Phase 3.4 bulk ham/spam training is the structural fix that targets the *input* stage. Both are needed.

**Not investigated (deferred, not blocking):**

- What snapshot the original Spamprobe→spamlite migration imported from. 5000×50 tokens ≈ 250k matches admin's current 255k token count, but Spamprobe's live 67 MB `sp_words` would have produced far more tokens than that. The import likely ran from an earlier `sp_words` snapshot, or filtered aggressively. Worth nailing down if/when a seed refresh happens.
- `train-as-ham.sieve` is mentioned in `CLAUDE.md` but does not exist in `/etc/dovecot/sieve/` on mrn. CLAUDE.md is stale on that point.

### Phase 0.5 — Reopen the training pipeline (confidence-gated, not pure TOE)

Nothing downstream will measurably move the digest until corpora can grow. Phase 0.5 restores organic corpus growth via **confidence-gated training** — a third mode between spamprobe's pure `receive` (TOE) and `train` (TONE). Pure TOE is unsafe here because the current classifier has a real fp/fn rate and TOE on a mis-scored message is a self-reinforcing feedback loop (cam@ck20's daily fp would get trained as spam, producing more fp tomorrow). TONE is a near no-op on this corpus because scores are already extreme — almost nothing lands in the uncertain band, so TONE wouldn't generate enough training signal to unfreeze anything. Confidence-gated training splits the difference: train on confident verdicts (most likely correct), skip uncertain ones (most likely wrong).

**Ordering note.** Phase 0.5 is NOT a strict prerequisite to all of Phase 1. The dependency graph is:

- **0.5 items 1–3 (implement commands)** → can happen immediately, local-test only, not deployed
- **1.4 (explain command)** → needed before any deployment so we can characterise what TOE would be training on
- **1.5 (shadow mode in wrapper)** → needed before flipping the sieve, so we can measure candidate behaviour without production risk
- **1.1–1.3 (operational: per-user threshold config, skewed-corpus detection + mature-DB gate fix, thenutfarm threshold=0.75)** → independent, land in parallel
- **0.5 item 4 (flip sieve from `score` to `receive`)** → ONLY after 1.4 and 1.5 exist and 1.3 has been applied

Phase 0.5 items:

1. **Rename current `spamlite receive` to `spamlite score`.** The current implementation is pure classification — matches spamprobe's `score` command semantically. Preserve under the correct name for backward compat.

2. **Implement new `spamlite receive` as confidence-gated training.** Score the message, print the verdict (unchanged sieve contract), then call `db.train(&tokens, verdict == Spam)` ONLY if the score is outside the configurable dead band `(gate, 1.0 - gate)`. The gate is exposed as `-g` / `SPAMLITE_TOE_GATE` from day one, default `0.2`. Semantic: gate = trusted-region half-width. `gate=0.2` trains when `score ≤ 0.2 || score ≥ 0.8`; `gate=0.0` disables training entirely (read-only); `gate=0.5` is pure TOE (train everything). The SPAM/GOOD score prints to stdout *before* training runs so the sieve contract holds even if the training write fails. Training failures are non-fatal stderr — delivery must not break because counts couldn't be written. **Status: implemented and locally verified in v0.3.0** (see `src/main.rs` `cmd_receive`, static `TOE_GATE`, const `TOE_GATE_DEFAULT`). Five-case test matrix confirmed against `admin_maildir/`:
    - Default gate (0.2) + 20 confident messages → +10/+10 (training fires)
    - Default gate + empty DB (score exactly 0.5) → 0/0 (gate blocks)
    - `-g 0` + empty DB → 0/0 (training disabled, gate=0 trusts nothing)
    - `-g 0.49` + 20 confident → +10/+10 (nearly-pure TOE, tiny block zone)
    - `SPAMLITE_TOE_GATE=0.49` env override + 5 spam → +5 spam (env var works)

    **Gate default is provisional.** `0.2` is a reasonable starting point but the right width is empirical — it depends on how bimodal the score distribution actually is on this cluster's mail mix. Baseline observation from `admin_maildir/`: 20 real messages scored `≤0.000006` or `≥0.952`, all far outside `[0.2, 0.8]`. If this holds across the production cluster (to be confirmed via explain command in Phase 1.4), a wider gate like `0.35` could catch more genuine edge cases without reducing the training rate meaningfully. Revisit after explain exists and we have real distribution data.

3. **Future: `spamlite train` as TONE.** Add when/if scores start clustering near the decision boundary after confidence-gated training has had several weeks to operate. On the current extreme-score corpus it would be dead code, so not shipping it in v0.3.0.

4. **Flip the sieve.** After 1.4 + 1.5 land and the wrapper's per-user threshold + corpus-ratio exclusions are in place (see Phase 1.1), update the `spamfilter` wrapper to invoke `spamlite receive` instead of today's classify-only behaviour. Staged rollout: start with admin@renta.net only (healthy 5084/4957, recently ham-top-upped), monitor via shadow mode for a week, then expand.

5. **thenutfarm and any other skewed-corpus user must be excluded from confidence-gated training.** A 2243/11222 corpus means every borderline message scores spam, every borderline message gets trained as spam under TOE, and the skew worsens. Even the confidence gate can't save users whose corpora are already this far off because *all* of their scores will be confident-spam. The exclusion check lives in the `spamfilter` wrapper (see Phase 1.1), which computes `max(good,spam) / min(good,spam)` from the per-user DB and routes users with ratio `> 2.5` to `score` instead of `receive`. **Use the same `2.5` threshold here that Phase 1.2's mature-DB gate uses**, so there is exactly one "is this corpus skewed" rule across the whole system. Defense in depth: once such a user's corpus has been rebalanced (manual ham-training pass, per Phase 3 item 4), the wrapper automatically lets them back into `receive`.

6. **Confidence-gated training interacts with the per-user threshold override.** Raising thenutfarm's threshold to 0.75 (Phase 1.3) means fewer messages cross into Spam territory, which under confidence-gated training means fewer messages trained as spam, which slowly pulls the corpus ratio back toward sanity. That is the right long-term self-correction — but only with the gate, *and* only once the wrapper stops sending thenutfarm through `receive` at all. These two levers have to be reasoned about together for any skewed-corpus user.

### Phase 1 — Operational infrastructure (no classifier changes)

Every item in this phase is independent of the classifier and should land before any algorithm work.

1. **Per-user threshold config.** Add lookup for `/srv/{domain}/msg/{user}/.spamlite/config` so sieve invocations can pass a per-user `-t` override. spamlite already supports `-t` on the CLI. **Implementation location: the `spamfilter` wrapper at `/usr/local/bin/spamfilter` on mrn**, not spamlite itself — the wrapper already reads the per-user directory path and currently hardcodes `-t 0.6`, making it the natural injection point for a per-user override. Keeps spamlite pure and avoids another file-read on the classification hot path.

2. **Skewed-corpus detection in the digest + fix mature-DB gate bug.** Flag users whose good/spam ratio is outside `[0.4, 2.5]` (equivalent: `max/min > 2.5`) with a recommendation (train more of the minority class, or raise threshold). **Also fix the mature-DB gate**: current digest uses `good>=5000 AND spam>=5000`, which excludes kenelle@auzy.net.au (4753/4929, fn=9 — the worst fn user in the cluster) from the threshold-candidate list. Replace with `min(good, spam) >= 3000 AND max(good, spam) / min(good, spam) <= 2.5`. This captures "enough of each class" AND "not too skewed" in one rule, includes kenelle (min 4753, ratio 1.04), and excludes thenutfarm (ratio 5.0) and info@markuschep (min 2174 < 3000). **Use the same `2.5` ratio cap in the Phase 0.5 item 5 wrapper exclusion** so there is exactly one skew-definition across the system.

3. **Apply threshold=0.75 to thenutfarm immediately AND schedule a bulk ham pass.** Threshold override is zero-risk, lands in tomorrow's digest, plausibly halves cluster-wide fp count. **But it only treats the symptom.** The 2026-04-06 log harvest revealed the root cause: a bulk-training script fired 5770 spam TRAIN events that day, and thenutfarm has 0 ham corrections *ever*. The corpus is 5× skewed because somebody ran a one-sided training pass, not because their mail stream is 5× spam. The structural fix is a bulk ham training pass on thenutfarm's `.Archive/cur/` + `.Sent/cur/` to rebalance the corpus (Phase 3.4 mechanism, escalated to Phase 1 priority). Sequence: threshold override today, bulk ham pass next week once Phase 0.5 + shadow mode are in place so the effect is measurable.

4. **Dump/explain command.** `spamlite explain <message>` shows top-N interesting tokens with their f(w) scores and per-class counts. Equivalent to Spamprobe's `-T` flag (see `Command_receive.cc:60-62`) and its separate `spamprobe dump` command at `spamprobe-1.4d/src/spamprobe/Command_dump.cc`. Build this before any classifier changes — every subsequent experiment will need it for debugging. **Canonical test case: cam@ck20** (5063/4929, fn=0 fp=5) — a balanced-corpus user with 5 fp/day. Not a corpus problem. When dump/explain works, point it at cam's 5 fp messages and the output should reveal either a specific token family that's misbehaving or a structural algorithm weakness. Everything in Phase 2 should be validated against this target before merging.

5. **Shadow mode.** Runs the candidate classifier and logs decisions without acting on them. Enables evaluation of candidate builds against live mail in real time without risking user-visible regressions. This is the primary measurement apparatus going forward. **Implementation location: the `spamfilter` wrapper, not spamlite itself.** The wrapper already dispatches per-user between spamlite and spamprobe — adding a third branch that runs both and logs divergence to a per-user JSONL is half a day's work and touches zero classifier code. Candidate spamlite builds drop in as alternate binaries; no sieve changes required.

6. **Release discipline.** Git-tagged releases for each experiment. **Per-user `.spamlite-stats.jsonl` must include the spamlite version** (`"v":"0.3.0"`) on every line, not just the daily digest. Correlating a given user's fn/fp history to a specific deployed version is essential for blaming regressions — otherwise we only know cluster-wide deploys, not which version produced any given decision. One field, trivial cost, large debugging payoff. Rollback-in-under-a-minute capability: stage candidate binaries at `/usr/local/bin/spamlite-<version>` and flip a symlink.

7. **Feedback-event benchmark corpus — retrospectively reconstructable.** Verified on mrn 2026-04-14: `/var/log/mail.log` has 557 TRAIN events since 2026-04-12, plus 5 rotated logs (`mail.log.1` through `mail.log.4.gz`) going back to 2026-03-22. At ~280 TRAIN events/day cluster-wide that is roughly **6,000+ historical events available without waiting a month**. Sample line: `sieve: DEBUG: TRAIN: sandy@gardinermail.com.au -> good`. Historical messages are also preserved — users' `.Archive/cur/` folders have up to 5,945 messages per user (shcv.com.au/admin), Trash folders have hundreds more. Reconstruction loop:

    a. Parse `mail.log*` for `sieve: DEBUG: TRAIN:` lines → `(user, timestamp, direction)` tuples.
    b. Correlate timestamps against nearby imapsieve log lines to extract the IMAP UID and source/destination folder.
    c. Look up the actual message file in the user's Maildir (`.Junk/cur/`, `.Archive/cur/`, `.Trash/cur/`, etc).
    d. Store `(message_bytes, verdict)` pairs as the benchmark corpus. Freeze monthly going forward.

    Reconstruction will not be perfect — some messages will have been deleted from Trash, some UIDs will not correlate cleanly — but even a 50% recovery rate gives ~3,000 labelled events across ~216 users, which is a statistically useful adversarial benchmark. **Going forward**: also start logging new events to a quarantine path with full message bodies, so future reconstructions are not log-parse-dependent. Do the retrospective reconstruction first (it's the immediate unblock), do the forward-logging second.

### Phase 2 — Small algorithmic wins

Each item a separate commit. Methodology note: Phase 2 items 1–3 below were
landed on 2026-04-15 using **same-db evaluation against `admin_maildir/`**
via the new `spamlite-eval` harness (commit `7a61713`), not the falsifiable
cam@ck20 prediction protocol originally specified in this section. The
reason is that cam's Maildir has not been fetched from mrn yet and the
shadow-mode apparatus does not exist. Same-db eval is optimistic — it
measures parameter combining on a trained corpus, not generalisation — so
**v0.4.0 must still pass shadow-mode validation (Phase 1.5) before
deployment**. The admin_maildir gains are the *potential* improvement;
shadow mode is the gatekeeper.

Baseline on `admin_maildir/` at `t=0.6`: `fp=70 fn=65 err=1.26%` over
4079 ham + 6604 spam = 10683 messages.

1. **`max_interesting: 150 → 50`. SHIPPED in v0.4.0 (commit `327ec4a`).**
   Not `27` — the audit's original value was copied from Spamprobe's
   defaults for a thinner per-user corpus. On admin's 5074/4947 db, `50`
   produced strictly better numbers than `27` (105 vs 119 errors),
   likely because the richer corpus supports more tokens in the Fisher
   combine before noise dominates. Δ: `fp 70→55, fn 65→50, err 1.26%→0.98%`
   (−30 errors, −22%). Pareto improvement at both `t=0.5` and `t=0.6`.

2. **`unknown_prob: 0.5 → 0.45`. SHIPPED in v0.4.0 (commit `201e131`).**
   Slightly ham-biased default for unknown tokens. Spamprobe used `0.3`
   (very aggressive); `0.45` is a lighter touch justified by our cluster's
   fp-dominant error profile. Δ on top of Phase 2.1: `fp 55→48, fn 50→57,
   err unchanged at 0.98%`. Same total error count as Phase 2.1 alone but
   the fp/fn mix shifts toward fewer fp, which is what production UX
   weights more heavily.

3. **`strength: 1.0 → 0.5`. SHIPPED in v0.4.0 (commit `aef6f8c`).** Robinson
   strength parameter — controls how hard the per-token f(w) is pulled
   toward `unknown_prob`. This was **not in the original audit** but
   dominated every other knob in the eval sweep. On admin's mature db the
   gain was monotonic all the way down to `0.05` (25 errors total); landed
   at `0.5` as a safe midpoint because thin corpora are vulnerable to
   low-strength noise on single-observation tokens. Δ on top of Phase 2.1/2.2:
   `fp 48→25, fn 57→37, err 0.98%→0.58%` (−43 errors). **Biggest single
   Phase 2 win by a wide margin.** Cumulative Phase 2.1+2.2+2.3: 135→62
   errors (−54%), fp −64%, fn −43%.

4. **`good_bias` — config-exposed, default 1.0 (off). SHIPPED in
   the Phase 2 refactor (commit `70a70a7`).** Available as `Params.good_bias`;
   eval showed that non-1.0 values are a pure fp/fn tradeoff dial with no
   aggregate accuracy gain, so keeping the default off and leaving per-user
   tuning to the shadow-mode phase.

5. **`min_word_count` gate — config-exposed, default 0 (off). SHIPPED in
   commit `70a70a7`.** Eval showed this actively hurts accuracy on the
   admin db (values 3 or 5 roughly doubled fp) because it prunes the
   informative long tail of rarely-observed but strongly-discriminating
   tokens. Likely useful for cold/thin corpora — kept as config for
   per-user tuning, not a default.

6. **Token length bounds loosened to `1..=90`. DEFERRED to after shadow
   mode.** Exposed as `TokenizerConfig.min_len` / `max_len` in commit
   `70a70a7`, but not made the default because it mostly affects newly-
   tokenised messages against the existing db (which only knows old-bound
   tokens) — needs retrained corpora to evaluate fairly.

7. **Expanded header coverage — config-exposed, DEFERRED to after
   shadow mode.** Implemented as `TokenizerConfig.expanded_headers` in
   commit `70a70a7`: adds `h:to:*`, `h:cc:*`, and splits the received
   chain into `h:hrecv:*` (first hop) / `h:hrecvx:*` (subsequent). Same
   problem as item 6: the new token prefixes are unknown to every existing
   db, so the eval shows a small regression. Proper evaluation requires
   either retraining or a freshly-captured corpus.

### Phase 3 — Structural improvements

Only after Phase 2 has produced measurable improvement and the benchmark harness is characterising remaining error modes.

1. **TONE training (Train Only Near Errors).** Better than Spamprobe's TUNE loop — only trains when score is in the uncertainty band, producing sharper decision boundaries without the oscillation risk that Spamprobe's 25-iteration cap mitigates.

2. **OSB (Orthogonal Sparse Bigrams) body features.** From CRM114. Generates sparse bigrams across a 5-token window with distance weighting. Roughly 2× the discriminative power of adjacent bigrams. Replaces the original audit's "body bigrams" item. Storage implication: ~5× per-user row counts — schema review required. Long-token hashing (Phase 2 item 5) becomes mandatory here.

3. **Header field weighting.** Subject and From weight higher than Received chains. Spamprobe doesn't do this.

4. **Bulk Maildir-based ham training for cold corpora.** Reframed from the original "seed refresh" item after Phase 0 debunked both the seed and cap hypotheses. Mechanism is different: instead of distributing a shared corpus, train each user's cold spamlite DB on their own `Maildir/.Sent/cur/` and `.Archive/cur/` (strong ham ground truth) to bootstrap organic corpus growth. This is precisely what admin@renta.net already received on 2026-03-19 per the `.spamlite/.ham-trained` marker (`trained=3000 sent=1445 inbox=1555`). Candidates for this pass: users whose corpora don't recover organically under confidence-gated TOE after 2-4 weeks, identifiable via the digest's corpus-growth column (new in Phase 1). Skewed-corpus users (thenutfarm et al) need this as a remediation step before they can re-enter `receive` mode at all — see Phase 0.5 item 5.

### Phase 4 — Deferred / research-grade

Only reach for these if Phase 3 benchmarks show specific remaining error modes these techniques address.

- Character n-grams for short/obfuscated tokens (handles "v1agra", "v-i-a-g-r-a" without regex zoos).
- Concept drift handling via exponential decay on token counts. **Deferred unconditionally until users have organic traffic that has drifted from the seed/cap baseline.** Decay applied now would eat whatever baseline users have and leave them with nothing.
- Full TUNE/TOE retry loop (Spamprobe `SpamFilter.cc:460-494`). Value-add over TONE is marginal.
- Rspamd-style per-token learning-rate decay.

## Explicitly rejected from the original audit

- **Fisher → Robinson geometric mean replacement.** Fisher is better; keeping it. Spamprobe's choice was historical, not optimal.
- **Hardcoded `good_bias=2`.** Too heavy a thumb on the scale; exposing as config with default 1.0 instead.
- **Hardcoded `unknown_prob=0.3`.** Same reasoning; using 0.45 as default and exposing as config.

## Operating principles

- **No TOE training on messages scored in the uncertainty band.** The confidence gate is the invariant that protects against self-reinforcing feedback loops (cam@ck20-style fp getting trained as spam and creating more fp). Every future change to the training pipeline must preserve this invariant, or explicitly justify relaxing it with evidence.
- **Operational and observability infrastructure come before classifier code changes.** Phase 1 is non-negotiable prerequisite for anything in Phase 2+.
- **Every change is a separate commit**, evaluated in isolation via shadow mode and/or the feedback-event harness. No bundled "items 1-4" commits.
- **Every Phase 2 algorithmic change carries a falsifiable prediction against cam@ck20's explain baseline.** If the predicted change doesn't happen, the item doesn't merge.
- **Week-minimum observation windows** for live digest-based evaluation. 24 hours is within noise.
- **Success is measured by next month's digest, not by items landed.** If a change doesn't move the digest numbers in shadow mode, it doesn't merge.
- **Resolved: historical sieve-event data is reconstructable.** Phase 1.7 can use log-based retrospective reconstruction (~6000 events available from mail.log rotation) instead of waiting a month. Forward-logging is a parallel track, not a blocker.

## Testing methodology

The core development loop is local, reproducible, and does not touch production:

1. **Identify a technique** in `~/.gh/spamprobe-1.4d/src/` worth extracting. Aim for the highest impact-per-LOC. Reference: `SpamFilter.cc` (scoring core), `Command_receive.cc` (TOE/TONE semantics), `SimpleTokenSelector.cc` (top-N selection), `FilterConfig.cc` (defaults), `Command_dump.cc` (explain output format).
2. **Implement in spamlite** as a separate commit. No bundled changes.
3. **Local sanity**: `cargo test && cargo build --release`. If either fails, roll back.
4. **Corpus test against `admin_maildir/`**: run the candidate binary against a sample of messages from `Maildir/cur/` (ham), `.Junk/cur/` (spam), and the historical backups. Measure: (a) does it still produce a valid SPAM/GOOD score, (b) does the score for known-ham and known-spam messages move in the right direction versus the baseline binary, (c) does the classifier crash or error on any message.
5. **Only if local tests pass**: deploy the candidate as an alternate binary alongside the production spamlite (not replacing it), and let the Phase 1 shadow-mode wrapper log divergence against live mail for at least a week before promoting to primary.

The `admin_maildir/` corpus is the single source of truth for local testing. `.spamlite/db.sqlite` (9 MB, 255k tokens, 5074/4947 as of 2026-04-14) is the ground-truth starting state. `.spamprobe/sp_words` (67 MB) is the reference comparison — any technique that can't beat or match spamprobe on the same messages is not worth merging.

## Local resources

- **`~/.gh/spamprobe-1.4d/src/`** — Spamprobe 1.4d source, mined for techniques to extract. See Testing methodology for key files.
- **`admin_maildir/`** (gitignored) — offline copy of admin@renta.net from mrn. Contents:
  - `Maildir/` with `.Junk`, `.Sent`, `.Dmarc`, `.Drafts`, `.Archive`, `.Trash` — live tree, ground-truth ham + spam
  - `Maildir.backup.20250722_070105/` — Jul 2025 Maildir snapshot
  - `mdbox.backup.20251024_193622/` — Oct 2025 mdbox snapshot
  - `.spamlite/db.sqlite` (9 MB) + `.spamlite/.ham-trained` (records the 2026-03-19 3000-message bulk ham pass) + `.spamlite-stats.jsonl` (per-day counts)
  - `.spamprobe/sp_words` (67 MB, 2026-03-11) + `.spamprobe.backup/sp_words` (880 KB, Jul 2025) — 77× growth confirms no cap
  - **Note**: the sieve scripts in `admin_maildir/sieve/` are user-level filing rules, **not** the global spam-filtering sieve. The real sieve wiring lives on mrn (see below).
- **On mrn (ssh mrn):**
  - `/etc/dovecot/sieve/global.sieve` — inbound classification path; calls `spamfilter ... receive`
  - `/etc/dovecot/sieve/global.sieve.spamprobe` — previous all-spamprobe version (reference)
  - `/etc/dovecot/sieve/retrain-as-{ham,spam}.sieve` — IMAP-triggered training via `spamfilter-retrain`
  - `/usr/local/bin/spamfilter` — dispatcher wrapper (spamlite vs spamprobe based on `.spamlite/` existence), hardcodes `-t 0.6`. Target for Phase 1 items 1 and 5.
  - `/usr/local/bin/spamfilter-retrain` — retrain dispatcher wrapper.
  - Per-user dbs: `/srv/{domain}/msg/{user}/.spamlite/db.sqlite` or `/srv/{domain}/msg/{user}/.spamprobe/`.
