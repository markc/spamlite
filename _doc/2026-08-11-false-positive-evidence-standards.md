# Evidence standards for false-positive work

What counts as proof that spamlite got a message wrong, and three ways the obvious
metrics lie. Learned the hard way on a ~200-user production fleet, 2026-08-11.

The tempting metric is the IMAP rescue: sieve logs
`TRAIN: <user> <msgid> -> good` whenever a user drags a message out of Junk. It is the
only *explicit user action* in the logs, it needs no heuristics, and it is easy to count.
It is also not ground truth, and building a ranking on it put the wrong user at the top.

## Trap 1 — a rescue means "the user touched it", not "the filter was wrong"

Ranking users by deduped rescues produced a clear #1: 60 deliveries in 28 days, 49 of them
junked (81.7%), 24 rescues, an apparent 49% false-positive rate.

Resolving those rescues back to messages on disk showed every survivor was plain dropship
spam, and every one of them was sitting in **Trash**. The user was moving spam Junk →
INBOX — which fires `TRAIN → good` and trains it into her ham corpus — and then deleting
it. She was corrupting her own corpus at roughly 24 messages a month. Her 81.7% junk rate
was *correct*: her inbound really was almost all spam.

Two rules follow:

- **Validate every rescue against the message before it becomes evidence**, and certainly
  before it becomes training data.
- **The user contradicting their own rescue is the strongest signal available** — stronger
  than any content heuristic. If a rescued message is later found in Junk or Trash, the
  rescue was not a correction.

A cheap secondary flag is the sender's TLD: bulk dropship spam clusters on `.lol`,
`.store`, `.cloud`, `.space`, `.shop`, `.click`, `.top`, `.xyz`. Useful for *flagging a
rescue for review*; never for making a delivery decision.

## Trap 2 — re-scoring a rescued message understates the defect

A rescue triggers a retrain. So by the time you re-score that message, the database has
already been trained on it, and the score you get is not the score that junked it.

Measured across five users' confirmed false positives: nearly all of them now score
**under 0.5**, despite every one having been junked at delivery. Any harness reporting "of
the false positives still above threshold, N were fixed" is therefore answering a largely
moot question.

The mirror-image trap is just as real: **delivery-time scores are stale** for judging a
candidate fix, because the corpus has moved on since. One earlier misdiagnosis came from
trusting logged delivery scores without re-scoring.

**Both numbers are required — the delivery-time score says what the defect was, the
current score says what is left of it.** Neither alone is honest.

## Trap 3 — the rescue rate is a floor, and the worst users are invisible to it

A rescue only exists if the user noticed. Mail junked and never looked at leaves no trace,
so users who don't curate their Junk folder score *clean* on this metric while being the
worst affected.

The genuinely worst mailbox on the fleet ranked mid-table at a 23.7% "floor". Its Junk
folder turned out to be mostly the user's own committee correspondence — a finance report,
draft advertising, a reply in an ongoing thread, senders on consumer ISPs and free
webmail. A community organisation quietly losing its own mail.

The same check cuts the other way and saves work: another high-ranked user's kept-Junk was
defensible commercial bulk — supplier newsletters, retail promotions, real-estate
listings. He needed far less attention than his rank implied.

**Always read the junked-and-kept half.** Do it by eye, and never auto-train it: mail the
user left in Junk is their own verdict, and the default is to respect it.

## Trap 4 — a corpus-level predictor does not predict a per-user benefit

While rolling out a tokenizer fix that stopped raw HTML markup being treated as body
words, a cheap per-user predictor looked excellent: the good:spam ratio of the `b:style`
token, one `export | grep`, ranging from 0.23 (large improvement) to 0.86 (slight cost).

Measured against a validated queue, it failed twice — both times optimistically. The two
users with the *most* favourable ratios on the entire fleet measured **every delta exactly
0.000**. Their false positives were plain-text personal correspondence, which a
markup-tokenizing bug cannot affect by construction. A third favourable user came out
genuinely mixed: a large improvement on the messages that mattered to him, but two
delivered ham messages pushed over the line.

The ratio measures **where the corpus has put markup**. It says nothing about **whether
this user's false positives are the kind of mail the fix touches**. It is necessary but
not sufficient, and must be paired with an inspection of what the user's FPs actually are.

Costs, unlike benefits, generalised cleanly: top-band spam margin (`≥0.999`) fell in every
database measured, with no new false negatives at the default threshold. So the cost is
pure headroom — which is exactly what users on raised thresholds are spending.

## Trap 5 — a broken join reads exactly like "not enough data yet"

An A/B harness that adjudicates a candidate against user corrections has to join two
independent sources: the log line recording the user's action, and the record written at
delivery time. Those two sources format the message-ID differently — one keeps the angle
brackets from the header, the other has already stripped them — and joining them raw
produces **no matches, no error, and no warning**.

Every adjudication counter reads zero. That is indistinguishable from an honest "the canary
has not accumulated evidence yet", and it is worse than a crash: a rescue-lag guard, or any
other legitimate reason for low early counts, supplies the zero with a convincing excuse.
Left alone it runs the whole trial period and reports "no evidence either way".

**Print the join hit count.** One line — how many records matched any ground-truth key —
turns a silent permanent zero into a visible defect. Any counter that can be zero for two
different reasons needs a second number that tells them apart.

## Trap 6 — two ham-leaning knobs don't compose, they spend the same headroom

Two users diagnosed as needing a raised threshold — every message the filter junked in the
0.5–0.9 band over 28 days was legitimate, and their genuine spam sat at ≥0.999 — were moved
to `threshold = 0.9`. That fixed the great majority: delivered-inbox false positives fell
26 → 3 and 7 → 2, with no genuine spam released.

A handful of stragglers remained above 0.9, so the obvious next move was the *other*
ham-leaning knob: weighting ham evidence in the per-token probability (spamprobe's
`good_bias = 2.0`). It fixed the stragglers spectacularly — 0.94 → 0.0016, 0.9998 → 0.54 —
and destroyed the spam side: held-out spam false negatives at the same threshold went
**9.2% → 44.0%** for one user and **11.0% → 44.8%** for the other, and 9 of 14 messages in
one user's own Junk folder were released.

The lesson isn't "that parameter is bad". It's that a threshold raise and a ham bias are
**two ways of spending the same margin**. Once the threshold sits near the top of the score
range, the headroom is already committed; a second ham-leaning knob on top has nothing left
to spend and starts deleting the spam side instead. Pick one lever per user, measure it, and
treat a residual as a residual — some messages need a different kind of fix, not more of the
same one.

## Practical sequence

1. Rank candidates by deduped rescues, treating it as a **shortlist, not a finding**.
2. Resolve each rescue to a message on disk. Index the **whole** Maildir, not just INBOX
   and Junk — users file rescued mail into project folders.
3. Discard rescues that are self-contradicted or obvious spam. Keep the validated ham as
   the watch list.
4. Read the junked-and-kept half by eye. Expect to re-rank after this step.
5. Pair delivery-time scores with fresh re-scores.
6. Measure any candidate fix against the user's **unchanged** database, and report the
   false-negative side too — a change that fixes ham by leaking spam is not a fix.

## Note on scale

Resolving rescues means joining message-IDs to files. Grepping once per Maildir *file* to
build an index is honest but collapses on a large mailbox. Grepping once per *user* —
a single pass with every message-ID as a fixed-string pattern, then reading headers only
from the files that hit — is the same answer at a fraction of the cost.

One trap worth naming: `grep -F '-> good'` **matches nothing**, silently. The pattern
begins with `-`, so grep parses it as an option. Anchor extraction patterns on a harmless
first character.
