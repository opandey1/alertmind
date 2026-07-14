# AlertMind — Assisted Timing Pass Protocol

Goal: measure whether the assistant changes **time-to-triage** and **disposition
accuracy**, versus the unassisted baseline already in `timing-log.csv`.

---

## 0. The rule that decides whether this measurement is valid

**Model inference latency is NOT part of triage time.** The experiment asks whether
the assistant's *output* helps an analyst triage faster — not how fast llama3.1
runs on a local CPU. Your ~75 s/alert (batch) and 2–3 min/alert (live Streamlit)
are an artifact of local CPU inference; a production deployment would use a GPU or
hosted endpoint at 2–5 s. Counting that latency as "triage time" would measure the
wrong thing and bury the assistant's actual value.

So:

- **Pre-generate the assistant outputs in batch, before timing.** You already have
  them — the operational run's `assistant_outputs.json`. During the timed pass the
  analyst *reads* that pre-generated output; the clock never waits on the model.
- **Report inference latency separately** (from the audit log's `latency_ms`) as a
  deployment consideration, with the note that production inference is far faster.

Do **not** click "Triage with assistant" live during timing — that blocks on
inference. Read the alert's entry from `assistant_outputs.json` instead (pretty-
printed alongside the raw alert).

---

## 1. What you record

For every alert, in both conditions, the same two timestamps you used for the
baseline:

- **t3** = the moment you open the alert and (assisted only) its pre-generated output.
- **t4** = the moment you commit a disposition (true-positive / benign / needs-investigation).

`triage_min = t4 − t3`. Append rows to `timing-log.csv` with `condition = "assisted"`,
your `analyst_disposition`, and (filled afterwards) `disposition_correct`.

Primary metrics: median triage time per condition; disposition accuracy per
condition. (The assistant's own tag accuracy is already measured in the run scoring.)

---

## 2. Recommended pass — pragmatic, within-subject + washout

You already have the unassisted baseline for all 20 alerts. The simplest defensible
assisted pass:

1. **Washout ≥ 48–72 h** after the baseline (you have seen these alerts; the gap
   reduces recall).
2. **Randomise the order** — do not go A01→A20. Shuffle once and triage in that order.
3. For each alert: open the raw alert + its `assistant_outputs.json` entry, start the
   timer (t3), reach a disposition, stop (t4). Record the row, `condition="assisted"`.
4. Fill `disposition_correct` against ground truth afterwards (not during — don't
   look at answers while triaging).
5. Run `analysis.ipynb` → Part 2 activates automatically and plots unassisted vs
   assisted.

**Known confound (report it):** the assisted pass is a *second* exposure, so learning
makes it faster regardless of the assistant. This biases *toward* an apparent
assistant speed-up. Therefore: if you find **no** speed-up (the likely outcome), the
result is robust — the assistant didn't help even with a learning tailwind. If you
*do* find a speed-up, attribute it cautiously (partly familiarity). State this
direction explicitly — it turns a limitation into a conservative-inference argument.

---

## 3. Optional — counterbalanced crossover (maximum rigor)

If you want to *control* the order/learning confound instead of bounding it, run a
two-session crossover on a matched split and treat the current all-20 baseline as a
pilot (don't pool it into the crossover stats).

**Matched A/B split** (balanced 7 attack / 3 benign each):

- **Set A (10):** A01, A02, A03, A04, A05, A06, A07, A09, A10, A12
- **Set B (10):** A08, A11, A13, A14, A15, A16, A17, A18, A19, A20

Schedule:

| | Set A | Set B |
|---|---|---|
| Session 1 | **assisted** | unassisted |
| washout ≥48h | | |
| Session 2 | unassisted | **assisted** |

Now every alert has both an unassisted and an assisted time, and assisted-first vs
unassisted-first is balanced across A and B, so the learning effect cancels between
conditions. More work (≈40 timed triages), but it removes the confound rather than
reporting it.

---

## 4. Threats to validity to state in the report

- **Inference latency excluded from triage time** (measuring content value, not
  local-CPU speed; production inference is far faster). Latency reported separately.
- **Learning / order effect** — controlled by crossover, or bounded by washout +
  reported bias direction (§2).
- **Self-generation bias** — you built the attacks, so you know the answers; the
  unassisted accuracy ceiling is optimistic.
- **Small n (20), single environment, single model, one deterministic run
  (temp = 0)** — results are directional, not statistically powered.

---

## 5. Which pre-generated output to time against

Use the **operational** view (that is the realistic analyst experience — the analyst
sees the alert's own metadata). Pick the prompt you will report as "deployed":

- If you report **baseline** as deployed: time against the operational/baseline
  `assistant_outputs.json`.
- If you report **benign_aware** as deployed: time against operational/benign_aware,
  and note it trades a little technique confidence for better disposition calibration.

Either way, state which prompt the analyst was shown. You do **not** need any new
model inference for the timing pass — reuse the outputs you already generated.
