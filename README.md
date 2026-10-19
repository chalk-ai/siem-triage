# SIEM triage with a decision model on Chalk

A live queue of security alerts, each triaged by a decision model on one GPU. Every alert gets a
disposition (close, monitor, investigate, contain), a calibrated probability that it is malicious, a
severity, and the facts that moved the decision. Analyst feedback becomes a feature on the next
similar alert, so the queue adapts in seconds without retraining.

The company (Halcyon Freight), its people, hosts and alerts are fictional. Every risky alert has a
benign twin that differs only in context, so the model has to read the context to tell them apart.

## How it works

```
detection rule ─▶ raw alert ─▶ enrich ─────────────────────▶ record ─▶ decision model (1 batched pass)
                                 │ identity directory                     ├ disposition
                                 │ asset criticality, allowlist           ├ P(malicious), calibrated
                                 │ change windows                         ├ severity
                                 │ alerts on this user/host, last hour    └ one counterfactual per fact
                                 └ analyst feedback (expires in 15 min)
```

- **Model:** [`michaelfeil/laya-typed-decisions`](https://huggingface.co/michaelfeil/laya-typed-decisions),
  a 421M-parameter ModernBERT-large decision model fine-tuned on the
  [typed-decisions](https://huggingface.co/datasets/LocalLLaMA/typed-decisions) benchmark, whose
  workflows include security incidents. Records use that benchmark's security-incident schema.
- **Calibration:** the raw P(true) ranks alerts well but compresses toward 0.5. A logistic
  recalibration (`logit × 1.95 − 0.02`), fitted on the benchmark's 300-case security train split,
  lowers log loss from 0.590 to 0.563, and lowers test-split Brier from 0.0160 to 0.0133.
- **Contributions:** each fact (allowlisted source, change window, MFA, asset criticality,
  history, and each context note) is flipped to a counterfactual value, and the change in
  P(malicious) is its contribution. The flipped fact's evidence sentence is re-rendered too, so the
  record stays consistent. All variants run in one `predict_batch` call.
- **Feedback:**
  - *Allowlist this source* adds the source to a dynamic allowlist.
  - *Confirm malicious* adds an analyst-confirmed note for that rule and principal.
  
  Both apply to the next signals too, and expire after 15 minutes. Allowlisting lowers the score of
  anything from that source, malicious or not: that is the tuning trade-off analysts own.

## Files

| File | Role |
| --- | --- |
| `app/signals.py` | Fictional directory, assets, allowlist, and nine risky/benign alert pairs. |
| `app/triage.py` | Enrichment, the record, the decision questions, calibration and counterfactuals. |
| `app/server.py` | FastAPI: the shared triage loop, `GET /api/feed`, `POST /api/feedback`. |
| `deploy.py` | Builds the image (weights baked in) and deploys a `chalkcompute.ScalingGroup` on one L4. |

## Run it

You need [`uv`](https://docs.astral.sh/uv/) and a Chalk environment that can schedule GPU workloads.
Credentials come from your existing `chalk login`.

```bash
./deploy.py
curl "$WEB_URL/api/feed?after=0"
```

The triage loop runs only while someone has polled `/api/feed` in the last two minutes. Feeds are
limited to 90 polls a minute and feedback to 10 actions a minute per client. Browsers may call the
API only from `*.chalk.ai`, `*.chalk.dev` and localhost; set `TRIAGE_ALLOWED_ORIGIN_REGEX` to change
that.

To run it locally on CPU (slower: a few seconds per alert):

```bash
uv run --with laya==0.4.6 --with transformers==5.19.0 --with torch==2.7.1 \
  --with fastapi==0.116.1 --with "uvicorn[standard]==0.35.0" \
  env TRIAGE_FEED_INTERVAL_S=15 python app/server.py
```

## License

The code is Apache-2.0. The model weights are Apache-2.0, per their model card.

## Local authentication

The SDK reads credentials, API host, and the selected environment from your existing
`chalk login` in `~/.chalk.yml`, including project-scoped and default logins.
For unattended runs, `CHALK_CLIENT_ID` and `CHALK_CLIENT_SECRET` remain supported.
The examples use the current environment selected by your Chalk login.
