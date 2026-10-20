# Progent, taken apart

An interactive site for understanding
[**Progent: Securing AI Agents with Privilege Control**](https://arxiv.org/abs/2504.11703)
by Tianneng Shi, Jingxuan He, Zhun Wang, Hongwei Li, Linyu Wu, Wenbo Guo and Dawn Song
(arXiv:2504.11703, v3; [PDF](https://arxiv.org/pdf/2504.11703)), running against the authors' own code.

The paper's central guarantee, in its own words: "the agent's effective action space can only shrink
without approval". This site lets you watch that guarantee work, and fail.

Live at <https://progent.moosha.org> (password-protected).

- **Walkthrough:** the paper's running example (Figure 1), step by step. It shows the policy gating each
  call, each update classified live, and an action-space map of what the agent may do.
- **Policy playground:** write a policy in the paper's format and test tool calls against the
  reference enforcer and Algorithm 2 side by side.
- **Containment checker:** is an update a narrowing or an expansion? The reference checker and an
  independent paper-semantics checker run side by side. Every counterexample is replayed through the
  real enforcer, and the SMT query is shown.
- **Attack lab:** a real agent (Claude) in a sandboxed mock workspace with Progent in the loop. You
  choose the injection (including the paper's adaptive attacks), the approver mode, and the
  implementation. The policy model uses the reference prompts verbatim. With "Ask me", expansion
  approvals come to you in the browser.

## What the reference implementation gets wrong

Reference code: `sunblaze-ucb/progent` @ `5be7b63` (vendored unmodified in `vendor/secagent`, MIT).

1. **Anchors fail open.** `role_analyzer.regex_to_z3_expr` raises `NotImplementedError` on `^`, `$`
   and `\b`. `policy_analysis.solve_schema` catches every exception and returns "no model". As a
   result, `security_policy_subset_check` reports a *narrowing* for any update to a policy that uses
   an anchored pattern, including widening it to `.*`.
2. **The solver and the enforcer disagree on `pattern`.** Z3 is given `InRe(x, R)`, which is a full
   match. Enforcement is `jsonschema.validate`, which applies `pattern` with `re.search`.
   `enum ["alice@x.com"]` → `pattern "alice@x\.com"` therefore looks like an equality to Z3, but
   at runtime it admits `eve@evil.comalice@x.com`.
3. **Solver `unknown` and timeouts** fall through the same path and count as narrowings.
4. **Only the first allow rule per tool** is compared by the subset check and honoured by the
   enforcer (a failing priority-100 allow rule raises immediately). That differs from Equation 3 in
   the paper.
5. The subset check only runs when `SECAGENT_ONLY_ALLOW_NARROW=true`. In the default mode, which is
   the Auto-Approve configuration behind the paper's headline numbers, it isn't called.

`tests/test_checkers.py` reproduces 1–4 and checks every counterexample against the real enforcer.
`tests/test_lab.py` drives the full agent loop with a scripted model. Under manual approval, the
injected widening is applied without ever reaching the human when the reference checker is used, and
is put to the human and blocked with the paper-semantics checker.

The paper-semantics checker (`app/spec_checker.py`) models `jsonschema`'s actual behaviour:
`re.search`, Python's `$` matching before a trailing newline, `.` excluding newline, and first-match
rule order with forbid-before-allow. It fails closed on anything it can't model. It is honest about
one approximation: `\d`, `\w` and `\s` are modelled as ASCII.

## Deploy on a DigitalOcean droplet

A 1 GB droplet is enough; 2 GB is more comfortable. Ubuntu 24.04.

1. **DNS:** point an A record (for example `progent.yourdomain.org`) at the droplet's IP. Caddy fetches
   the TLS certificate itself.
2. **Docker:**
   ```sh
   curl -fsSL https://get.docker.com | sh
   ufw allow OpenSSH && ufw allow 80,443/tcp && ufw allow 443/udp && ufw --force enable
   ```
3. **Code:** copy this directory to the droplet (`scp -r` or `git clone`), then `cd` into it.
4. **Config:**
   ```sh
   cp .env.example .env
   ./make-password.sh        # prompts for a password, prints the BASIC_AUTH_HASH line
   nano .env                 # set SITE_DOMAIN, BASIC_AUTH_USER, paste the hash line
   chmod 600 .env
   # The Anthropic key: one line in .key, readable by the container user (uid 10001) only.
   nano .key && chown root:10001 .key && chmod 640 .key
   ```
   Keep the single quotes around the hash. Compose reads single-quoted values literally, and the
   hash contains `$`.
5. **Start:**
   ```sh
   docker compose up -d --build
   docker compose logs -f caddy   # watch the certificate get issued
   ```

To update, run `docker compose up -d --build` again. To stop, run `docker compose down`.

The app container isn't published on any port; only Caddy (80/443) is. It runs as a non-root user
on a read-only filesystem with all capabilities dropped.

### Keys and limits

| Variable | Needed for |
|---|---|
| `.key` file (or `ANTHROPIC_API_KEY`) | Attack lab. The other three sections work without any key. |
| `OPENAI_API_KEY` | Optional. Adds `gpt-4o-2024-08-06`, the paper's policy model, to the lab. |
| `TYPESAFE_API_KEY` | Optional. Enables the Jev update gate (a Noul over the same inputs as the paper's gate prompt). |
| `AGENT_MODEL`, `POLICY_MODEL` | Model IDs (default `claude-sonnet-5-5`). |
| `MAX_STEPS`, `MAX_CONCURRENT_RUNS`, `APPROVAL_TIMEOUT_S` | Bounds on agent steps, simultaneous runs and how long a run waits for you. |

A lab run makes roughly 10–30 model calls. Runs live in process memory, which is why the server uses
a single worker and runs disappear on restart.

## Citation

```bibtex
@article{shi2025progent,
  title   = {Progent: Securing AI Agents with Privilege Control},
  author  = {Shi, Tianneng and He, Jingxuan and Wang, Zhun and Li, Hongwei and
             Wu, Linyu and Guo, Wenbo and Song, Dawn},
  journal = {arXiv preprint arXiv:2504.11703},
  year    = {2025},
  url     = {https://arxiv.org/abs/2504.11703}
}
```

## License

MIT (see `LICENSE`). The vendored reference implementation keeps its own MIT license.

## Local development

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest -q
ANTHROPIC_API_KEY=... .venv/bin/uvicorn app.main:app --reload --port 8000
```

## Layout

```
app/main.py           FastAPI routes
app/reference.py      wrappers around the vendored reference code (no globals, no sys.exit/input)
app/spec_checker.py   paper-semantics containment checker and Algorithm 2 evaluator
app/lab.py            Algorithm 3 agent loop, approvers, event stream
app/gate.py           update gate: reference prompt, Jev, or none
app/scenarios.py      sandboxed mock workspaces and injection templates
static/               the site (no build step)
vendor/secagent/      reference implementation, unmodified (see VENDOR.md)
```
