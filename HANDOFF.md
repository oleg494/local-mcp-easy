Branch: fix/hardening.

**IMPORTANT (sandbox-specific):** git clone/push through the Conol egress proxy
does NOT work for this repo ("GitHub not connected / needs reauth", 403, even
after Secrets(refresh)) — the `fix/hardening` branch and its commits exist
ONLY in this snapshot's local git history, never pushed upstream. If the
sandbox resets, restore from the most recent WIP tarball delivered to the
user via Collect, re-`tar xzf` it, `git init && git checkout -b fix/hardening`,
commit as a fresh baseline (git history/authorship before the restore point
is lost — that's expected and fine, the code content is what matters).

Baseline: 201 passed, 6 pre-existing fails (python vs python3 PATH,
tests/test_command_jobs.py x5 + tests/test_core.py::ProgramNameTests x1) —
fix by using sys.executable / Path(sys.executable).stem. Not regressions.

## Done + committed
1. **6 critical fixes**: env leak to child processes, git `-c`/global-option
   RCE gadget, refspec branch-delete, force-push block, fetch/pull refspec
   validation, `.git`/repo-context write guard.
2. **A/D/E/F**: fs tools wrapped in `asyncio.to_thread`, `_consteq` constant-
   time token compare (core.py, used in 5 places), `urlsplit` port parse
   guarded against `ValueError`, OAuth consent requires `action == "approve"`.
3. **B — refresh-token family revocation on reuse** (RFC 9700 §4.14.2,
   auth/oauth.py): every refresh token carries a stable `family_id` across
   rotation; replaying an already-rotated token revokes the ENTIRE family
   (including the live descendant), not just the replayed token. Bounded/
   TTL'd `_rotated_refresh` marker map mirrors the existing `_used_codes`
   eviction pattern (`MAX_ROTATED_REFRESH` / `ROTATED_REFRESH_TTL`).
4. **C — client_secret hashed at rest** (auth/oauth.py + server.py):
   `OAuthStore.store_client` persists only SHA-256(secret); `oauth_state.json`
   never holds the plaintext. `register_client` never mutates the caller's
   `client_info`, so the SDK's one-time DCR HTTP response still discloses the
   raw secret as RFC 7591 requires. `get_client` always returns
   `client_secret=None` so the SDK's own (now-impossible) comparison is a
   permanent no-op. New `ClientSecretAuthMiddleware` in server.py is the real
   enforcer — mirrors the SDK's client_secret_basic/client_secret_post
   extraction, hashes the presented secret, compares via the existing
   constant-time `_consteq`. Public clients pass through untouched.

Current full suite: **215 passed**, same 6 pre-existing fails, on top of the
6-critical-fixes + A/D/E/F commit (all one squashed-restore baseline commit
since git history from before the sandbox reset was lost — see note above).

Tests added: tests/test_env_sanitization.py, tests/test_git_hardening.py,
tests/test_file_trust_anchor.py, tests/test_async_fs_tools.py, additions to
tests/test_oauth_store.py (RefreshTokenFamilyTests x7, ClientSecretStorageTests
x3) and tests/test_oauth_flow.py (rotation-replay + confidential-client
secret enforcement + public-client passthrough, tests 07/07a/08/09/10/11).

## NOT done yet — resume in this order
1. **Launcher G/H/I/J** (launcher.py):
   - G: `connection.txt` chmod 0600 + CONFIG_DIR 0700 + mask token in console
     output (`mask_token` helper).
   - H: macOS `ps -p <pid> -o command=` fallback in `process_command_line()`.
   - I: `stop_pid()` — SIGTERM → wait(5s) → SIGKILL, return a real bool
     reflected in the process exit code.
   - J: retry with exponential backoff (3s → 5min cap) around
     `resolve_tunnel_url`.
2. **Deps bump**: `mcp>=1.27.2` (prefer 1.28.1), `starlette>=1.3.1`, drop the
   `[cli]` extra, regenerate a lockfile with hashes; run the full e2e OAuth
   suite after bumping and fix whatever breaks.
3. **CI** (`.github/workflows/ci.yml`): matrix ubuntu/macos × Python 3.10-3.13,
   `branches: [main, master]` (repo's default branch is `master`; CI
   currently only listens on `main` — fix the mismatch), `timeout-minutes: 15`,
   add a `pip-audit` job, add `.github/dependabot.yml`, pin ruff version.
4. **POSIX wrappers**: `setup.sh` / `start.sh` / `stop.sh` mirroring the
   existing `.bat` scripts; gate any "see the .bat file" messages on
   `os.name == "nt"` vs POSIX.
5. **Fix the 6 pre-existing PATH tests** using `sys.executable` /
   `Path(sys.executable).stem` instead of hardcoded `"python"`.
6. Add tests for any remaining uncovered file tools and launcher stop logic.
7. Medium/low tech debt from the review note (TTL on temp output, cleanup of
   `*.mcp-tmp`, copy/move size limits, unify `_capture_process*` helpers,
   move `DEFAULT_ALLOWED_COMMANDS` from core into launcher, etc.) — best
   effort, lower priority than the above.
8. **Final release step**: bump `VERSION` to `2.3.0`, update `CHANGELOG.md`,
   run `python3 build_release.py` to produce the zip, deliver via Collect.

## Practical notes for whoever resumes
- Use the `Code` tool, `agent=claude`, `cwd=~/workspace/local-mcp-easy`.
  Strict TDD (failing test first). Keep calls SHORT and self-contained —
  long calls get cut off mid-work in this sandbox, and **`resume` does not
  work** ("No conversation found") — always start a fresh call and describe
  exactly what's left to do, including current git/test state, since the
  agent has zero memory of prior calls.
- **Do not trust a bare "done" from the agent** (SOUL.md Iron Law 4). After
  EVERY Code call: read the actual diff yourself, run
  `python3 -m pytest tests/ -q` yourself, and commit yourself
  (`git -c user.email=svetlana@local -c user.name="Svetlana Dev" commit`).
  Two things already caught this way: (1) a stage that mutated `os.environ`
  in tests without restoring it, breaking `test_oauth_flow.py` — fix is
  `mock.patch.dict` as a context manager / `addCleanup`; (2) a Code session
  silently ran `git reset` mid-task, uncommitting a finished stage while
  stacking new changes in the working tree — recovered via `git reflog`,
  no data lost, but always check `git log`/`git status` before trusting
  "committed" claims.
- A prior stage's design intentionally changed observable OAuth behavior
  (replaying an old refresh token now kills the ENTIRE family, including
  the just-rotated live token — this is the correct RFC 9700 posture, not a
  bug) — two pre-existing tests
  (`test_refresh_rotation_invalidates_previous_tokens` in
  test_oauth_store.py, `test_07_refresh_rotation_and_revocation` in
  test_oauth_flow.py) were updated to match; keep that in mind if a future
  change seems to "break" an old assertion about token survival after a
  replay — check whether the OLD assertion, not the new code, is stale.
- Design already approved by the project partner: deps = update fully and
  fix breakages; platform = add POSIX + fix macOS; refactor of the
  server.py monolith = explicitly deferred, do not do it. Release version
  is 2.3 (not 2.2).
- Full original review reference: note "Ревью local-mcp-easy" in Conol
  workspace `o05uzcpzr7128xgna5x7zgaz` (parent: Projects,
  `x328pgc9nc3485om0q7ehlnv`, note id `e96d9lok2zihv8h1z9ezlrw0`).
