Branch: fix/hardening. Baseline: 201 passed, 6 pre-existing fails (python vs python3 PATH, test_command_jobs.py + test_core.py — fix by using sys.executable).
Done+committed: 1) 6 critical fixes (env leak, git -c RCE, refspec delete/force-push, fetch/pull refspec, .git/repo-context write guard). 2) A/D/E/F (to_thread fs tools, _consteq const-time compare, urlsplit port fix, consent action==approve).
NOT done: B (refresh-token family revocation on reuse, RFC9700 4.14.2) + C (hash client_secret at rest) in auth/oauth.py — resume via Code tool, fresh session, same TDD approach as prior stages, baseline is 201/6.
Also pending per approved plan: deps bump (mcp>=1.28, starlette>=1.3.1), CI matrix+pip-audit, POSIX .sh wrappers + macOS ps-fallback in launcher, launcher G/H/I/J (perms, stop lifecycle, tunnel backoff), fix the 6 python-path tests, VERSION->2.3.0 + CHANGELOG, then build_release.py for the zip.
Design already approved by partner: deps=update fully, platform=add POSIX+fix macOS, refactor of server.py=deferred (do not do).
Full review reference: note "Ревью local-mcp-easy" in Conol workspace o05uzcpzr7128xgna5x7zgaz.
