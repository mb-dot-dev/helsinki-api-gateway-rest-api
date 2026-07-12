# Application Review Findings — Implementation Plan

Full-application review performed 2026-07-12. Each item is self-contained and can be
implemented independently unless a dependency is noted. Verify with `make test` (lint +
unit) after each change; infrastructure changes with `make cfn-lint`.

Priority order: items 1, 2, 6, 16 first (security + broken output + repo hygiene).

---

## Security

### 1. Use constant-time comparison for client credentials
- **File:** `app/oauth.py:27`
- **Problem:** `client_id != ... or client_secret != ...` uses ordinary string
  comparison, which short-circuits on the first differing byte and leaks timing
  information that can be used to recover the secret.
- **Fix:** Use `hmac.compare_digest()` for both comparisons, and combine with `&`
  (bitwise, non-short-circuiting) instead of `or` so both checks always execute:
  ```python
  import hmac

  valid = hmac.compare_digest(client_id, jwt_config.allowed_client_id) & hmac.compare_digest(
      client_secret, jwt_config.allowed_client_secret
  )
  if not valid:
      ...
  ```
- **Tests:** Existing tests in `tests/test_oauth.py` cover accept/reject paths; they
  must keep passing unchanged.

### 2. Stop injecting secrets as plaintext Lambda environment variables
- **Files:** `template.yaml:24-35, 85-87`, `app/jwt.py:23-28`
- **Problem:** `ALLOWED_CLIENT_SECRET` and `JWT_SIGNING_SECRET` are resolved via
  `AWS::SSM::Parameter::Value<String>` (which cannot read SecureString, so they are
  plain `String` params in SSM) and exposed as Lambda env vars, readable by anyone
  with `lambda:GetFunctionConfiguration`.
- **Fix:**
  1. Store `/projects/helsinki/allowed-client-secret` and
     `/projects/helsinki/jwt-signing-secret` as SecureString in SSM (manual/out-of-band
     step — flag it in the PR description).
  2. Remove those two parameters and env vars from `template.yaml`; instead pass the
     SSM parameter *names* as env vars (e.g. `ALLOWED_CLIENT_SECRET_PARAM`,
     `JWT_SIGNING_SECRET_PARAM`).
  3. In `get_jwt_config()`, fetch values with Powertools:
     `aws_lambda_powertools.utilities.parameters.get_parameter(name, decrypt=True, max_age=300)`.
  4. Add `ssm:GetParameter` (and `kms:Decrypt` for the SSM default key) for those two
     parameter ARNs to the Lambda role in `aws/iam-role.yml`.
- **Tests:** Update `tests/conftest.py` env fixture; mock/moto the SSM parameters or
  monkeypatch `get_parameter`. Keep `ALLOWED_CLIENT_ID` as a plain env var (not secret).
- **Note:** Interacts with item 12 — Powertools `max_age` provides caching; do NOT also
  wrap `get_jwt_config` in `functools.cache` if this item is done.

### 3. Validate issuer and require claims when decoding JWTs
- **File:** `app/jwt.py:45`
- **Problem:** `jwt.decode()` checks signature and audience but not `iss`, and does not
  require any claims to be present.
- **Fix:**
  ```python
  jwt.decode(
      jwt_token,
      jwt_config.signing_secret,
      algorithms=["HS256"],
      audience=jwt_config.audience,
      issuer=jwt_config.issuer,
      options={"require": ["exp", "iat", "aud", "iss"]},
  )
  ```
- **Tests:** Add test functions (no test classes — see item 14) for: token with wrong
  issuer → 401; token missing `exp` → 401.

### 4. Validate `grant_type` on the token endpoint
- **File:** `app/oauth.py` (`issue_token`, `_get_client_credentials`)
- **Problem:** RFC 6749 requires the token endpoint to validate
  `grant_type=client_credentials`; the endpoint currently ignores it entirely.
- **Fix:** Parse `grant_type` from the request body (both JSON and form branches).
  If it is missing or not `client_credentials`, return
  `400` with body `{"error": "unsupported_grant_type"}`.
- **Tests:** New test functions: missing grant_type → 400; wrong grant_type → 400;
  `grant_type=client_credentials` + valid creds → 200. Update existing happy-path
  tests to include `grant_type=client_credentials` in their bodies.

### 5. Add stage-level throttling
- **File:** `template.yaml` (ApiGateway resource)
- **Problem:** No usage plan or method settings; only account-level default throttling
  protects the token endpoint against brute force (IP allowlist mitigates but defense
  in depth is cheap).
- **Fix:** On `AWS::Serverless::Api` add:
  ```yaml
  MethodSettings:
    - ResourcePath: "/*"
      HttpMethod: "*"
      ThrottlingRateLimit: 10
      ThrottlingBurstLimit: 20
  ```
  (Limits are suggestions; keep them low — this is a single-client API.)
- **Verify:** `make cfn-lint`.

---

## Correctness

### 6. Fix `ApiGatewayUrl` output — missing stage path
- **File:** `template.yaml:48`
- **Problem:** Output is `https://${ApiGateway}.execute-api.${AWS::Region}.amazonaws.com/`
  but REST API v1 requires the stage segment. The URL as output returns 403.
- **Fix:** Append the stage: `.../amazonaws.com/Prod/`.

### 7. Remove dead outputs in CI `prepare` job
- **File:** `.github/workflows/main.yaml:27-28`
- **Problem:** `jwt_issuer` and `jwt_audience` outputs reference
  `steps.vars.outputs.JWT_ISSUER`/`JWT_AUDIENCE`, which are never set by the `vars`
  step. They are always empty and nothing consumes them.
- **Fix:** Delete both output lines. (Alternative — only if doing item 8 via CI
  parameter-overrides: actually set them in the `vars` step and pass them through to
  `sam deploy`. Deleting is the simpler, preferred option.)

### 8. Move hardcoded issuer/audience out of code
- **File:** `app/jwt.py:19-20`, `template.yaml`
- **Problem:** `JwtConfig` bakes `https://auth.molnarbence.dev/` and `api://default`
  defaults into the package instead of configuration.
- **Fix:** Add `JWT_ISSUER` and `JWT_AUDIENCE` env vars in `template.yaml` (plain
  values or SSM `String` params, they are not secrets) and read them in
  `get_jwt_config()`. Keep the current values as the defaults if the env vars are
  absent, so tests and local runs keep working.
- **Tests:** `tests/conftest.py` already defines `ISSUER`/`AUDIENCE` constants — set
  the env vars in the `_lambda_env` fixture from those constants.

---

## Code quality

### 9. Rename `app/jwt.py` — it shadows the `pyjwt` package name
- **Files:** `app/jwt.py`, imports in `app/oauth.py:10`, `app/producer.py:11`
- **Problem:** The module is named `jwt` and itself does `import jwt`. Works with
  absolute imports but is confusing and fragile under refactoring.
- **Fix:** Rename to `app/auth.py` (`git mv`), update the two imports. No test imports
  it directly today; grep to confirm.

### 10. Use Powertools case-insensitive headers directly in `issue_token`
- **File:** `app/oauth.py:19-22`
- **Problem:** `dict(event.headers or {})` copies the headers into a plain dict and
  then does `headers.get("content-type")` — this only works because Powertools happens
  to normalize keys; the copy is unnecessary and relies on an implementation detail.
- **Fix:** Drop the `dict(...)` copy; use
  `content_type = event.headers.get("content-type", "")` directly (same pattern as the
  `Authorization` lookup in the bearer middleware).

### 11. Extract duplicated constants
- **Files:** `app/oauth.py:44,57`, `app/main.py:13`, `app/producer.py:14`,
  `template.yaml`
- **Fix:**
  - Add `TOKEN_TTL_SECONDS = 3600` module constant in `app/oauth.py`; use it for the
    `exp` claim and the `expires_in` response field.
  - Remove `namespace="Helsinki"` from both `Metrics(...)` constructors and instead set
    `POWERTOOLS_METRICS_NAMESPACE: Helsinki` in the Lambda env vars in `template.yaml`.
    Tests will need the env var set in `tests/conftest.py` `_lambda_env`.

### 12. Cache `get_jwt_config()`
- **File:** `app/jwt.py:23`
- **Fix:** Add `@functools.cache` (matches the `get_sqs_client` pattern in
  `app/clients.py`). **Skip this item if item 2 is implemented** — Powertools
  `get_parameter(max_age=...)` already caches, and `functools.cache` would prevent
  secret rotation from ever being picked up.
- **Tests:** If cached, add `get_jwt_config.cache_clear()` to an autouse fixture in
  `tests/conftest.py` so monkeypatched env vars take effect per-test.

### 13. Return 413 for bodies exceeding the SQS message size limit
- **File:** `app/producer.py` (`enqueue`)
- **Problem:** API Gateway accepts up to 10 MB but SQS rejects messages >256 KB (262,144
  bytes); today this surfaces as a generic 500 after a wasted SQS round-trip.
- **Fix:** Before calling `send_message`, check `len(event_body.encode("utf-8")) >
  262_144` and return `Response(status_code=413, ...)` with a JSON message.
- **Tests:** New test function with an oversized body asserting 413 and that no message
  was enqueued.

---

## Tests

### 14. Flatten `TestEnqueue` class into individual test functions
- **File:** `tests/test_producer.py:38`
- **Problem:** Project convention is individual test functions, never test classes
  (the other test files already comply).
- **Fix:** Remove the class, dedent all methods into module-level functions, drop the
  `self` parameter, and prefix names for clarity (e.g. `test_enqueue_accepts_request_with_valid_token`).
  No behavior changes; all 25 tests must still pass.

### 15. Make SQS client cache tests order-independent
- **File:** `tests/test_clients.py`, `app/clients.py`
- **Problem:** `get_sqs_client` is `functools.cache`d and shared across the test
  session; producer tests populate the cache under `mock_aws`, so `test_clients.py`
  results depend on test execution order.
- **Fix:** Add an autouse fixture (in `tests/conftest.py`) that calls
  `get_sqs_client.cache_clear()` before each test.

---

## Infrastructure / housekeeping

### 16. Remove committed coverage artifact and tighten .gitignore
- **Files:** `.coverage` (tracked in git), `.gitignore`
- **Fix:**
  ```
  git rm --cached .coverage
  ```
  Add to `.gitignore`: `.coverage`, `.pytest_cache/`, `.ruff_cache/`.

### 17. Template polish
- **File:** `template.yaml`, `Makefile`
- **Fixes (independent, all optional):**
  - `Architectures: [arm64]` on the Function (cheaper; all deps are pure Python).
    **Must be done together with** changing `--python-platform x86_64-manylinux2014`
    to `aarch64-manylinux2014` in the Makefile `install-pip-ci` target.
  - `TracingEnabled: true` on the API and `Tracing: Active` on the Function (X-Ray).
    Requires X-Ray write permissions on the Lambda role (`aws/iam-role.yml`) — add
    the `AWSXRayDaemonWriteAccess` managed policy.
  - Restrict the two API events from `Method: ANY` to `Method: POST` — both routes
    are POST-only; the resolver 404s other methods anyway, but this avoids invoking
    Lambda for junk requests. Verify the resolver still returns proper 403/404 via the
    gateway for non-POST after the change.
- **Verify:** `make cfn-lint`; arm64 change needs a real deploy to verify.

### 18. Write a real README and project description
- **Files:** `README.md`, `pyproject.toml:4`
- **Fix:** Replace the placeholder description in `pyproject.toml`. Expand README to
  cover: the two endpoints (`POST /oauth/token` client-credentials flow, `POST /`
  enqueue with Bearer JWT), required SSM parameters (`/sqs/oslo/queue-url`,
  `/allowed-ips/all`, `/projects/helsinki/*`), the deploy pipeline (GitHub Actions →
  SAM), and local dev commands (`make install-dev`, `make test`).

---

## Verification checklist (run after all changes)

- [ ] `make test` — lint (ruff + ty) and all unit tests pass
- [ ] `make cfn-lint` — templates valid
- [ ] `make coverage` — coverage still ≥ 75%
- [ ] No test classes remain (`grep -rn "^class Test" tests/` is empty)
- [ ] No secrets in `Environment.Variables` in `template.yaml` (if item 2 done)
