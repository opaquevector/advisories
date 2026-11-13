# Security Advisory — Reflected XSS in the Banner Manager `admin/banner_manager.php` (Modified Shop)

> **Identifier:** [CVE to be requested / internal ID OV-2026-004]
> **Publication date:** [to be defined]
> **Last updated:** 12/11/2026
> **Severity:** Medium
> **CVSS:** 4.0 — `CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79 — Cross-site Scripting (Reflected)
> **Status:** Unpatched

---

## 1. Executive summary

A **Reflected XSS** vulnerability was identified in **modified eCommerce Shopsoftware (Modified Shop) 3.3.0 rev16825** (also in GitHub `main`). When saving a banner fails (e.g. an empty banner group), `admin/banner_manager.php` **rebuilds the form from `$_POST`** and reflects, **without encoding**, the `banners_image_exist[<lang>]` parameter at **two sinks** (the `<img src>` attribute and the "del_image" checkbox). An attacker can induce an administrator to submit a forged request (CSRF), executing JavaScript in the victim's session.

---

## 2. Affected products

| Product / Component | Affected versions | Fixed version | Status |
|---|---:|---:|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 rev16825 (and `main` as of 11/11/2026) | — | Affected |

### Unaffected
- Successful save flow (group filled) → `302` redirect (stored path, covered in ADV-01), which does not reflect via `$_POST`.

---

## 3. Vulnerability description

The `banners_image_exist[<lang>]` parameter is reflected without encoding at sink `L533` (`<img src>` attribute) and `L536` (checkbox). The logic that decides reflection vs storage:

```php
470: if (isset($_POST) && count($_POST) > 0) {   // R1: value from the current request
475:   $bInfo = new objectInfo($banner);
476: } elseif (isset($_GET['bID'])) {             // stored path: value from the database
```

The `$_POST` branch runs only when the save fails (e.g. empty banner group, L229): nothing is stored and the form is re-rendered from the request, reflecting the payload.

### Prerequisites
- Authentication: the victim is an administrator (with Banner Manager access).
- User interaction: the victim must submit the forged POST request (CSRF) — not deliverable via a simple link.
- Condition: empty banner group (to trigger the reflection branch).

---

## 4. Impact

- JavaScript execution in the victim administrator's session (via CSRF).
- In an admin context, may lead to privileged actions / escalation.

### Confidentiality: Low. ### Integrity: Low. ### Availability: No direct impact.

---

## 5. Classification

### CVSS
- **Score:** 4.0 — **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N`
  *(AC:H because of the save-failure condition + the need for CSRF.)*

### CWE
- **CWE-79 — Cross-site Scripting (Reflected)**

### CAPEC
- **CAPEC-591 — Reflected XSS**

---

## 6. Exploitation scenario

1. The attacker prepares a page that submits a POST to `banner_manager.php` with a malicious `banners_image_exist[1]` and an empty banner group.
2. It induces an authenticated administrator to open/submit that page (CSRF).
3. The save fails (empty group) → the form is rebuilt from `$_POST`.
4. The payload is reflected without encoding at sinks L533/L536.
5. The JavaScript executes in the administrator's session.

---

## 7. Technical evidence

### Affected component
```text
admin/banner_manager.php (L470-476 decision; sinks L533 and L536)
Parameter: banners_image_exist[<lang>]
```

### Observed response (empty group → 200, two sinks)
```html
<img style="max-width:360px;margin-bottom:10px;" src="/images/banner/x" onerror="alert('R1-reflected:'+origin)" />
<input type="checkbox" name="del_image_1" value="x" onerror="alert('R1-reflected:'+origin)" class="ChkBox">
```

### Result
| Banner group | Response | Stored? | Path |
|---|---|---|---|
| filled | `302 Found`, `Location: ...&bID=<n>` | yes | stored (DB) |
| empty | `200 OK`, form rebuilt from `$_POST` | no | reflected |

> **Note:** No tokens, cookies or real data are included in this advisory.

---

## 8. Proof of concept

```text
Parameter banners_image_exist[1] (via proxy), with an empty banner group:
x" onerror="alert(origin)
Trigger: the 200 response to the save POST (failing due to empty group)
```

### Expected result
```text
The 200 response reflects the payload at L533 (img src) and L536 (checkbox); the onerror executes (native alert).
```

### PoC limitations
- Does not cause unavailability; does not alter third-party data; no persistence/backdoor; no real credentials; no mass automation.

---

## 9. Reproduction steps

1. Access version 3.3.0 rev16825 authenticated as a Banner Manager admin.
2. Submit the banner form with `banners_image_exist[1]` = `x" onerror="alert(origin)` and an **empty banner group** (via proxy).
3. Observe the `200 OK` response with the rebuilt form.
4. Confirm execution of the `onerror` at both sinks. Expected secure behavior: the value should be encoded in the attribute.

---

## 10. Mitigation
- Validate `banners_image_exist`/`_mobile_exist` server-side (allow-list of files in `images/banner/`).
- Robust CSRF protection on admin forms.
- Encode reflected values on output.

---

## 11. Fix
No fix available at this time.

### Recommended change
- `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` at sinks L533/L536 + server-side validation of the parameter + CSRF token.

---

## 12. Detection and indicators
- POST to `banner_manager.php` with `banners_image_exist` containing `"`, `onerror=`, and an empty group.

```text
banner_manager.php .* banners_image(_mobile)?_exist=.*(onerror=|%22)
```

---

## 13. Disclosure timeline

| Date | Event |
|---|---|
| 11/11/2026 | Identified |
| 11/11/2026 | Validated |
| [to be defined] | Vendor notified (`info@modified-shop.org`) |
| [to be defined] | CVE requested |
| [to be defined] | Advisory published |

---

## 14. Vendor communication
- **Vendor:** Modified-Shop (modified-shop.org)
- **Channel:** e-mail to `info@modified-shop.org`
- **Status:** notified; awaiting response

---

## 15. Credits
- **Researcher:** Opaque Vector
- **Type:** Independent security researcher
- **Contact:** opaquevector@gmail.com
- **Profile:** https://github.com/opaquevector

---

## 16. References
- https://github.com/modified-shop/modified-shop/blob/main/admin/banner_manager.php
- CWE-79: https://cwe.mitre.org/data/definitions/79.html

---

## 17. Revision history
| Version | Date | Change |
|---|---|---|
| 1.0 | 12/11/2026 | Initial publication |

---

## 18. Legal notice

This advisory is published as part of coordinated/responsible vulnerability disclosure, for defensive and remediation purposes. The findings result from independent security research conducted by the author against instances under the author's own control. The author does not authorize or endorse the use of this information for unauthorized access, service disruption, or any unlawful activity.

---

## 19. Contact
- **E-mail:** opaquevector@gmail.com
