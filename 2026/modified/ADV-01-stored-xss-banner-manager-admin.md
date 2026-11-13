# Security Advisory — Stored XSS in the admin panel `admin/banner_manager.php` (Modified Shop)

> **Identifier:** [CVE to be requested / internal ID OV-2026-001]
> **Publication date:** [to be defined]
> **Last updated:** 12/11/2026
> **Severity:** Medium
> **CVSS:** 4.8 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
> **Status:** Unpatched

---

## 1. Executive summary

A **Stored Cross-Site Scripting (Stored XSS)** vulnerability was identified in **modified eCommerce Shopsoftware (Modified Shop)**, version **3.3.0 rev16825** (also present in the GitHub `main` branch), allowing an **administrator restricted to the Banner Manager** (`admin_access.banner_manager = 1`) to store HTML/JavaScript that executes in the browser of **another administrator** — including the super administrator — when they open the Banner Manager screen.

Successful exploitation can result in **JavaScript execution in a higher-privileged administrator's session**, enabling **privilege escalation** within the admin panel.

---

## 2. Affected products

| Product / Component | Affected versions | Fixed version | Status |
|---|---:|---:|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 rev16825 (and `main` as of 11/11/2026) | — | Affected |

### Unaffected
- Edit-form fields `banners_title`, `banners_url`, `banners_image_title`, `banners_image_alt` — use `xtc_draw_input_field()` → `encode_htmlspecialchars()`.
- `banners_sort` / `expires_impressions` (cast to int) and `bID` (forced numeric by the global filter).

---

## 3. Vulnerability description

The vulnerability is caused by the **absence of contextual output encoding**.

Administrator-supplied values are read with `xtc_db_prepare_input()` (only `trim` + `stripslashes`) and are **not** covered by the global input filter. On output, **`admin/banner_manager.php`** prints these values with a plain `echo`, **without** `htmlspecialchars()` / `encode_htmlspecialchars()`, at four distinct sinks:

| ID | Input | Output (rev16825) | Context |
|---|---|---|---|
| S1 | `banners_title[<lang>]` | L649 (listing), L691 (info box) | HTML text |
| S2 | `new_banners_group` | L650 (listing) | HTML text |
| S3 | `banners_image_exist[<lang>]` (desktop) | L533 (`<img src>`), L536, L694 | HTML attribute |
| S4 | `banners_image_mobile_exist[<lang>]` (mobile) | L533, L536, L694 | HTML attribute |

In the current `main` branch the corresponding sinks are at lines 549, 552, 666, 667, 698, 701 and 708. The `banners_image_exist` / `_mobile_exist` fields are `<select>` elements, but the server accepts any submitted value (via an intercepting proxy).

### Prerequisites
- Authentication required: yes — an **administrator** account restricted to the Banner Manager.
- User interaction: yes — the victim (another admin) opens the Banner Manager screen.
- Access: remote (network).

---

## 4. Impact

- JavaScript execution in another administrator's session, including the super administrator.
- Privilege escalation: the restricted admin performs, via the victim's session, actions it cannot perform itself (e.g. granting itself permissions through `accounting.php`).
- Arbitrary admin actions in the victim's context (authenticated CSRF via JS).

### Confidentiality: Low — data visible in the victim admin's session.
### Integrity: Low to High — modification of settings/permissions in the victim's context (escalation).
### Availability: No direct impact.

---

## 5. Classification

### CVSS
- **Score:** 4.8 — **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
  *(If escalation to super administrator is rated as full impact `C:H/I:H`, the score reaches 8.1 — High.)*

### CWE
- **CWE-79 — Cross-site Scripting (Stored)**

### CAPEC
- **CAPEC-592 — Stored XSS**

---

## 6. Exploitation scenario

1. A restricted "marketing" administrator (Banner Manager only; `customers.php` and `accounting.php` redirect it to `login.php`) creates/edits a banner.
2. In the banner title (or group / image parameter via proxy) it inserts a JavaScript payload.
3. The application stores the value without encoding.
4. The super administrator opens the Banner Manager screen.
5. The JavaScript executes in the super admin's session → privileged actions / escalation.

---

## 7. Technical evidence

### Affected component
```text
admin/banner_manager.php  (sinks L533, L536, L649, L650, L691, L694)
Source: L119-126 (xtc_db_prepare_input)
```

### Source (S1–S4)
```php
// admin/banner_manager.php (L119-126)
$banners_title       = xtc_db_prepare_input($_POST['banners_title'][...]);
$new_banners_group   = xtc_db_prepare_input($_POST['new_banners_group']);
$banners_image_exist = xtc_db_prepare_input($_POST['banners_image'.$images_type.'_exist'][...]);
```

### Sink (example S3 — attribute without encoding)
```php
// L533 — double-quoted attribute, no encoding:
<img ... src="<?php echo DIR_WS_CATALOG_IMAGES.'banner/'.$bInfo->{'banners_image'.$images_type.'_exist'}; ?>" />
```

### Result
The stored values are rendered without encoding in the admin banner listing/edit pages, executing JavaScript in the session of whoever opens the page.

> **Note:** No tokens, cookies or real data are included in this advisory.

---

## 8. Proof of concept

Performed against an instance under the researcher's control, using the restricted "marketing" admin account.

```text
S1 — Banner Title (all language tabs): <img src=x onerror=alert(document.domain)>
S2 — New Banner Group:                 <svg onload=alert(origin)>
S3 — banners_image_exist[1] (proxy):   x" onerror="alert(origin)
S4 — banners_image_mobile_exist[1]:    x" onerror="alert(origin)
```

### Expected result
```text
On opening the listing (S1/S2) or the banner edit page (S3/S4), the native alert() fires
in the session of the administrator who opened the screen (reproduced in the super admin's session).
```

### PoC limitations
- Does not cause unavailability.
- Does not remove or modify third-party data.
- Creates no persistence or backdoor.
- Contains no real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction steps

1. Access version 3.3.0 rev16825.
2. Create an admin restricted to the Banner Manager (`admin_access.banner_manager = 1`).
3. As that admin, create/edit a banner and insert the payload in the relevant field (S1–S4; for S3/S4 change the `<select>` value via proxy).
4. Save.
5. As the super administrator, open the Banner Manager (listing for S1/S2; edit page for S3/S4).
6. Observe JavaScript execution. Expected secure behavior: the value should be rendered as inert text (encoded).

---

## 10. Mitigation

- Restrict who is granted access to the Banner Manager.
- Review permissions of low-level administrator accounts.
- Monitor banner creation/editing for suspicious content (`<`, `onerror=`, `onload=`).

---

## 11. Fix

No fix available at this time.

### Recommended change
- Encode on output: `encode_htmlspecialchars()` for HTML text (L649, L650, L691) and `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` for attributes (L533, L536, L694).
- Validate `banners_image_exist` / `_mobile_exist` server-side against the files present in `images/banner/` (allow-list) — fixes S3/S4.

---

## 12. Detection and indicators

- Requests to `admin/banner_manager.php` with `banners_title`, `new_banners_group` or `banners_image*_exist` containing `<`, `onerror=`, `onload=`, `<script`.
- Stored banners whose title/group contain HTML markup.

```text
banner_manager.php .* (onerror=|onload=|<script|%3Cscript)
```

---

## 13. Disclosure timeline

| Date | Event |
|---|---|
| 11/11/2026 | Vulnerability identified |
| 11/11/2026 | Vulnerability validated |
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
