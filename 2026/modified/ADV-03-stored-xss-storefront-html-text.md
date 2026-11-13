# Security Advisory — Stored XSS on the storefront via the banner `html_text` field (Modified Shop)

> **Identifier:** [CVE to be requested / internal ID OV-2026-003]
> **Publication date:** [to be defined]
> **Last updated:** 12/11/2026
> **Severity:** Medium
> **CVSS:** 4.8 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79 — Cross-site Scripting (Stored)
> **Status:** Unpatched

---

## 1. Executive summary

A **Stored XSS** vulnerability was identified in **modified eCommerce Shopsoftware (Modified Shop) 3.3.0 rev16825** (also in GitHub `main`). The banner **`html_text`** field (edited via CKEditor) is stored and **rendered without encoding on the shop storefront**. An **administrator restricted to the Banner Manager** can therefore inject JavaScript that executes in the browser of **every shop visitor** (including unauthenticated users and logged-in customers), not only administrators.

Successful exploitation can result in **mass JavaScript execution on the public storefront**.

---

## 2. Affected products

| Product / Component | Affected versions | Fixed version | Status |
|---|---:|---:|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 rev16825 (and `main` as of 11/11/2026) | — | Affected |

### Unaffected
- Storefront fields that pass through `|onlytext`/escape in the template (e.g. `IMAGE_TITLE`, `IMAGE_ALT`).

---

## 3. Vulnerability description

The `html_text` field is stored in the `banners_html_text` column (`banner_manager.php` L174) and rendered **without encoding** in the storefront template:

```smarty
{* templates/<tpl>/module/banners.html *}
{if $banner_data.TEXT != ''}
  <div class="banner_html_text">{$banner_data.TEXT}</div>   {* no |onlytext / escape *}
```

The storefront loader (`includes/extra/header/header_body/banners.php`) assigns this value, for active banners (`status=1`) of each group, to `{$BANNER}` on the homepage. The payload executes for **every visitor**. The `data-cke-filter="off"` attribute only disables CKEditor's **client-side** filter — it is not a security boundary, since the server stores the raw HTML regardless.

### Prerequisites
- Authentication: administrator restricted to the Banner Manager (to store).
- User interaction: the victim loads the shop homepage (normal behavior).
- Access: remote; victims may be **unauthenticated**.

---

## 4. Impact

- JavaScript execution on the public frontend for **all visitors** of the shop.
- Session/credential theft of customers, redirection, client-side defacement, abuse depending on the victim's session.

### Confidentiality: Low — visitor data/session.
### Integrity: Low — actions in the visitor's context.
### Availability: No direct impact (broad reach, not downtime).

---

## 5. Classification

### CVSS
- **Score:** 4.8 — **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
  *(Broad reach — every shop visitor; the base score keeps C:L/I:L.)*

### CWE
- **CWE-79 — Cross-site Scripting (Stored)**

### CAPEC
- **CAPEC-592 — Stored XSS**

---

## 6. Exploitation scenario

1. A restricted "marketing" admin creates/edits a banner and, in the HTML Text field (CKEditor source view), inserts a payload.
2. The server stores the raw HTML in `banners_html_text`.
3. The banner is active in a group displayed on the homepage.
4. Any visitor opens `/index.php`.
5. The JavaScript executes in the visitor's browser.

---

## 7. Technical evidence

### Affected component
```text
admin/banner_manager.php (L174, storage of banners_html_text)
templates/<tpl>/module/banners.html ({$banner_data.TEXT} without escape)
includes/extra/header/header_body/banners.php (storefront loader)
```

### Observed response (shop homepage)
```html
<div class="banner_html_text"><script>alert('S6-storefront:'+origin)</script></div>
```

### Result
`html_text` is reflected without encoding on the homepage; the native `alert()` fired for a storefront visitor.

> **Note:** No tokens, cookies or real data are included in this advisory.

---

## 8. Proof of concept

```text
HTML Text field (CKEditor source view):
<p data-cke-filter="off"><script>alert(origin)</script></p>
Trigger: load the shop homepage /index.php
```

### Expected result
```text
The script executes for the shop visitor (native alert), proving Stored XSS on the public frontend.
```

### PoC limitations
- Does not cause unavailability; does not alter third-party data; no persistence/backdoor; no real credentials; no mass automation.

---

## 9. Reproduction steps

1. Access version 3.3.0 rev16825.
2. As an admin restricted to the Banner Manager, edit a banner and insert the payload in the HTML Text field (source view).
3. Ensure the banner is active (`status=1`) in a group displayed on the homepage.
4. Open `/index.php` as an unauthenticated visitor.
5. Observe execution. Expected secure behavior: the content should be sanitized (allow-list) before storage/rendering.

---

## 10. Mitigation
- Sanitize `html_text` server-side (allow-list of tags/attributes, e.g. HTML Purifier) before storing/rendering.
- Restrict who can edit banners containing HTML.
- Monitor banners whose `html_text` contains `<script`, `on*` handlers.

> CKEditor's client-side filter is not sufficient.

---

## 11. Fix
No fix available at this time.

### Recommended change
- Server-side sanitization of `html_text` (allow-list) on write and/or escaping in the storefront template.
- Keep the bundled CKEditor updated (see References — the bundle is CKEditor 4.22.1).

---

## 12. Detection and indicators
- `banner_manager.php` receiving `html_text` with `<script`, `on*=`, `javascript:`.
- Active banners whose HTML text contains executable markup.

```text
banners_html_text .* (<script|on\w+=|javascript:)
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
- https://github.com/modified-shop/modified-shop/blob/main/templates
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- Outdated component (note): CKEditor 4.22.1 — CVE-2024-24816 (XSS in samples with the preview feature); update the bundle.

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
