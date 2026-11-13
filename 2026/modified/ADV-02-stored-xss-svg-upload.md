# Security Advisory — Stored XSS via unrestricted SVG file upload in the Banner Manager (Modified Shop)

> **Identifier:** [CVE to be requested / internal ID OV-2026-002]
> **Publication date:** [to be defined]
> **Last updated:** 12/11/2026
> **Severity:** Medium
> **CVSS:** 4.8 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-434 — Unrestricted Upload of File with Dangerous Type; CWE-79 — Cross-site Scripting
> **Status:** Unpatched

---

## 1. Executive summary

A vulnerability was identified in **modified eCommerce Shopsoftware (Modified Shop) 3.3.0 rev16825** (also in GitHub `main`): the banner image upload accepts **`.svg`** files, which are stored **byte-for-byte** and served publicly as `image/svg+xml`. Because SVG can contain JavaScript, an **administrator restricted to the Banner Manager** can upload a malicious SVG that **executes JavaScript when any user — including an unauthenticated one — opens the file URL**.

Successful exploitation can result in **JavaScript execution in the same origin as the `/admin/` panel**, reaching both administrators and visitors.

---

## 2. Affected products

| Product / Component | Affected versions | Fixed version | Status |
|---|---:|---:|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 rev16825 (and `main` as of 11/11/2026) | — | Affected |

### Unaffected
- Uploads re-encoded as JPEG/GIF/PNG (processed by the `image_manipulator` `create()`), which strip active content.

---

## 3. Vulnerability description

The flaw is due to **insufficient file-type validation on upload + absence of active-content neutralization**.

`admin/includes/upload_types.php` includes `svg` in the extension allow-list and `image/svg+xml` in the accepted MIME types. `admin/includes/classes/image_manipulator.php` only re-encodes JPEG/GIF/PNG; for other types it performs a **byte-for-byte copy**. The `images/.htaccess` allows `.svg`, so Apache serves `/images/banner/<name>.svg` as `image/svg+xml`, executing embedded script when the URL is opened.

```php
// admin/includes/upload_types.php (L11-12)
$accepted_image_extensions = array("jpg","jpeg","jpe","gif","png","tiff","tif","bmp","svg");
$accepted_image_mime_types = array(..., "image/svg", "image/svg+xml");

// admin/includes/classes/image_manipulator.php (L40-41) — no transform => literal copy
} elseif (is_file($this->a) && $this->d !== "") { copy($this->a, $this->d); }
```

> Note: the UI help text does not list `svg`, but the server-side allow-list accepts it.

### Prerequisites
- Authentication: administrator restricted to the Banner Manager (upload).
- User interaction: the victim opens the SVG file URL.
- Access: remote. The victim may be **unauthenticated**.

---

## 4. Impact

- JavaScript execution in the `/admin/` origin when the file is opened.
- Reaches administrators (escalation, as in ADV-01) and **unauthenticated visitors** who open the link.

### Confidentiality: Low — victim session data.
### Integrity: Low/High — actions in the victim's context (if admin, escalation).
### Availability: No direct impact.

---

## 5. Classification

### CVSS
- **Score:** 4.8 — **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`

### CWE
- **CWE-434 — Unrestricted Upload of File with Dangerous Type**
- **CWE-79 — Cross-site Scripting**

### CAPEC
- **CAPEC-209 / CAPEC-592**

---

## 6. Exploitation scenario

1. A restricted "marketing" admin uploads a `.svg` as a banner image.
2. The server stores the file unchanged at `/images/banner/<name>.svg`.
3. The attacker sends the file URL to the victim (admin or visitor).
4. The victim opens the URL; Apache serves it as `image/svg+xml`.
5. The SVG JavaScript executes in the victim's session.

---

## 7. Technical evidence

### Affected component
```text
admin/includes/upload_types.php (allow-list)
admin/includes/classes/image_manipulator.php (L40-41, literal copy)
images/.htaccess (serves .svg)
Served URL: /images/banner/<name>.svg
```

### Observed response
```http
HTTP/1.1 200 OK
Content-Type: image/svg+xml

<svg xmlns="http://www.w3.org/2000/svg" onload="alert('S5:'+origin)"><rect width="50" height="50" fill="red"/></svg>
```

### Result
The SVG uploaded by the "marketing" account is served unchanged and executable; the native `alert()` fired in the super administrator's session when opening the URL.

> **Note:** No tokens, cookies or real data are included in this advisory.

---

## 8. Proof of concept

```text
SVG file uploaded as a banner image (field banners_image_<lang>):
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(origin)"><rect/></svg>
Trigger: open /images/banner/<name>.svg
```

### Expected result
```text
The browser executes the SVG onload (native alert), proving script execution in the admin origin.
```

### PoC limitations
- Does not cause unavailability; does not alter third-party data; no persistence/backdoor; no real credentials; no mass automation.

---

## 9. Reproduction steps

1. Access version 3.3.0 rev16825.
2. As an admin restricted to the Banner Manager, create a banner and upload the SVG above as its image.
3. Locate the served URL at `/images/banner/<name>.svg`.
4. Open the URL (as an unauthenticated visitor).
5. Observe execution of the `onload`. Expected secure behavior: the SVG should not be accepted/served as executable.

---

## 10. Mitigation
- Block `.svg` / `image/svg+xml` on image upload.
- Serve files from `images/` with `Content-Disposition: attachment` or `Content-Security-Policy: sandbox`.
- Monitor uploads with the `.svg` extension.

---

## 11. Fix
No fix available at this time.

### Recommended change
- Remove `svg` / `image/svg+xml` from the allow-lists OR sanitize SVGs server-side (strip scripts/handlers), plus serve with headers that prevent execution.

---

## 12. Detection and indicators
- Uploads to `images/banner/` with a `.svg` extension.
- SVGs containing `onload=`, `<script`, `onerror=`.

```text
POST .*banner_manager.php .* filename=".*\.svg"
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
- https://github.com/modified-shop/modified-shop/blob/main/admin/includes/upload_types.php
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
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
