// Generated from two real VulnForge scans of a throwaway web server on the author's own machine.
// Nothing here was invented; long descriptions are shortened.
window.SCANS = [
 {
  "label": "Web scan",
  "blurb": "HTTP checks against a local test page that is deliberately missing its security headers.",
  "id": "VF-20261106-205938",
  "target": "http://127.0.0.1:8899/",
  "duration": 2.06,
  "summary": {
   "total_findings": 10,
   "severity_counts": {
    "critical": 0,
    "high": 0,
    "medium": 5,
    "low": 5,
    "info": 0
   },
   "open_ports": 0,
   "risk_score": 25,
   "web_checks": 12,
   "hidden_low_confidence": 0
  },
  "ports": [],
  "findings": [
   {
    "title": "HTTPS Not Available (Plain HTTP Only)",
    "sev": "medium",
    "conf": "high",
    "src": "web_scan",
    "desc": "The site could only be reached over plain HTTP, so traffic is unencrypted and browsers ignore HSTS on HTTP responses.",
    "fix": "Serve the site over HTTPS with a valid certificate and redirect HTTP to it.",
    "ev": "Final URL after redirects: http://127.0.0.1:8899/",
    "cat": "transport",
    "g": 0,
    "cve": null
   },
   {
    "title": "Missing Security Header: Content-Security-Policy",
    "sev": "medium",
    "conf": "high",
    "src": "web_scan",
    "desc": "CSP missing — increased XSS risk.",
    "fix": "Add 'Content-Security-Policy' response header with appropriate value.",
    "ev": "",
    "cat": "security_headers",
    "g": 1,
    "cve": null
   },
   {
    "title": "Missing Security Header: X-Frame-Options",
    "sev": "medium",
    "conf": "high",
    "src": "web_scan",
    "desc": "X-Frame-Options missing — clickjacking risk.",
    "fix": "Add 'X-Frame-Options' response header with appropriate value.",
    "ev": "",
    "cat": "security_headers",
    "g": 1,
    "cve": null
   },
   {
    "title": "Cookie Missing Secure Flag: sid",
    "sev": "medium",
    "conf": "high",
    "src": "web_scan",
    "desc": "Cookie 'sid' transmitted over plain HTTP.",
    "fix": "Set Secure flag on all cookies.",
    "ev": "",
    "cat": "cookies",
    "g": 2,
    "cve": null
   },
   {
    "title": "Cookie Missing HttpOnly Flag: sid",
    "sev": "medium",
    "conf": "high",
    "src": "web_scan",
    "desc": "Cookie 'sid' accessible via JavaScript (XSS risk).",
    "fix": "Set HttpOnly flag on session cookies.",
    "ev": "",
    "cat": "cookies",
    "g": 2,
    "cve": null
   },
   {
    "title": "Missing Security Header: X-Content-Type-Options",
    "sev": "low",
    "conf": "high",
    "src": "web_scan",
    "desc": "X-Content-Type-Options missing — MIME sniffing risk.",
    "fix": "Add 'X-Content-Type-Options' response header with appropriate value.",
    "ev": "",
    "cat": "security_headers",
    "g": 1,
    "cve": null
   },
   {
    "title": "Missing Security Header: Referrer-Policy",
    "sev": "low",
    "conf": "high",
    "src": "web_scan",
    "desc": "Referrer-Policy not set — may leak sensitive URLs.",
    "fix": "Add 'Referrer-Policy' response header with appropriate value.",
    "ev": "",
    "cat": "security_headers",
    "g": 1,
    "cve": null
   },
   {
    "title": "Missing Security Header: Permissions-Policy",
    "sev": "low",
    "conf": "high",
    "src": "web_scan",
    "desc": "Permissions-Policy not set — browser features uncontrolled.",
    "fix": "Add 'Permissions-Policy' response header with appropriate value.",
    "ev": "",
    "cat": "security_headers",
    "g": 1,
    "cve": null
   },
   {
    "title": "Server Information Disclosure: Server",
    "sev": "low",
    "conf": "high",
    "src": "web_scan",
    "desc": "Header 'Server: SimpleHTTP/0.6 Python/3.13.15' reveals server technology.",
    "fix": "Remove or obfuscate the 'Server' response header.",
    "ev": "Server: SimpleHTTP/0.6 Python/3.13.15",
    "cat": "info_disclosure",
    "g": 3,
    "cve": null
   },
   {
    "title": "Cookie SameSite Not Strict/Lax: sid",
    "sev": "low",
    "conf": "high",
    "src": "web_scan",
    "desc": "Cookie 'sid' SameSite=None — CSRF risk.",
    "fix": "Set SameSite=Strict or SameSite=Lax on cookies.",
    "ev": "",
    "cat": "cookies",
    "g": 2,
    "cve": null
   }
  ]
 },
 {
  "label": "Port + CVE scan",
  "blurb": "nmap service detection on the same server, then offline CVE matching on the banner it reported.",
  "id": "VF-20261106-205952",
  "target": "http://127.0.0.1:8899/",
  "duration": 10.29,
  "summary": {
   "total_findings": 69,
   "severity_counts": {
    "critical": 21,
    "high": 48,
    "medium": 0,
    "low": 0,
    "info": 0
   },
   "open_ports": 1,
   "risk_score": 100,
   "web_checks": 0,
   "hidden_low_confidence": 0
  },
  "ports": [
   {
    "port": "tcp/8899",
    "service": "http",
    "product": "Apache httpd",
    "version": "2.4.49"
   }
  ],
  "findings": [
   {
    "title": "CVE-2021-41773 — Apache HTTP Server path traversal / RCE",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Path traversal in Apache HTTP Server 2.4.49 allows mapping URLs to files outside the document root; combined with mod_cgi can lead to RCE.",
    "fix": "Upgrade to Apache HTTP Server 2.4.51 or later.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2021-41773"
   },
   {
    "title": "CVE-2021-42013 — It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was in [CISA KEV:…",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories a…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2021-42013"
   },
   {
    "title": "CVE-2021-44790 — A carefully crafted request body can cause a buffer overflow in the mod_lua mult",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser (r:parsebody() called from Lua scripts). The Apache httpd team is not aware of an exploit for the vulnerabilty though it might be possible to craft one. This issue af…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2021-44790"
   },
   {
    "title": "CVE-2022-22720 — Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when err",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered discarding the request body, exposing the server to HTTP Request Smuggling CVSS 9.8.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2022-22720"
   },
   {
    "title": "CVE-2022-22721 — If LimitXMLRequestBody is set to allow request bodies larger than 350MB (default",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "If LimitXMLRequestBody is set to allow request bodies larger than 350MB (defaults to 1M) on 32 bit systems an integer overflow happens which later causes out of bounds writes. This issue affects Apache HTTP Server 2.4.52 and earlier. CVSS 9.1.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2022-22721"
   },
   {
    "title": "CVE-2022-23943 — Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an att",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap memory with possibly attacker provided data. This issue affects Apache HTTP Server 2.4 version 2.4.52 and prior versions. CVSS 9.8.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2022-23943"
   },
   {
    "title": "CVE-2022-28615 — Apache HTTP Server 2.4.53 and earlier may crash or disclose information due to a",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Apache HTTP Server 2.4.53 and earlier may crash or disclose information due to a read beyond bounds in ap_strcmp_match() when provided with an extremely large input buffer. While no code distributed with the server can be coerced into such a call, third-party…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2022-28615"
   },
   {
    "title": "CVE-2022-31813 — Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* headers to",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* headers to the origin server based on client side Connection header hop-by-hop mechanism. This may be used to bypass IP based authentication on the origin server/application. CVSS 9.8.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2022-31813"
   },
   {
    "title": "CVE-2022-36760 — Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerab",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This issue affects Apache HTTP Server Apache HTTP Se…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2022-36760"
   },
   {
    "title": "CVE-2023-25690 — Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.5",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 allow a HTTP Request Smuggling attack. Configurations are affected when mod_proxy is enabled along with some form of RewriteRule or ProxyPassMatch in which a non-specific patter…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2023-25690"
   },
   {
    "title": "CVE-2024-38474 — Substitution encoding issue in mod_rewrite in Apache HTTP Server 2.4.59 and earl",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Substitution encoding issue in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows attacker to execute scripts in directories permitted by the configuration but not directly reachable by any URL or source disclosure of scripts meant to only to be exec…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-38474"
   },
   {
    "title": "CVE-2024-38475 — Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earl [CISA KEV:…",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem locations that are permitted to be served by the server but are not intentionally/directly reachable by any URL, resulting in code…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-38475"
   },
   {
    "title": "CVE-2024-38476 — Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are vulnerably to",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are vulnerably to information disclosure, SSRF or local script execution via backend applications whose response headers are malicious or exploitable. Users are recommended to upgrade to version 2…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-38476"
   },
   {
    "title": "CVE-2025-23048 — In some mod_ssl configurations on Apache HTTP Server 2.4.35 through to 2.4.63, a",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "In some mod_ssl configurations on Apache HTTP Server 2.4.35 through to 2.4.63, an access control bypass by trusted clients is possible using TLS 1.3 session resumption. Configurations are affected when mod_ssl is configured for multiple virtual hosts, with ea…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2025-23048"
   },
   {
    "title": "CVE-2026-28780 — Heap-based Buffer Overflow vulnerability in mod_proxy_ajp of Apache HTTP Server.",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Heap-based Buffer Overflow vulnerability in mod_proxy_ajp of Apache HTTP Server. If mod_proxy_ajp connects to a malicious AJP server this AJP server can send a malicious AJP message back to mod_proxy_ajp and cause it to write 4 attacker controlled bytes after…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-28780"
   },
   {
    "title": "CVE-2026-29167 — Use After Free vulnerability in Apache HTTP Server with mod_ldap in per-director",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Use After Free vulnerability in Apache HTTP Server with mod_ldap in per-directory configuration This issue affects Apache HTTP Server: from 2.4.0 through 2.4.67. Users are recommended to upgrade to version 2.4.68, which fixes the issue. CVSS 9.8.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-29167"
   },
   {
    "title": "CVE-2026-42535 — A path handling issue in mod_dav_fs in Apache 2.4.67 and earlier allows a WebDAV",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "A path handling issue in mod_dav_fs in Apache 2.4.67 and earlier allows a WebDAV content author to directly manipulate trusted DAV property databases, potentially causing child process crashes. Users are recommended to upgrade to version 2.4.68, which fixes t…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-42535"
   },
   {
    "title": "CVE-2026-44631 — Buffer Underwrite vulnerability in Apache HTTP Server on crafted regular express",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Buffer Underwrite vulnerability in Apache HTTP Server on crafted regular expressions in the configuration. This issue affects Apache HTTP Server: from 2.4.0 through 2.4.67. Users are recommended to upgrade to version 2.4.68, which fixes the issue. CVSS 9.8.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-44631"
   },
   {
    "title": "CVE-2026-56154 — Use After Free vulnerability in Apache HTTP Server's mod_rewrite when using look",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Use After Free vulnerability in Apache HTTP Server's mod_rewrite when using lookahead (%{LA-U:HTTP:...}) This issue affects Apache HTTP Server: from 2.4.0 through 2.4.68. CVSS 9.8.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-56154"
   },
   {
    "title": "CVE-2026-57941 — Use After Free vulnerability in Apache HTTP Server's mod_http2 via shared sessio",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Use After Free vulnerability in Apache HTTP Server's mod_http2 via shared session->bbtmp re-entrancy This issue affects Apache HTTP Server: from 2.4.0 through 2.4.68. CVSS 9.8.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-57941"
   },
   {
    "title": "CVE-2026-59797 — Improper Privilege Management vulnerability in Apache HTTP Server's mod_ssl via",
    "sev": "critical",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Improper Privilege Management vulnerability in Apache HTTP Server's mod_ssl via SSLRequire and file-related expressions. This issue affects Apache HTTP Server: from 2.4.0 through 2.4.68. CVSS 9.8.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-59797"
   },
   {
    "title": "CVE-2006-20001 — A carefully crafted If: request header can cause a memory read, or write of a si",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "A carefully crafted If: request header can cause a memory read, or write of a single zero byte, in a pool (heap) memory location beyond the header value sent. This could cause the process to crash. This issue affects Apache HTTP Server 2.4.54 and earlier. CVS…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2006-20001"
   },
   {
    "title": "CVE-2021-41524 — While fuzzing the 2.4.49 httpd, a new null pointer dereference was detected duri",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "While fuzzing the 2.4.49 httpd, a new null pointer dereference was detected during HTTP/2 request processing, allowing an external source to DoS the server. This requires a specially crafted request. The vulnerability was recently introduced in version 2.4.49…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2021-41524"
   },
   {
    "title": "CVE-2021-44224 — A crafted URI sent to httpd configured as a forward proxy (ProxyRequests on) can",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "A crafted URI sent to httpd configured as a forward proxy (ProxyRequests on) can cause a crash (NULL pointer dereference) or, for configurations mixing forward and reverse proxy declarations, can allow for requests to be directed to a declared Unix Domain Soc…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2021-44224"
   },
   {
    "title": "CVE-2022-22719 — A carefully crafted request body can cause a read to a random memory area which",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "A carefully crafted request body can cause a read to a random memory area which could cause the process to crash. This issue affects Apache HTTP Server 2.4.52 and earlier. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2022-22719"
   },
   {
    "title": "CVE-2022-26377 — Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerab",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This issue affects Apache HTTP Server Apache HTTP Se…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2022-26377"
   },
   {
    "title": "CVE-2022-29404 — In Apache HTTP Server 2.4.53 and earlier, a malicious request to a lua script th",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "In Apache HTTP Server 2.4.53 and earlier, a malicious request to a lua script that calls r:parsebody(0) may cause a denial of service due to no default limit on possible input size. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2022-29404"
   },
   {
    "title": "CVE-2022-30556 — Apache HTTP Server 2.4.53 and earlier may return lengths to applications calling",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Apache HTTP Server 2.4.53 and earlier may return lengths to applications calling r:wsread() that point past the end of the storage allocated for the buffer. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2022-30556"
   },
   {
    "title": "CVE-2023-27522 — HTTP Response Smuggling vulnerability in Apache HTTP Server via mod_proxy_uwsgi.",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "HTTP Response Smuggling vulnerability in Apache HTTP Server via mod_proxy_uwsgi. This issue affects Apache HTTP Server: from 2.4.30 through 2.4.55. Special characters in the origin response header can truncate/split the response forwarded to the client. CVSS…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2023-27522"
   },
   {
    "title": "CVE-2023-31122 — Out-of-bounds Read vulnerability in mod_macro of Apache HTTP Server.This issue a",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Out-of-bounds Read vulnerability in mod_macro of Apache HTTP Server.This issue affects Apache HTTP Server: through 2.4.57. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2023-31122"
   },
   {
    "title": "CVE-2023-38709 — Faulty input validation in the core of Apache allows malicious or exploitable ba",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Faulty input validation in the core of Apache allows malicious or exploitable backend/content generators to split HTTP responses. This issue affects Apache HTTP Server: through 2.4.58. CVSS 7.3.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2023-38709"
   },
   {
    "title": "CVE-2024-27316 — HTTP/2 incoming headers exceeding the limit are temporarily buffered in nghttp2",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "HTTP/2 incoming headers exceeding the limit are temporarily buffered in nghttp2 in order to generate an informative HTTP 413 response. If a client does not stop sending headers, this leads to memory exhaustion. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-27316"
   },
   {
    "title": "CVE-2024-38472 — SSRF in Apache HTTP Server on Windows allows to potentially leak NTLM hashes to",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "SSRF in Apache HTTP Server on Windows allows to potentially leak NTLM hashes to a malicious server via SSRF and malicious requests or content Users are recommended to upgrade to version 2.4.60 which fixes this issue. Note: Existing configurations that access…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-38472"
   },
   {
    "title": "CVE-2024-38473 — Encoding problem in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows re",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Encoding problem in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows request URLs with incorrect encoding to be sent to backend services, potentially bypassing authentication via crafted requests. Users are recommended to upgrade to version 2.4.60, w…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-38473"
   },
   {
    "title": "CVE-2024-38477 — null pointer dereference in mod_proxy in Apache HTTP Server 2.4.59 and earlier a",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "null pointer dereference in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows an attacker to crash the server via a malicious request. Users are recommended to upgrade to version 2.4.60, which fixes this issue. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-38477"
   },
   {
    "title": "CVE-2024-39573 — Potential SSRF in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Potential SSRF in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to cause unsafe RewriteRules to unexpectedly setup URL's to be handled by mod_proxy. Users are recommended to upgrade to version 2.4.60, which fixes this issue. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-39573"
   },
   {
    "title": "CVE-2024-40898 — SSRF in Apache HTTP Server on Windows with mod_rewrite in server/vhost context,",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "SSRF in Apache HTTP Server on Windows with mod_rewrite in server/vhost context, allows to potentially leak NTML hashes to a malicious server via SSRF and malicious requests. Users are recommended to upgrade to version 2.4.62 which fixes this issue. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-40898"
   },
   {
    "title": "CVE-2024-42516 — HTTP response splitting in the core of Apache HTTP Server allows an attacker who",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "HTTP response splitting in the core of Apache HTTP Server allows an attacker who can manipulate the Content-Type response headers of applications hosted or proxied by the server can split the HTTP response. This vulnerability was described as CVE-2023-38709 b…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-42516"
   },
   {
    "title": "CVE-2024-43204 — SSRF in Apache HTTP Server with mod_proxy loaded allows an attacker to send outb",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "SSRF in Apache HTTP Server with mod_proxy loaded allows an attacker to send outbound proxy requests to a URL controlled by the attacker. Requires an unlikely configuration where mod_headers is configured to modify the Content-Type request or response header w…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-43204"
   },
   {
    "title": "CVE-2024-43394 — Server-Side Request Forgery (SSRF) in Apache HTTP Server on Windows allows to po",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Server-Side Request Forgery (SSRF) in Apache HTTP Server on Windows allows to potentially leak NTLM hashes to a malicious server via mod_rewrite or apache expressions that pass unvalidated request input. This issue affects Apache HTTP Server: from 2.4.0 throu…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-43394"
   },
   {
    "title": "CVE-2024-47252 — Insufficient escaping of user-supplied data in mod_ssl in Apache HTTP Server 2.4",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Insufficient escaping of user-supplied data in mod_ssl in Apache HTTP Server 2.4.63 and earlier allows an untrusted SSL/TLS client to insert escape characters into log files in some configurations. In a logging configuration where CustomLog is used with \"%{va…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2024-47252"
   },
   {
    "title": "CVE-2025-49630 — In certain proxy configurations, a denial of service attack against Apache HTTP",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "In certain proxy configurations, a denial of service attack against Apache HTTP Server versions 2.4.26 through to 2.4.63 can be triggered by untrusted clients causing an assertion in mod_proxy_http2. Configurations affected are a reverse proxy is configured f…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2025-49630"
   },
   {
    "title": "CVE-2025-49812 — In some mod_ssl configurations on Apache HTTP Server versions through to 2.4.63,",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "In some mod_ssl configurations on Apache HTTP Server versions through to 2.4.63, an HTTP desynchronisation attack allows a man-in-the-middle attacker to hijack an HTTP session via a TLS upgrade. Only configurations using \"SSLEngine optional\" to enable TLS upg…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2025-49812"
   },
   {
    "title": "CVE-2025-53020 — Late Release of Memory after Effective Lifetime vulnerability in Apache HTTP Ser",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Late Release of Memory after Effective Lifetime vulnerability in Apache HTTP Server. This issue affects Apache HTTP Server: from 2.4.17 up to 2.4.63. Users are recommended to upgrade to version 2.4.64, which fixes the issue. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2025-53020"
   },
   {
    "title": "CVE-2025-55753 — An integer overflow in the case of failed ACME certificate renewal leads, after",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "An integer overflow in the case of failed ACME certificate renewal leads, after a number of failures (~30 days in default configurations), to the backoff timer becoming 0. Attempts to renew the certificate then are repeated without delays until it succeeds. T…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2025-55753"
   },
   {
    "title": "CVE-2025-58098 — Apache HTTP Server 2.4.65 and earlier with Server Side Includes (SSI) enabled an",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Apache HTTP Server 2.4.65 and earlier with Server Side Includes (SSI) enabled and mod_cgid (but not mod_cgi) passes the shell-escaped query string to #exec cmd=\"...\" directives. This issue affects Apache HTTP Server before 2.4.66. Users are recommended to upg…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2025-58098"
   },
   {
    "title": "CVE-2025-59775 — Server-Side Request Forgery (SSRF) vulnerability in Apache HTTP Server on Window",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Server-Side Request Forgery (SSRF) vulnerability in Apache HTTP Server on Windows with AllowEncodedSlashes On and MergeSlashes Off allows to potentially leak NTLM hashes to a malicious server via SSRF and malicious requests or content Users are recommended to…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2025-59775"
   },
   {
    "title": "CVE-2026-24072 — An escalation of privilege bug in various modules in Apache HTTP 2.4.66 and earl",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "An escalation of privilege bug in various modules in Apache HTTP 2.4.66 and earlier allows local .htaccess authors to read files with the privileges of the httpd user. Users are recommended to upgrade to version 2.4.67, which fixes this issue. CVSS 8.8.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-24072"
   },
   {
    "title": "CVE-2026-29168 — Allocation of Resources Without Limits or Throttling vulnerability in Apache HTT",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Allocation of Resources Without Limits or Throttling vulnerability in Apache HTTP Server's mod_md via OCSP response data. This issue affects Apache HTTP Server: from 2.4.30 through 2.4.66. Users are recommended to upgrade to version 2.4.67, which fixes the is…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-29168"
   },
   {
    "title": "CVE-2026-29169 — A NULL pointer dereference in mod_dav_lock in Apache HTTP Server 2.4.66 and earl",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "A NULL pointer dereference in mod_dav_lock in Apache HTTP Server 2.4.66 and earlier may allow an attacker to crash the server with a malicious request.mod_dav_lock is not used internally by mod_dav or mod_dav_fs. The only known use-case for mod_dav_lock was m…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-29169"
   },
   {
    "title": "CVE-2026-34059 — Buffer Over-read vulnerability in Apache HTTP Server. This issue affects Apache",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Buffer Over-read vulnerability in Apache HTTP Server. This issue affects Apache HTTP Server: through 2.4.66. Users are recommended to upgrade to version 2.4.67, which fixes the issue. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-34059"
   },
   {
    "title": "CVE-2026-34355 — A buffer overflow in mod_proxy_html in Apache HTTP Server 2.4.67 and earlier all",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "A buffer overflow in mod_proxy_html in Apache HTTP Server 2.4.67 and earlier allows an attack by an untrusted backend. Users are recommended to upgrade to version 2.4.68, which fixes this issue. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-34355"
   },
   {
    "title": "CVE-2026-34356 — Heap-based Buffer Overflow vulnerability in Apache HTTP Server with malicious ba",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Heap-based Buffer Overflow vulnerability in Apache HTTP Server with malicious backend servers and ProxyPassReverseCookie* This issue affects Apache HTTP Server: from 2.4.0 through 2.4.67. Users are recommended to upgrade to version 2.4.68, which fixes the iss…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-34356"
   },
   {
    "title": "CVE-2026-42536 — Heap-based Buffer Overflow vulnerability in Apache HTTP Server with mod_xml2enc,",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Heap-based Buffer Overflow vulnerability in Apache HTTP Server with mod_xml2enc, xml2StartParse, and untrusted content This issue affects Apache HTTP Server: from 2.4.0 through 2.4.67. Users are recommended to upgrade to version 2.4.68, which fixes the issue.…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-42536"
   },
   {
    "title": "CVE-2026-44185 — Buffer Over-read vulnerability in Apache HTTP Server via outbound OCSP requests",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Buffer Over-read vulnerability in Apache HTTP Server via outbound OCSP requests to an attacker controlled OCSP server This issue affects Apache HTTP Server: from 2.4.0 through 2.4.67. Users are recommended to upgrade to version 2.4.68, which fixes the issue.…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-44185"
   },
   {
    "title": "CVE-2026-44186 — Loop with Unreachable Exit Condition ('Infinite Loop') vulnerability in the mod_",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Loop with Unreachable Exit Condition ('Infinite Loop') vulnerability in the mod_proxy_ftp module in Apache HTTP Server with an attacker controlled backend FTP server. This issue affects undefined: from 2.4.0 through 2.4.67. Users are recommended to upgrade to…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-44186"
   },
   {
    "title": "CVE-2026-46729 — NULL Pointer Dereference vulnerability in Apache HTTP Servers mod_heartmonitor o",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "NULL Pointer Dereference vulnerability in Apache HTTP Servers mod_heartmonitor over unicast listener. This issue affects Apache HTTP Server: from 2.4.0 through 2.4.68. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-46729"
   },
   {
    "title": "CVE-2026-48005 — Missing authentication checks in mod_auth_digest in Apache Software Foundation A",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Missing authentication checks in mod_auth_digest in Apache Software Foundation Apache HTTP Server before 2.4.69 on all platforms allows an unauthenticated remote client to cause a denial of service (forced re-authentication) via forged Authorization headers w…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-48005"
   },
   {
    "title": "CVE-2026-49975 — Memory Allocation with Excessive Size Value vulnerability in Apache HTTP Server'",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Memory Allocation with Excessive Size Value vulnerability in Apache HTTP Server's mod_http leads to denial of service via malicious HTTP requests. This issue affects Apache HTTP Server: from 2.4.17 through 2.4.67. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-49975"
   },
   {
    "title": "CVE-2026-56153 — Out-of-bounds Write vulnerability in Apache HTTP Server's mod_charset_lite. This",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Out-of-bounds Write vulnerability in Apache HTTP Server's mod_charset_lite. This issue affects Apache HTTP Server: from 2.4.0 through 2.4.68. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-56153"
   },
   {
    "title": "CVE-2026-56449 — Out-of-bounds Write vulnerability in Apache HTTP Server's mod_proxy_html with cr",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Out-of-bounds Write vulnerability in Apache HTTP Server's mod_proxy_html with crafted HTTP response bodies. This issue affects Apache HTTP Server version 2.4.68. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-56449"
   },
   {
    "title": "CVE-2026-59685 — Out-of-bounds Write vulnerability in Apache HTTP Server on Windows while process",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Out-of-bounds Write vulnerability in Apache HTTP Server on Windows while processing paths with 8.3 names that may grow when expanded. This issue affects Apache HTTP Server: from 2.4.0 through 2.4.68. CVSS 7.5.",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-59685"
   },
   {
    "title": "CVE-2026-63045 — Improper validation of FTP PASV reply address in mod_proxy_ftp in Apache Softwar",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Improper validation of FTP PASV reply address in mod_proxy_ftp in Apache Software Foundation Apache HTTP Server through 2.4.68 on all platforms allows, in forward proxy configurations, an untrusted FTP server to cause the proxy to open a data connection to an…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-63045"
   },
   {
    "title": "CVE-2026-63292 — Stack-based buffer overflow in mod_vhost_alias in Apache Software Foundation Apa",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Stack-based buffer overflow in mod_vhost_alias in Apache Software Foundation Apache HTTP Server through 2.4.68 on all platforms allows a remote client to cause a denial of service or potentially execute arbitrary code via an HTTP request with a Host header ex…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-63292"
   },
   {
    "title": "CVE-2026-63686 — A NULL pointer dereference in mod_xml2enc in Apache Software Foundation Apache H",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "A NULL pointer dereference in mod_xml2enc in Apache Software Foundation Apache HTTP Server before 2.4.69 on all platforms allows an untrusted backend server to cause a denial of service via a proxied response with a charset whose conversion partially succeeds…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-63686"
   },
   {
    "title": "CVE-2026-63718 — Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') response smuggling vulnerability in Apache HTTP Server via mod_proxy_uwsgi and a crafted uwsgi response with Transfer-Encoding. This issue affects Apache HTTP Server: from 2.4.30…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-63718"
   },
   {
    "title": "CVE-2026-73636 — Authentication bypass by capture-replay in mod_auth_digest in Apache Software Fo",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Authentication bypass by capture-replay in mod_auth_digest in Apache Software Foundation Apache HTTP Server 2.4.x on all platforms allows a man-in-the-middle (MITM) attacker to replay captured digest authentication credentials via crafted requests that trigge…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-73636"
   },
   {
    "title": "CVE-2026-73637 — Use after free in mod_auth_digest in Apache Software Foundation Apache HTTP Serv",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Use after free in mod_auth_digest in Apache Software Foundation Apache HTTP Server before 2.4.69 on all platforms allows an unauthenticated remote client to cause authentication state corruption via concurrent Digest authentication requests when AuthDigestNcC…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-73637"
   },
   {
    "title": "CVE-2026-93546 — Integer overflow in mod_dav_fs in Apache HTTP Server through 2.4.68 allows an au",
    "sev": "high",
    "conf": "high",
    "src": "cve_matcher",
    "desc": "Integer overflow in mod_dav_fs in Apache HTTP Server through 2.4.68 allows an authenticated WebDAV client with write access to crash worker processes and persistently corrupt a directory's property database via PROPPATCH requests declaring many XML namespaces…",
    "fix": "Upgrade to a patched version; confirm against the vendor advisory.",
    "ev": "Port 8899/tcp — Apache httpd 2.4.49",
    "cat": "cve_match",
    "g": 4,
    "cve": "CVE-2026-93546"
   }
  ]
 }
];
window.GUIDES = [
 {
  "tools": [
   "curl",
   "Browser"
  ],
  "steps": [
   "curl -sI https://<target>/   - if it fails to connect or errors, HTTPS is not available.",
   "Open https://<target>/ in a browser and see whether it loads without a certificate warning.",
   "curl -sI http://<target>/ | grep -i location   - check whether HTTP redirects to HTTPS.",
   "Re-run just this check in isolation to confirm it reproduces:\n       python vulnforge.py <target> -s <module> -o txt"
  ]
 },
 {
  "tools": [
   "curl",
   "Burp Suite (Repeater)"
  ],
  "steps": [
   "curl -sI https://<target>/   — look for the missing header in the response.",
   "Burp: send the request to Repeater, fire it, and check the Response 'Headers' tab for the header named in the finding.",
   "If present but weak (e.g. a short HSTS max-age), check the exact value against OWASP's Secure Headers cheat sheet.",
   "Re-run just this check in isolation to confirm it reproduces:\n       python vulnforge.py <target> -s <module> -o txt"
  ]
 },
 {
  "tools": [
   "Browser DevTools",
   "Burp Suite (Proxy)"
  ],
  "steps": [
   "Browser DevTools → Application/Storage → Cookies: check the Secure, HttpOnly, and SameSite columns for the named cookie.",
   "Burp: Proxy → HTTP history → open the response → 'Cookies' tab shows the same flags without needing the browser UI.",
   "curl -v https://<target>/ 2>&1 | grep -i set-cookie   — flags appear inline (e.g. 'HttpOnly; Secure; SameSite=Lax').",
   "Re-run just this check in isolation to confirm it reproduces:\n       python vulnforge.py <target> -s <module> -o txt"
  ]
 },
 {
  "tools": [
   "curl",
   "Burp Suite (Repeater)"
  ],
  "steps": [
   "curl -sI https://<target>/   — confirm the disclosed header/value is still present.",
   "Burp: Repeater → send the request → check Response headers and body for the exact string quoted in 'evidence' (server banner, stack trace, etc.).",
   "If it's a stack trace, try to trigger the same error path manually (e.g. malformed input) to confirm it's reproducible, not a one-off.",
   "Re-run just this check in isolation to confirm it reproduces:\n       python vulnforge.py <target> -s <module> -o txt"
  ]
 },
 {
  "tools": [
   "Manual banner grab",
   "searchsploit / Exploit-DB",
   "Vendor advisory"
  ],
  "steps": [
   "Confirm the exact version first — banner grab manually: nc <target> <port>   or   curl -sI https://<target>:<port>/ depending on the service.",
   "searchsploit <product> <version>   — see if a known PoC exists for the matched CVE. If the finding names a Metasploit module, 'msfconsole -q -x \"info <module>\"' shows its target versions without running it.",
   "Check the vendor's own advisory for the CVE ID to confirm the affected version range matches exactly (VulnForge's local CVE dataset is a seed set, not authoritative).",
   "Only attempt the actual exploit PoC if you have explicit authorization to do so on this specific target.",
   "Re-run just this check in isolation to confirm it reproduces:\n       python vulnforge.py <target> -s <module> -o txt"
  ]
 }
];
