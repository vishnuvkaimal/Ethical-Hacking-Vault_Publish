
>Note: This summary is compiled and edited by AI, using the real Book PDF. In case of any changes or additions, will correct as per notice
# Executive summary (what the book is and how to use this summary)

- **Scope of the book:** Practical field guide to common web vulnerabilities, organized by vulnerability class. Each chapter introduces a class, explains mechanics, shows several _real bounty reports/case studies_ and ends with actionable “takeaways” (how to test, why it was possible, and how to fix). The book is practical for both beginners and intermediate bug hunters.
    
    Real-World Bug Hunting
    
- **Structure of this summary:** chapter → short definition → how it works → concrete examples from the book (with report identifiers / dates / bounties where present) → practical PoC / exploitation patterns you can try during testing → detection & remediation notes → author’s takeaways.
    

---

# Chapter 1 — Bug Bounty Basics

**What it covers:** fundamental web concepts (client/server model, DNS, TCP, HTTP requests/responses, headers, HTTP methods, statelessness), and bug bounty program basics: what a vulnerability is, what a bounty is, how to approach responsible disclosure. The author also outlines common reconnaissance techniques and tools referenced later.

Real-World Bug Hunting

**Key testing tips / takeaways**

- Monitor HTTP traffic with a proxy (Burp/ZAP) and learn how browsers render responses — many bugs become visible in the parameters/headers.
    
- Understand the meaning of standard HTTP codes (301/302/303/307/308) because many redirect-related vulnerabilities rely on how Location headers are handled.
    
    Real-World Bug Hunting
    

---

# Chapter 2 — Open Redirect

**Definition:** a site accepts attacker-controlled input as a redirect target and sends victims to attacker sites, abusing the victim site’s trust. Often low impact but useful for phishing/OAuth token exfiltration.

Real-World Bug Hunting

**How it works (mechanics):**

- The server returns a Location header (or uses `<meta http-equiv="refresh">` or `window.location`) whose value is attacker controlled.
    
- Common parameter names: `redirect`, `redirect_to`, `next`, `url`, `u`, `r`, `checkout_url`, `domain_name` etc.
    
- Special URL characters (e.g., `.` or `@`) or subdomain concatenation tricks (`mystore.myshopify.com.<attacker>.com`) can be abused when the site blindly concatenates values.
    
    Real-World Bug Hunting
    

**Concrete book examples**

- **Shopify Theme Install Open Redirect** — `domain_name` parameter allowed off-site redirects; bounty $500. (HackerOne report referenced.)
    
    Real-World Bug Hunting
    
- **Shopify Login Open Redirect** — `checkout_url` parameter combined with store URL; attackers used characters to change meaning so DNS resolves to attacker domain; bounty $500.
    
    Real-World Bug Hunting
    
- **HackerOne interstitial redirect (Zendesk integration)** — missing interstitial allowed JavaScript redirect to run and move users to an attacker site; shows chained-service attack (HackerOne → Zendesk).
    
    Real-World Bug Hunting
    

**How to test (PoC-style):**

1. Look for redirect-style parameters in URLs (`?next=`, `?checkout_url=`, `?return_to=`).
    
2. Replace parameter with attacker URL — check behavior (Location header, meta refresh or JS redirect).
    
3. Try URL-trick characters (prepend `.` or `@`, add subdomain fragments) to see whether the final resolved host becomes attacker-controlled.
    
4. If the app uses third-party services (Zendesk, SSO), inspect interstitial pages for missing checks or injected params.
    
    Real-World Bug Hunting
    

**Detection / Fixes:**

- Fix: Whitelist allowed redirect hosts; require relative paths only; or canonicalize+validate hostname before redirect.
    
- Add interstitials when linking to third-party content; require user confirmation for cross-site redirects.
    
    Real-World Bug Hunting
    

**Takeaway:** Open redirects are often low severity, but excellent for learning redirect mechanics and for chaining with other bugs (phishing, OAuth token theft).

Real-World Bug Hunting

---

# Chapter 3 — HTTP Parameter Pollution (HPP)

**Definition:** attackers send duplicate parameters or specially encoded values to change how parameters are interpreted, causing the server or downstream service (or client) to use attacker-controlled values. HPP can be **server-side** or **client-side** depending on where parameter parsing differs.

Real-World Bug Hunting

**How it works:**

- Many languages/frameworks parse duplicate keys differently (first wins, last wins, arrays, etc.). If backend signature or validation uses one occurrence and the action uses another, you can bypass checks.
    
- Client-side HPP: URIs rendered into client JS/widgets or social share links can be tampered with so the generated third-party link points elsewhere.
    

**Book case studies**

- **HackerOne social sharing buttons** — appending `&u=` or additional `text=` parameters caused shared posts to link to attacker URLs. Bounty: $500.
    
    Real-World Bug Hunting
    
- **Twitter unsubscribe HPP** — attacker added a second `uid` parameter so the signature validated with one `uid` but action executed under the second `uid`, enabling unsubscribing other users; bounty $700. This is a classic “signature bound to first parameter, action uses last parameter” mismatch.
    
    Real-World Bug Hunting
    
- **Twitter Web Intents** — parameter tampering to change the content or link of tweets created via web intents.
    
    Real-World Bug Hunting
    

**PoC / exploitation patterns:**

1. Identify parameters that look like user IDs, signatures, or state tokens (`uid`, `id`, `sig`, `token`).
    
2. Try appending a second parameter with the same name and a different value: `...?uid=ATTACKER&uid=VICTIM&sig=...` and observe which value the server uses for verification vs for action.
    
3. Encode `&` as `%26` (or similarly encode) to smuggle parameters into values that later decode into additional parameters client-side.
    
4. For social widgets, append `&u=` or `&text=` and inspect generated third-party links.
    
    Real-World Bug Hunting
    

**Detection / Fixes:**

- Normalize parameter handling (reject duplicates, canonicalize to a single format).
    
- Bind signatures to the _exact canonicalized representation_ of inputs and use both validation and action on the same canonical values.
    
- For third-party link generation, escape and validate user-built components.
    
    Real-World Bug Hunting
    

**Takeaway:** Persistence pays — HPP often requires trying duplicate parameters, encodings, and understanding how different layers parse parameters.

Real-World Bug Hunting

---

# Chapter 4 — Cross-Site Request Forgery (CSRF)

**Definition:** an attacker tricks an authenticated user’s browser into making an unwanted request to a trusted site (exploiting the browser’s automatic credential sending like cookies). CSRF can change state (POST) or perform actions via GET if poorly designed.

Real-World Bug Hunting

**Mechanics & defenses explained:**

- CSRF with GET: unsafe apps expose state-changing GET endpoints — attacker can embed images/links to trigger them.
    
- CSRF with POST: attacker can auto-submit forms or use XHR from attacker site in some conditions (but SOP limits cross-origin XHR unless CORS allows it).
    
- Defenses: CSRF tokens (synchronizer tokens), SameSite cookies, require double-submit cookies, validate Origin/Referer headers, ensure state changes are not via GET.
    
    Real-World Bug Hunting
    

**Examples in the book**

- **Shopify Twitter disconnect** — CSRF used to disconnect social account association; demonstrates OAuth / third-party integrations being affected.
    
    Real-World Bug Hunting
    
- **Instacart zone changes / account modification** — CSRF leading to state change examples.
    
    Real-World Bug Hunting
    
- **Badoo full account takeover** — a real high-impact example combining CSRF and other flows causing full takeover.
    
    Real-World Bug Hunting
    

**Testing approach:**

1. Look for state-changing endpoints accessible from an authenticated browser.
    
2. Attempt to trigger via `<img src>`, `<form action>` on attacker page, and see if request succeeds for signed-in user.
    
3. Check for CSRF token presence, verify token uniqueness per session and binding to user session.
    
4. Test Referer/Origin header checks — some sites only require Referer origin verification.
    
    Real-World Bug Hunting
    

**Mitigations:** Use per-request cryptographically secure CSRF tokens, enforce SameSite/Lax cookies for session cookies, and avoid state changes via GET.

Real-World Bug Hunting

---

# Chapter 5 — HTML Injection and Content Spoofing

**Definition:** injection of HTML content into pages where untrusted input is rendered as HTML (not escaped). This differs from XSS in that HTML injection may not allow script execution (depending on context) but can spoof content, create fake UI, or inject tags like `<meta>`/`<img>` to phish data.

Real-World Bug Hunting

**Examples from the book**

- **Coinbase comment injection via encoding** — attacker used character encoding to inject HTML-like content into comments producing spoofed UI.
    
    Real-World Bug Hunting
    
- **HackerOne unintended HTML inclusion** — certain pages included HTML fragments unintentionally, enabling content spoofing; followed by a fix bypass example illustrating real-world nuance.
    
    Real-World Bug Hunting
    
- **Within Security content spoof** — an example of content rendered from untrusted sources causing misleading displays.
    
    Real-World Bug Hunting
    

**Testing patterns:**

- Try various encodings (UTF-7, alternate encoding, HTML entities) to see if content is interpreted as HTML.
    
- Look for contexts where user input is injected into page markup (e.g., comments, blog posts, profile fields) and test rendering in different browsers.
    
- If scripts are blocked but HTML accepted, attempt UI-based phishing (fake forms/links) or content placement to mislead admins/users.
    
    Real-World Bug Hunting
    

**Fixes:** Properly escape or sanitize HTML input, use content security policy (CSP) to limit script execution, and treat user-provided markup as data, not executable markup.

Real-World Bug Hunting

---

# Chapter 6 — Carriage Return / Line Feed (CRLF) Injection & HTTP Response Splitting

**Definition:** CRLF injection is about injection of newline characters into headers or HTTP responses leading to response splitting, header injection, or cache poisoning. Closely related to HTTP request smuggling/splitting.

Real-World Bug Hunting

**Book examples**

- **v.shopify.com response splitting** — response splitting allowing header control; book walks through how to inject CRLF into user input that later becomes header content.
    
    Real-World Bug Hunting
    
- **Twitter HTTP response splitting** — another example showing cross-browser and server differences.
    
    Real-World Bug Hunting
    

**Testing patterns:**

1. Try inserting `%0d%0a` or `\r\n` into parameters used in header values.
    
2. Inspect server responses for extra headers, cookie manipulation, or extra body segments that indicate splitting.
    
3. Check caching layers and proxies (CDNs) for poisoning or cache key manipulation.
    
    Real-World Bug Hunting
    

**Fixes:** Sanitize and validate header values; disallow newline characters in values that will be used in headers. Use framework helpers to set headers (instead of string concatenation).

Real-World Bug Hunting

---

# Chapter 7 — Cross-Site Scripting (XSS)

**Definition:** injection of attacker-supplied scripts (or scriptable content) into pages viewed by other users. The book covers **reflected**, **stored**, and **DOM-based** XSS, plus subtle contexts (attributes, CSS, JS contexts).

Real-World Bug Hunting

**How it works:** User input is placed into HTML without proper escaping; when victim visits the page the input executes as script in their origin, allowing cookie theft, CSRF bypass, session hijacking, DOM manipulation, redirecting, and more.

**Notable examples from the book**

- **Shopify Wholesale XSS** and **Shopify currency formatting XSS** — shows how formatters and templating can create XSS contexts.
    
    Real-World Bug Hunting
    
- **Yahoo! Mail stored XSS** — a high-impact stored XSS example affecting mail content rendering.
    
    Real-World Bug Hunting
    
- **Google Image Search / Tag Manager stored XSS** — demonstrates how third-party components or templating can expose XSS vectors.
    
    Real-World Bug Hunting
    

**Testing patterns:**

- Test common payloads in different contexts (`<script>`, `"><img src=x onerror=...>`, event handlers, `javascript:` URIs).
    
- Check unusual encodings and attributes (SVG, `data:` URIs, CSS contexts) and test DOM sinks (`innerHTML`, `eval`, `document.write`, `setAttribute('on*')`).
    
- Use Burp payload lists, DOM monitors, and browser consoles to test whether injected content executes.
    
    Real-World Bug Hunting
    

**Fixes / mitigations:** output-encode per context (HTML, attribute, JS, CSS), adopt CSP, use secure templating libraries and framework helpers, sanitize user files and third-party content.

Real-World Bug Hunting

---

# Chapter 8 — Template Injection

**Definition:** injection of template syntax into server or client side template engines (e.g., Jinja2, AngularJS, Smarty). If the template engine evaluates expressions, attackers can run arbitrary code (server-side template injection = RCE risk), or at least manipulate rendered output (client-side template injections).

Real-World Bug Hunting

**Concrete examples**

- **Uber AngularJS template injection** — client-side Angular expression injection that lets attacker run expressions in page context.
    
    Real-World Bug Hunting
    
- **Uber Flask/Jinja2 server-side template injection** — demonstrates server-side template languages allowing code execution when user input is passed unescaped into templates.
    
    Real-World Bug Hunting
    
- **Rails dynamic render**, **Unikrn Smarty injection** — more examples showing multiple frameworks and how dangerous unsanitized template inputs become.
    
    Real-World Bug Hunting
    

**PoC steps & testing patterns:**

1. Identify fields that might be inserted into templates (e.g., `{{ user.name }}`, `{{ message }}`).
    
2. Try test payloads appropriate to engine: Angular `{{constructor.constructor('alert(1)')()}}`-style probes for client templates; for Jinja attempt `{{ self.__init__.__globals__ }}` enumeration etc. (the book explains library-specific payloads).
    
3. For server engines, aim to get the engine to evaluate function calls — this often leads to function invocation or file reads.
    
    Real-World Bug Hunting
    

**Fixes:** avoid evaluating templates with user input, use strict escaping, or sandboxed template engines. Update or remove template features that evaluate expressions in untrusted input.

Real-World Bug Hunting

---

# Chapter 9 — SQL Injection (SQLi)

**Definition:** injection of SQL into database queries via unsanitized input — allows data exfiltration, modification, or DB takeover. The book covers blind SQLi, error-based, and UNION-based techniques and countermeasures.

Real-World Bug Hunting

**Examples**

- **Yahoo! Sports blind SQLi** — demonstrates time-based and boolean blind techniques.
    
    Real-World Bug Hunting
    
- **Uber Blind SQLi** — how large infrastructure apps can leak data via blind techniques.
    
    Real-World Bug Hunting
    
- **Drupal SQLi** — a real vulnerability class example and remediation discussion.
    
    Real-World Bug Hunting
    

**Testing / exploitation patterns:**

- Confirm injectable parameter using `' OR 1=1 --` style probes (careful on production).
    
- For blind SQLi use time delays (`SLEEP(5)`), boolean tests (`AND ASCII(SUBSTRING(...))>x`) to exfiltrate data one bit/character at a time.
    
- Use UNION SELECT to retrieve data if error disclosure is available.
    
- Use automated tools (sqlmap) as an aid but manual exploitation often required for complex cases.
    
    Real-World Bug Hunting
    

**Remediation:** parameterized queries/prepared statements, ORM safe APIs, least privilege DB accounts, input validation and output encoding for DB output.

Real-World Bug Hunting

---

# Chapter 10 — Server-Side Request Forgery (SSRF)

**Definition:** an attacker gets the server to make HTTP(S)/TCP requests to arbitrary internal/external hosts. SSRF is powerful because servers can access private metadata endpoints, internal services, and other resources not reachable from the attacker.

Real-World Bug Hunting

**Key mechanics in the book:**

- Demonstrates GET vs POST invocation (how to make server issue different request methods).
    
- **Blind SSRF**: trigger a request where you only know whether it happened (e.g., by observing network callbacks).
    
- SSRF to internal AWS metadata (`169.254.169.254`) to steal credentials is covered (ESEA SSRF example).
    
    Real-World Bug Hunting
    

**Book case studies**

- **ESEA SSRF** — querying AWS metadata to obtain IAM credentials.
    
    Real-World Bug Hunting
    
- **Google internal DNS SSRF** — illustrating the power of internal DNS/internal resource access.
    
    Real-World Bug Hunting
    
- **Internal port scanning using webhooks** — clever technique to enumerate internal ports/services via SSRF callbacks.
    
    Real-World Bug Hunting
    

**Testing approach:**

1. Find endpoints that accept URLs (webhooks, remote image fetchers, importers).
    
2. Use a collaborator/callback service (or your own endpoint) to capture server requests.
    
3. Try internal IPs (`127.0.0.1`, `169.254.169.254`), IPv6 shorthand, DNS rebinding or poisoned hostnames to reach internal services.
    
4. Use protocols besides HTTP (ftp://, file://) where permitted to access local files or other resources.
    
    Real-World Bug Hunting
    

**Mitigations:** allowlist outgoing hosts, metadata service protections (IAM role policies, IMDSv2 in AWS), input validation for URLs, block or sanitize IP ranges pointing to internal addresses.

Real-World Bug Hunting

---

# Chapter 11 — XML External Entity (XXE)

**Definition:** abusing XML parsers that resolve external entities (DTD) to read local files, SSRF to internal services, or cause DoS. XXE relies on parsers that process external DTDs by default.

Real-World Bug Hunting

**Examples**

- **Read access to Google** — the book shows how an XML upload/parse flow was abused to read unexpected resources.
    
    Real-World Bug Hunting
    
- **Facebook XXE via Microsoft Word** — demonstrates how documents containing external entity references can be used to trigger XXE.
    
    Real-World Bug Hunting
    
- **Wikiloc XXE** — another real report showing data or file access via XXE.
    
    Real-World Bug Hunting
    

**Testing patterns:**

1. Look for XML upload endpoints (file imports, document parsing, SOAP endpoints).
    
2. Submit XML with `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>` and reference `&xxe;` to try to get parsed content returned.
    
3. For blind contexts, have the parser perform an external entity reference to a remote controlled host to detect callbacks.
    
    Real-World Bug Hunting
    

**Fixes:** disable external entity resolution in XML parsers, use safe parsing libraries, or use JSON/AJAX alternatives that don't evaluate external entities.

Real-World Bug Hunting

---

# Chapter 12 — Remote Code Execution (RCE)

**Definition:** attacker input ultimately leads to execution of shell commands or language-level functions on a server. RCE is a high-impact vulnerability. The chapter covers both function invocation and shell invocation vectors.

Real-World Bug Hunting

**Examples**

- **Polyvore ImageMagick exploit** — image processing libraries (ImageMagick) parsing attacker files, enabling command execution. The book explains how image processors can invoke system commands.
    
    Real-World Bug Hunting
    
- **Algolia RCE on facebooksearch.algolia.com** — demonstrates chained third-party service misconfigurations.
    
    Real-World Bug Hunting
    
- **RCE through SSH / misconfigured keys / infrastructure mistakes** — how exposed credentials or weak config can lead to remote command execution.
    
    Real-World Bug Hunting
    

**Testing / exploitation approach:**

1. Identify input that is later passed to system tools (image processors, `exec()` wrappers, template engines that evaluate).
    
2. Supply crafted payloads designed to break out of safe contexts (ImageMagick mvg or URL payloads), or provide input that causes parameter injection.
    
3. After RCE, escalate by obtaining persistent shells, pivoting to internal network, or retrieving secrets. The book details escalation strategies.
    
    Real-World Bug Hunting
    

**Mitigation:** avoid calling shell commands with untrusted input; run processors with limited permissions and sandboxes; validate and sanitize file types and content; apply least privilege to service accounts.

Real-World Bug Hunting

---

# Chapter 13 — Memory Vulnerabilities

**Definition:** classic program memory issues like buffer overflows, out-of-bounds reads/writes, integer overflows, and Heartbleed-style leaks. While less common in pure web app code (often in C/C++ libraries), many web services still rely on native modules that can be exploited.

Real-World Bug Hunting

**Examples**

- **Buffer overflows, Heartbleed reference** — general memory risk examples.
    
    Real-World Bug Hunting
    
- **PHP ftp_genlist() integer overflow** — real vuln in PHP function enabling memory corruption.
    
    Real-World Bug Hunting
    
- **Libcurl read out of bounds** — vulnerabilities in widely used native libraries.
    
    Real-World Bug Hunting
    

**Testing / notes:** memory bugs are usually found by fuzzing, code auditing, or monitoring crash reports. Many of these are high-impact but require specialized skills to exploit.

**Mitigation:** update native libs, use safe languages or sandboxing, apply compiler mitigations (ASLR, stack canaries), and run memory-safe coding practices.

Real-World Bug Hunting

---

# Chapter 14 — Subdomain Takeover

**Definition:** when DNS records point to an external service that is no longer provisioned (e.g., CNAME to unclaimed S3/Heroku/Zendesk), an attacker can claim that external resource and host content under the victim subdomain.

Real-World Bug Hunting

**Book examples**

- **Heroku / Ubiquiti example** — how a service stopped existing but DNS still pointed to provider, enabling takeover; includes Heroku and other platforms takeover walk-throughs.
    
    Real-World Bug Hunting
    
- **scan.me pointing to Zendesk** — a real example where the subdomain resolved to a vendor resource that the attacker could claim, enabling content serving under the victim domain.
    
    Real-World Bug Hunting
    

**Testing & exploitation pattern:**

1. Crawl subdomains (via recon), check for CNAMEs pointing to cloud providers (S3, Heroku, Shopify, Zendesk).
    
2. Verify whether the referenced resource exists/account is claimed; if not, attempt to claim it and serve content.
    
3. Use the taken subdomain to host phishing pages or JS to exfiltrate cookies (if cookie scope allows).
    
    Real-World Bug Hunting
    

**Fix:** remove stale DNS records; use provider checks to detect unlinked domains; set HSTS and secure cookie host restrictions where appropriate.

Real-World Bug Hunting

---

# Chapter 15 — Race Conditions

**Definition:** concurrency bugs where two operations overlap in time and produce inconsistent or exploitable states (e.g., two payments causing double spend, file rename and read racing to create a file disclosure).

Real-World Bug Hunting

**Examples**

- **HackerOne payments race condition** — example where concurrent operations allowed inconsistent monetary state changes (book details show how race was invoked during payments).
    
    Real-World Bug Hunting
    
- **Invite multiple times / create resource race** — the book shows tactics to induce races (parallel requests, thread pools) and how to prove them.
    
    Real-World Bug Hunting
    

**Exploitation & testing:**

1. Identify endpoints that perform atomic operations (create, transfer, delete).
    
2. Attempt to issue many concurrent requests (multithreaded curl, Burp Intruder) and see if invariants are violated.
    
3. Use small timing adjustments and parallelism to increase success probability; record logs to prove the condition.
    
    Real-World Bug Hunting
    

**Mitigation:** use DB-level transactions, row-level locking, idempotency tokens, and server-side atomic operations.

---

# Chapter 16 — Insecure Direct Object References (IDOR / ID-based access control)

**Definition:** authorization errors where object identifiers (IDs) are used directly in requests and access control checks rely on the client or are missing, allowing unauthorized access to objects by changing IDs.

Real-World Bug Hunting

**Examples**

- **ACME customer info disclosure** — IDOR allowing access to other customers’ data.
    
    Real-World Bug Hunting
    
- **Binary.com privilege escalation** and **Moneybird app creation** — show other IDOR patterns and how chained flows can lead to privilege escalation.
    
    Real-World Bug Hunting
    
- **Twitter Mopub API token theft** — describes token theft via incorrect object access checks.
    
    Real-World Bug Hunting
    

**Testing approach:**

1. Identify predictable integer or string IDs in requests (`/user/1234`, `?id=`).
    
2. Attempt to change to other values (increment or enumerate) and observe whether the server enforces authorization.
    
3. Check whether server validates the authenticated user owns the referenced object or whether checks rely on client/state only.
    
    Real-World Bug Hunting
    

**Fix:** server-side authorization for all object accesses, use non-guessable IDs (GUIDs) plus authorization checks, and enforce least privilege.

---

# Chapter 17 — OAuth Vulnerabilities

**Definition / focus:** OAuth flows and token handling mistakes can cause token leakage, token misuse, or redirection misuse (open redirects + OAuth). Book ties earlier redirect and cross-site vulnerabilities to OAuth token theft.

Real-World Bug Hunting

**Key learning points:**

- Always validate redirect URIs in OAuth exchanges.
    
- Protect OAuth tokens from being leaked via open redirects, referers, or weak callback handling.
    
- Use best-practice flows (PKCE for public clients) and minimize token exposure on client.
    
    Real-World Bug Hunting
    

---

# Chapter 18 — Application Logic and Configuration Vulnerabilities

**Definition:** vulnerabilities that are not formulaic (not classic injection issues) but arise from flawed logic, misconfigurations, or assumptions (price calculation errors, accounting logic, misconfigured storage ACLs). These are often high-value if found because they affect business logic.

Real-World Bug Hunting

**Examples / book highlights**

- The author emphasizes recon to find logic edges (features contacting other services, complex state transitions).
    
- He outlines various real reports where logic flaws allowed privilege elevation or data exposure.
    
    Real-World Bug Hunting
    

**Testing patterns:** think like a user and the business — model state transitions, attempt unusual sequences (e.g., create → delete → re-create; change pricing then purchase), look for misapplied permissions.

Real-World Bug Hunting

---

# Chapter 19 — Finding Your Own Bug Bounties (recon, tooling, methodology)

**Content:** practical recon techniques (subdomain enumeration, Google dorking, Wayback caching), tooling recommendations (Burp, ZAP, Nmap, gobuster, gowitness), how to search HackerOne / Bugcrowd disclosures for ideas, and how to prioritize targets. The book gives an efficiency framework for triage and testing.

Real-World Bug Hunting

**Key tips:**

- Read disclosed reports for patterns and re-test similar endpoints on other targets.
    
- Keep an eye on third-party services a site uses — they widen your attack surface (Zendesk, S3, Algolia, etc.).
    
    Real-World Bug Hunting
    

---

# Chapter 20 — Vulnerability Reports (how to write them)

**Content:** how to write high-quality reports: include clear reproduction steps, PoCs, impact justification, proof of exploitability, and remediation suggestions. The author shows how to build relationships with triage teams and improve acceptance.

Real-World Bug Hunting

**Practical checklist (book based):**

- Short executive summary + detailed steps with request/response samples.
    
- Proof of impact (screenshots, logs, scripts).
    
- Suggested remediation and code hints.
    
- If vendor disagrees, politely expand PoC or show chained exploit demonstrating impact.
    
    Real-World Bug Hunting
    

---

# Appendices — Tools & Resources

**Appendix A (Tools):** recommended tools (Burp Suite, ZAP, Nmap, gobuster, docker tools, scanner helpers).

Real-World Bug Hunting

  
**Appendix B (Resources):** HackerOne Hacktivity, OWASP, Web Application Hacker’s Handbook, blogs, and video resources (Bugcrowd LevelUp, LiveOverflow). The book strongly encourages reading disclosed reports and following the community.

Real-World Bug Hunting

---

# Quick index of the book’s vulnerability list (A→Z, for fast reference)

(These are the chapters / exploit classes the book covers — use this as your checklist when hunting.)

- Open Redirect.
    
    Real-World Bug Hunting
    
- HTTP Parameter Pollution (HPP).
    
    Real-World Bug Hunting
    
- Cross-Site Request Forgery (CSRF).
    
    Real-World Bug Hunting
    
- HTML Injection & Content Spoofing.
    
    Real-World Bug Hunting
    
- CRLF / Response Splitting / HTTP Smuggling.
    
    Real-World Bug Hunting
    
- Cross-Site Scripting (XSS).
    
    Real-World Bug Hunting
    
- Template Injection (server & client).
    
    Real-World Bug Hunting
    
- SQL Injection (SQLi).
    
    Real-World Bug Hunting
    
- Server-Side Request Forgery (SSRF).
    
    Real-World Bug Hunting
    
- XML External Entity (XXE).
    
    Real-World Bug Hunting
    
- Remote Code Execution (RCE).
    
    Real-World Bug Hunting
    
- Memory Vulnerabilities (buffer overflows, OOB).
    
    Real-World Bug Hunting
    
- Subdomain Takeover.
    
    Real-World Bug Hunting
    
- Race Conditions.
    
    Real-World Bug Hunting
    
- Insecure Direct Object References (IDOR).
    
    Real-World Bug Hunting
    
- OAuth vulnerabilities.
    
    Real-World Bug Hunting
    
- Application logic/configuration bugs.
    
    Real-World Bug Hunting