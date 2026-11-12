# PHP security review (a language where the default is unsafe)

## What it is

PHP's historical defaults are the root of most of its findings. `mysql_query`
interpolated; `echo $_GET[...]` printed raw; `unserialize()` on request data;
`include` with a variable path; `==` comparing loosely. None of these is a subtle
bug -- each is a documented API that does exactly what it was asked.

This skill covers what to review, and -- equally important -- **the honest limits
of what TriageKit detects**. PHP has no dedicated taint analyzer and no dedicated
rule pack in this tool. Two regex rules cover PHP in the general scanner
(`src/triagekit/core/analyzers/repo_scan.py`). That is a small fraction of the
real PHP attack surface, so a clean PHP result means very little. Say so.

The trust boundary crossed is the same one as everywhere else: attacker bytes
reaching a grammar. PHP just provides more one-line routes to it.

## What TriageKit actually detects in PHP

Two rules in the `INJECTION` pattern list, both regex, both requiring the source
and the sink on the same line:

| Rule id | Severity | CWE | Pattern |
| --- | --- | --- | --- |
| `php-sqli` | critical | CWE-89 | `$_GET/POST/REQUEST/COOKIE[...]` on a line with `mysql_query`, `mysqli_query`, or `->query(` |
| `php-xss` | high | CWE-79 | `$_GET/POST/REQUEST` followed by `echo`/`print` |

Plus two general rules that fire on PHP files: `unsafe-deserialization`
(`unserialize(`, CWE-502, critical), `command-injection`
(`system`/`popen`/`exec`/`passthru`, CWE-78, high), `open-redirect`
(`header('Location', request...`, CWE-601, medium), `path-traversal`
(`../../` or `open(...+`, CWE-22, high), `hardcoded-secret`, and
`plaintext-password-compare` (which includes `strcmp($..., password)`).

**Known limitations, stated plainly:**

- **The SQLi and XSS rules require source and sink on one line.** A PHP codebase
  that assigns `$id = $_GET['id'];` at the top of a file and interpolates it into
  a query 40 lines later will NOT match. This is the dominant PHP shape. Absence
  of a `php-sqli` finding is not evidence of absence.
- **No cross-file flow.** `include`/`require` composition is not traced.
- **No rule pack** for PHP the way Rust (`rust_rules.py`), Java (`java_rules.py`),
  C#, Swift, and C++ have. The `RECS` map contains `php-sqli` and `php-xss`
  remediation text, which is coverage of the *remediation* strings, not of new
  detection.
- **Modern PHP is invisible here.** PDO with prepared statements is safe and, being
  free of `mysql_query`, is correctly not matched -- but so is a
  `PDO::query("... '$_GET[id]' ...")` call, which is unsafe.

So for PHP, this skill is the primary detection mechanism and the rules are the
safety net. Read the code.

## Detection (what to look for, by hand)

### Interpolation into SQL

    // matched only because it is on one line
    mysql_query("SELECT * FROM users WHERE id = " . $_GET['id']);

    // NOT matched, and unsafe -- the real shape in most PHP codebases
    $id = $_GET['id'];
    $q  = "SELECT * FROM users WHERE id = $id";
    $r  = mysqli_query($conn, $q);

    // safe
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$_GET['id']]);

### Output without escaping

    echo $_GET['name'];                    // matched: php-xss
    $name = $_POST['name'];
    print "<h1>$name</h1>";                // NOT matched, unsafe
    print "<h1>" . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</h1>";   // safe

### Type juggling -- the PHP-specific class

    if ($_POST['password'] == $known_hash)          // loose compare
    if (strcmp($_POST['token'], $real) == 0)        // matched: plaintext-password-compare
    if ($_POST['a'] == md5($_POST['b']))            // magic-hash collision, "0e..." prefix

Loose `==` compares `"0e123" == "0e456"` as true (both parse as 0 in scientific
notation). The fix is `===` and, for secrets, `hash_equals()` which is
constant-time. This class has no analog in most other languages and is missed by
every regex in this tool.

### Inclusion and file operations

    include($_GET['page'] . '.php');               // LFI/RCE
    include("/pages/" . basename($_GET['page']) . ".php");   // narrowed, still allowlist it
    file_get_contents($_GET['url']);               // SSRF
    unlink("uploads/" . $_POST['name']);            // arbitrary delete

### Deserialization and object injection

    $obj = unserialize($_COOKIE['prefs']);         // matched: unsafe-deserialization
    $obj = unserialize(base64_decode($_GET['d']));  // NOT matched, unsafe

### Command execution

    system("ping " . $_GET['host']);                 // matched: command-injection
    passthru("convert " . escapeshellarg($_FILES['f']['name']));   // the fix shape
    exec("git log " . $branch);                      // NOT matched unless `exec(` is on the line with a source

### Configuration that ships

    display_errors = On            // stack traces to the attacker in production
    allow_url_include = On         // enables remote file inclusion -> RCE
    register_globals = On          // pre-5.4, turns every request var into a variable
    error_reporting(E_ALL)         // fine; display_errors is the dangerous one

## How it works (attack mechanics)

Two mechanics that are distinctly PHP:

- **Direct interpolation.** PHP string interpolation (`"$var"`, `"{$a['b']}"`,
  `"$obj->m"`) expands inside double-quoted strings, so the vulnerable SQL and the
  variable are grammatically one token. `' . $_GET['id'] . '` concatenation is
  the same. The payload shape is `' OR '1'='1`, identical to every other SQL
  injection.
- **Type juggling.** PHP's `==` performs type coercion before comparison, so
  `"0e12345" == "0e56789"` is true and `"abc" == 0` is true on older versions.
  Where a comparison is the security decision -- a password check, a token
  comparison, a signature check -- the coercion is the vulnerability. The fix is
  `===` or `hash_equals()`, and this is invisible to pattern matching.

## Is it actually exploitable?

1. **Is `display_errors` reachable, or is this a stack trace in the response
   body?** Error-based SQLi and schema disclosure both depend on it.
2. **Is the loose comparison the security decision?** `==` on a non-secret is a
   style issue. `==` on a password, token, or signature is a finding.
3. **Does `include` take any part of the request?** Any interpolation into a
   file path that is included is file inclusion, and with
   `allow_url_include` it is remote code execution.
4. **Is the framework doing the escaping?** Laravel's Blade, Symfony's Twig, and
   WordPress's `esc_attr`/`esc_html` all escape by default. A raw `echo` inside a
   Blade template that then goes through a `{!! !!}` raw tag is the finding; a
   `{{ }}` tag is safe.
5. **Is the query through PDO with prepared statements?** Then there is no SQLi
   regardless of what the regex matched.

## False positives (do NOT report)

- **`htmlspecialchars` / `esc_html` / `esc_attr` / `Blade {{ }}`.** The escape is
  present.
- **`PDO::prepare()` with placeholders.** Parameterized; the regex did not match
  and it is not a finding.
- **`escapeshellarg()` / `escapeshellcmd()` around an argument.** Correct.
- **`hash_equals()` for the comparison.** The correct PHP primitive.
- **`==` comparing two integers or two booleans** where no request data reaches
  either side.
- **`unserialize` on a value the application itself wrote and signed** (an HMAC
  verified before the call, with the key in the environment).
- **`include` of a literal path or a constant.** Only interpolated paths are
  findings.
- **A `mysql_query` inside a comment or a docblock.**
- **A test fixture containing a payload string.**
- **`display_errors = Off`** -- that is the fix, already applied.

Given the two matched rules require single-line source-plus-sink, the most likely
PHP false positive here is the opposite problem: a file with obvious
vulnerabilities that produces zero findings. Report that as a coverage
limitation, not as a clean result.

## Severity

Unauthenticated SQL injection through a directly interpolated query:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

VI:H because a stacked statement can modify as well as read, where the driver
permits it -- if `mysqli_multi_query` is not in use, drop VI to N and say why.
File inclusion under `allow_url_include` is
`AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` with `AT:P` because the
`php.ini` setting is a precondition, not a certainty. A loose-compare password
check is `AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` -- `AC:H`
because finding a magic-hash collision is a search, not a single request. Never
hand-compute the number.

## Remediation

```php
// SQL -- the dominant fix
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);            // never interpolate

// Output
echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');

// Secrets -- constant time, strict
if (hash_equals($known_token, $_POST['token'])) { /* ... */ }   // not ==, not strcmp

// Command -- one argument, no shell grammar
passthru("convert " . escapeshellarg($path));

// Inclusion -- an allowlist, not a filename
$page = in_array($_GET['p'], ALLOWED_PAGES, true) ? $_GET['p'] : "home";
include __DIR__ . "/pages/$page.php";

// Deserialization
$data = json_decode($_COOKIE['prefs'], true);   // not unserialize
```

And in `php.ini` / the deployment config: `display_errors = Off`,
`allow_url_include = Off`, `expose_php = Off`. Those are deployment changes --
name the file, not just the directive.

## Verify the fix

- `grep -rn '$_GET\|$_POST\|$_REQUEST\|$_COOKIE' --include='*.php' . | grep -v
  'prepare\|execute\|htmlspecialchars\|esc_html\|esc_attr\|escapeshellarg\|hash_equals\|intval\|filter_var\|in_array'`
  -- each remaining hit is reviewed by hand. With two regex rules, the grep is
  the real coverage.
- `grep -rn 'mysql_query\|mysqli_query' --include='*.php' .` returns nothing.
- `grep -rn 'unserialize\|allow_url_include\|display_errors\s*=\s*On' --include='*.php' .`
  and the `php.ini` returns nothing unsafe.
- A test asserting the payload `' OR '1'='1` in the parameter returns zero rows.
- A test asserting a loose-compare candidate (`"0e123"`) is rejected.
- `php -l` on every changed file, so a syntax error never accompanies the fix.
