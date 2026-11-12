# SQL Injection (CWE-89)

## What it is

SQL injection happens when text an attacker controls is handed to the database
as part of a SQL statement rather than as a value bound to it, so the parser
reads attacker syntax as SQL. The trust boundary crossed is request data (or a
CLI argument, environment variable, file, or a row written earlier) into
statement text. TriageKit reports this class as CWE-89 under the finding
category `taint-sql-execution`, with a source-to-sink trace in the evidence.

## Detection

### Python (the AST taint analyzer; the precision claims below are Python-only)

The analyzer seeds taint at a recognized source expression and follows it
through assignments, `+` concatenation, `%`-formatting, f-strings, container
literals, tuples/dicts, method calls on tainted receivers, and calls into
functions defined in the same file (call-site sensitive, keyword aware). A
finding is raised when that taint reaches the statement text of a SQL call.

Recognized sources (the first step of the trace):

```python
name  = request.args["name"]      # Flask query string
email = request.form["email"]     # POST body
hdr   = request.headers["Host"]   # attacker-controlled header
uid   = request.cookies["uid"]
arg   = sys.argv[1]               # CLI tool
key   = os.environ["KEY"]         # deployment config
data  = open(p).read()            # file contents
row   = cur.fetchone()            # stored data (second order)
```

Reported shapes (each of these IS reported):

```python
# concatenation
cur.execute("SELECT * FROM users WHERE email = '" + email + "'")

# %-format
cur.execute("SELECT * FROM users WHERE name = '%s'" % name)

# f-string
cur.execute(f"SELECT * FROM users WHERE name = '{name}'")

# .format() one hop earlier -- the sink is the execute() call, not the format()
stmt = "SELECT * FROM users WHERE name = '{}'".format(name)
cur.execute(stmt)

# ORM escape hatches
User.objects.raw("SELECT * FROM u WHERE n = '%s'" % name)
User.objects.extra(where=["n = '%s'" % name])
session.execute(text("SELECT * FROM t WHERE n = '" + n + "'"))
conn.execute("SELECT * FROM t WHERE n = '" + n + "'")
db.executemany("INSERT INTO t VALUES ('%s')" % name, rows)
sqlite3.connect(path).execute("SELECT * FROM t WHERE n = '" + n + "'")
```

Not reported shapes (each of these is NOT reported):

```python
# parameterized -- the statement text is a constant, values travel beside it
cur.execute("SELECT * FROM users WHERE email = ?", (email,))
cur.execute("SELECT * FROM users WHERE email = %s", (email,))   # psycopg2
cur.execute("SELECT * FROM users WHERE email = :e", {"e": email})
cur.execute(sql="SELECT * FROM users WHERE email = %s", params=(email,))

# ORM value binding -- the ORM binds, it does not interpolate
User.objects.filter(email=email)
User.objects.get(name=name)
session.query(User).filter(User.email == email)
```

Precise analyzer semantics, so the report can state them without guessing:

- A second positional argument that is a tuple or list literal, or a
  `params=` / `parameters=` / `vars=` / `args=` / `param=` keyword bound to a
  tuple or list, is read as parameter binding.
- Only the statement text decides whether a SQL sink is dangerous. Bound
  parameters are deliberately never checked: they cannot alter query
  structure, whatever they contain.
- Parameterization does not launder an interpolated statement. This IS
  reported: `cur.execute(f"SELECT * FROM t WHERE n = '{n}'", (n,))`.
- The sink checks argument 0 (or the `sql=` / `query=` / `statement=` /
  `operation=` / `command=` keyword). Taint in a later argument is not a SQL
  finding on its own.
- Interprocedural flows are reported at the sink line inside the callee, so a
  helper such as `def run(cur, q): cur.execute(q)` called with an interpolated
  string is reported at the `cur.execute(q)` line, with the caller's source in
  the trace.

### Other languages (pattern-level, not taint-tracked)

Look for template literals or `+` into `db.query(...)` / `knex.raw(...)` /
`sequelize.query(...)` in JS/TS, and `"`-interpolated strings into
`mysqli_query` / `pg_query` in PHP. These findings come from the pattern
scanners, not the taint engine, so carry lower confidence and need the same
manual proof described below.

## How it works (attack mechanics)

The attacker controls one parameter of a request. Because the parameter is
pasted into the statement text before the database parses it, the attacker can
close the quoted literal and append their own SQL. Payload shapes, against a
local fixture database only:

- Auth-bypass shape: `' OR '1'='1` turns a `WHERE` clause into a tautology.
- UNION extraction shape: `' UNION SELECT name, value FROM secrets --` reads a
  second table through the first query's result set.
- Stacked-statement shape (where the driver allows it): `'; DROP TABLE x --`.
- Oracle shapes for blind injection: a comparison in the predicate
  (`' AND substr(pw,1,1)='a`) or a time delay, distinguished only by response
  length or latency.

What the sink does with the value matters: `execute` parses the whole string as
one statement; `executemany` parses it once and repeats with bound rows;
`executescript` runs multiple statements, which raises impact.

## Is it actually exploitable? (exploitability test)

1. Trace check: does the tainted value land in the statement text, or only in a
   bound parameter? The finding's evidence lists every hop and the last hop is
   the sink call. If the value only ever appears as a bound parameter, close it.
2. Is the sink reachable from outside? Read the route decorator and any auth
   middleware. An unauthenticated handler raises severity; an internal
   admin-only endpoint lowers it. Say which in the narrative.
3. What does the response reveal? Query results echoed back means extraction
   is direct. A stack trace or driver error returned to the client is an oracle
   (see skills/19-headers-and-cookies.md for error disclosure). A bare
   success/failure means blind injection, which is still exploitable.
4. What privileges does the application's database user have? Read-only on one
   schema caps impact at confidentiality of that schema. Write access, or
   host-escape features such as `LOAD_FILE`, `COPY ... TO PROGRAM`, or
   `xp_cmdshell`, raises it to integrity and availability, and a shared
   database raises the subsequent-system metrics.
5. If the source category is database or file (a second-order flow), the
   attacker needs a prior write path. State that precondition in the narrative
   instead of presenting the flow as directly reachable.

## False positives (do NOT report)

- `cur.execute("SELECT * FROM t WHERE id = ?", (id_,))` and every other
  parameterized call. These produce no finding; if one appears, the statement
  text itself was interpolated elsewhere in the same flow.
- Django ORM `.filter(...)` / `.get(...)` / `.create(...)` and SQLAlchemy
  `session.query(...)` / `select(...)` with keyword arguments. The ORM binds
  values. Only `.raw(...)` / `.extra(...)` / `text(...)` with interpolation is
  a finding.
- `.execute()` on a receiver that is not a database cursor or connection. A
  thread pool or task queue (`pool.execute(job)`, `executor.execute(task)`)
  matches the sink name; check the receiver in the trace snippet. If it is not
  a DB object, it is not SQL injection.
- A value chosen by the code through a constant mapping:
  `col = {"email": "email", "name": "name"}[request.args["sort"]]` followed by
  `cur.execute("SELECT * FROM t ORDER BY " + col)`. The subscript lookup does
  not propagate taint from the key, so this is not reported, and it is
  genuinely safe: the text reaching the SQL is a constant the code chose.
  Note that `.get(request.args["sort"])` DOES propagate taint, so the mapping
  must be an index, not a method call.
- A constant statement with no interpolation and no tainted variable anywhere
  in the flow.

## Severity

Representative vector for an unauthenticated handler on an internet-facing
application whose database the application can read and write:

    CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N

Calculator: `https://www.first.org/cvss/calculator/v4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`

How the metrics move, without computing a score (v4.0 is a lookup table; never
produce a number by hand): AV stays N for a web handler, L for a local CLI
tool. PR rises from N to L when the endpoint requires a session. AT stays N:
no user interaction beyond the request. VC and VI stay H for full statement
control; VA is H only where destructive statements are permitted. SC, SI and
SA rise from N when the database is shared with other tenants or holds other
systems' data.

## Remediation

sqlite3 / DB-API, before and after:

```python
# before
cur.execute("SELECT * FROM users WHERE email = '" + email + "'")
cur.execute(f"SELECT * FROM users WHERE name = '{name}'")

# after
cur.execute("SELECT * FROM users WHERE email = ?", (email,))
cur.execute("SELECT * FROM users WHERE name = ?", (name,))
```

psycopg2 / PostgreSQL, before and after:

```python
# before
cur.execute("SELECT * FROM users WHERE email = '%s'" % email)

# after
cur.execute("SELECT * FROM users WHERE email = %s", (email,))
```

SQLAlchemy, before and after:

```python
# before
session.execute(text("SELECT * FROM t WHERE n = '" + n + "'"))

# after
session.execute(text("SELECT * FROM t WHERE n = :n"), {"n": n})
```

Django, before and after:

```python
# before
User.objects.raw("SELECT * FROM u WHERE n = '%s'" % name)

# after -- ORM binding
User.objects.filter(name=name)

# after -- raw() with bound params
User.objects.raw("SELECT * FROM u WHERE n = %s", [name])
```

Identifiers (a sort column, a table name) cannot be bound. Use a mapping, not
an f-string:

```python
# before -- attacker names the column
cur.execute(f"SELECT * FROM t ORDER BY {request.args['sort']}")

# after -- the SQL text is assembled from constants only
SORT_COLUMNS = {"email": "email", "name": "name"}
col = SORT_COLUMNS[request.args["sort"]]      # KeyError -> 400
cur.execute("SELECT * FROM t ORDER BY " + col)
```

Never build the mapping with `SORT_COLUMNS.get(request.args["sort"])`: a
`.get()` call propagates taint and the flow is reported again.

## Verify the fix

1. Behavioural test, run against the local fixture database:

```python
def test_email_is_bound_not_interpolated(client):
    r = client.get("/search?email=x' OR '1'='2")
    assert r.status_code == 200
    assert b"admin@example.com" not in r.content    # tautology did not match
```

2. Source check for leftover interpolation on SQL calls:

```
grep -rnE '(execute|executemany|raw|extra)\(' --include='*.py' . \
  | grep -E '(\+|%|format|f")'
```

Every remaining hit must be inside `tests/` or a fixture that seeds a constant
string. Production hits are unfinished work.

3. Re-scan and confirm the finding is gone, not downgraded:

```
triagekit scan <path> --json
```

There must be no finding with category `taint-sql-execution` pointing at the
touched file. A correctly parameterized query produces no finding at all,
because the statement text is constant; the flow is not merely re-scored.

Cross-reference: skills/06-injection-surface.md for how this class is routed
into triage, skills/26-finding-narrative.md for the trace wording, and
skills/27-false-positive-control.md when a reported flow must be closed as a
false positive with evidence.
