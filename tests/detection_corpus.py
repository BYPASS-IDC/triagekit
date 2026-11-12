"""Source-to-sink detection corpus for the native analyzers.

HARNESS CONTRACT (see tests/test_taint_analysis.py)
-----------------------------------------------
1. Every fixture is written to a unique temporary directory removed in a
   ``finally`` block.
2. Analysis always goes through the module-level helpers
   (``analyze_python_file`` / ``analyze_js_file``), which build a fresh
   analyzer per call.
3. ASCII only: the console on this platform is cp1252.
4. Each case asserts an EXPECTED detection outcome, so a regression in either
   direction -- a missed vulnerability or an invented one -- fails here.

This module is the single source of truth for the corpus.
``dev/probes/probe_python_detection.py`` imports it to print a detection-rate
table, so the ad-hoc measurement and the regression suite cannot drift apart.
"""

from __future__ import annotations

PYTHON_DETECTION_CASES: list[tuple[str, bool, str]] = []


def _case(cid, expect, src):
    PYTHON_DETECTION_CASES.append((cid, expect, src))


# ---------------------------------------------------------------- injection ---

_case("sqli-flask-fstring", True, '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/u")
def user():
    name = request.args.get("name")
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return "ok"
''')

_case("sqli-flask-bracket", True, '''
from flask import request
import sqlite3

def user():
    name = request.args["name"]
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return "ok"
''')

_case("sqli-parameterized-safe", False, '''
from flask import request
import sqlite3

def user():
    name = request.args.get("name")
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return "ok"
''')

_case("sqli-helper-interprocedural", True, '''
from flask import request
import sqlite3

def run_query(conn, uid):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + uid)

def handler():
    uid = request.args.get("id")
    run_query(sqlite3.connect("d.db"), uid)
''')

_case("sqli-keyword-arg-sink", True, '''
from flask import request
import sqlite3

def handler():
    uid = request.args.get("id")
    conn = sqlite3.connect("d.db")
    conn.cursor().execute(sql="SELECT * FROM t WHERE id = " + uid)
''')

_case("sqli-safe-no-flow", False, '''
import sqlite3

def handler():
    conn = sqlite3.connect("d.db")
    conn.cursor().execute("SELECT 1")
''')

_case("sqli-class-method", True, '''
from flask import request
import sqlite3

class Repo:
    def find(self, uid):
        self.conn.cursor().execute("SELECT * FROM t WHERE id = " + uid)

def handler():
    uid = request.args.get("id")
    Repo().find(uid)
''')

# --------------------------------------------------------- command injection ---

_case("cmdi-os-system", True, '''
import os
from flask import request

def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
''')

_case("cmdi-subprocess-shell", True, '''
import subprocess
from flask import request

def ping():
    host = request.args.get("host")
    subprocess.run("ping -c 1 " + host, shell=True)
''')

_case("cmdi-subprocess-argv-safe", False, '''
import subprocess
from flask import request

def ping():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], shell=False)
''')

_case("cmdi-helper", True, '''
import os
from flask import request

def run(cmd):
    os.system(cmd)

def handler():
    run("ls " + request.args.get("dir"))
''')

_case("cmdi-shlex-quote-safe", False, '''
import os
import shlex
from flask import request

def ls():
    d = request.args.get("dir")
    os.system("ls " + shlex.quote(d))
''')

# ------------------------------------------------------------ code injection ---

_case("codei-eval", True, '''
from flask import request

def calc():
    return eval(request.args.get("expr"))
''')

_case("codei-exec-fstring", True, '''
from flask import request

def run():
    exec(f"x = {request.args.get('n')}")
''')

_case("codei-safe-literal-eval", False, '''
import ast
from flask import request

def calc():
    return ast.literal_eval(request.args.get("expr"))
''')

# ---------------------------------------------------------- deserialization ---

_case("deser-pickle", True, '''
import pickle
from flask import request

def load():
    return pickle.loads(request.data)
''')

_case("deser-yaml-unsafe", True, '''
import yaml
from flask import request

def load():
    return yaml.load(request.data, Loader=yaml.Loader)
''')

_case("deser-yaml-safe", False, '''
import yaml
from flask import request

def load():
    return yaml.safe_load(request.data)
''')

# ------------------------------------------------------------- SSTI / XSS ---

_case("ssti-render-template-string", True, '''
from flask import render_template_string, request

def page():
    return render_template_string(request.args.get("tpl"))
''')

_case("xss-make-response", True, '''
from flask import make_response, request

def page():
    return make_response("<h1>" + request.args.get("n") + "</h1>")
''')

_case("xss-escape-safe", False, '''
from flask import make_response, request
from markupsafe import escape

def page():
    return make_response("<h1>" + str(escape(request.args.get("n"))) + "</h1>")
''')

# ------------------------------------------------------------ path traversal ---

_case("path-open-user", True, '''
from flask import request

def read():
    with open("/data/" + request.args.get("f")) as fh:
        return fh.read()
''')

_case("path-send-file", True, '''
from flask import send_file, request

def dl():
    return send_file("/data/" + request.args.get("f"))
''')

# ---------------------------------------------------------- SSRF / redirect ---

_case("ssrf-requests-get", True, '''
import requests
from flask import request

def fetch():
    return requests.get(request.args.get("url")).text
''')

_case("ssrf-urlopen", True, '''
import urllib.request
from flask import request

def fetch():
    return urllib.request.urlopen(request.args.get("url")).read()
''')

_case("redirect-open", True, '''
from flask import redirect, request

def go():
    return redirect(request.args.get("next"))
''')

# --------------------------------------------------------------- env / argv ---

_case("argv-os-system", True, '''
import os
import sys

def main():
    os.system("echo " + sys.argv[1])
''')

_case("environ-os-system", True, '''
import os

def main():
    os.system("echo " + os.environ["USER_CMD"])
''')

_case("getenv-os-system", True, '''
import os

def main():
    os.system("echo " + os.getenv("USER_CMD"))
''')

_case("input-os-system", True, '''
import os

def main():
    os.system("echo " + input("cmd: "))
''')

# ------------------------------------------------------------- cryptography ---

_case("md5-weak-hash", True, '''
import hashlib
from flask import request

def h():
    return hashlib.md5(request.args.get("p").encode()).hexdigest()
''')

# --------------------------------------------------------------- log/ReDoS ---

_case("log-injection", True, '''
import logging
from flask import request

log = logging.getLogger(__name__)

def note():
    log.info("user " + request.args.get("u") + " logged in")
''')

_case("redos-user-pattern", True, '''
import re
from flask import request

def match():
    return re.match(request.args.get("p"), "x" * 100)
''')

# ------------------------------------------------------- multi-hop / chained ---

_case("chain-two-hops", True, '''
import os
from flask import request

def inner(v):
    return v.strip()

def outer(v):
    return inner(v)

def handler():
    os.system("echo " + outer(request.args.get("x")))
''')

_case("chain-fstring-hop", True, '''
import subprocess
from flask import request

def build(v):
    return f"tar czf out.tgz {v}"

def handler():
    subprocess.run(build(request.args.get("d")), shell=True)
''')

_case("dict-container-flow", True, '''
import os
from flask import request

def handler():
    payload = {"cmd": request.args.get("c")}
    os.system(payload["cmd"])
''')

_case("no-flow-constant", False, '''
import os

def handler():
    os.system("ls -la")
''')

_case("sanitized-then-sink-safe", False, '''
import os
import shlex
from flask import request

def handler():
    d = shlex.quote(request.args.get("d"))
    os.system("ls " + d)
''')

_case("int-sink-param-index", True, '''
import subprocess
from flask import request

def handler():
    subprocess.run(["sh", "-c", request.args.get("c")])
''')


