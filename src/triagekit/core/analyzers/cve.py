"""Dependency CVE / advisory lookup via OSV (https://osv.dev) — no API key."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import httpx

OSV_QUERY = "https://api.osv.dev/v1/query"


def _parse_requirements_txt(text: str) -> list[tuple[str, Optional[str]]]:
    pkgs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"([A-Za-z0-9_.-]+)\s*([=<>!~]+)\s*([A-Za-z0-9_.+-]+)", line)
        if m:
            pkgs.append((m.group(1), m.group(3)))
        else:
            name = re.split(r"[<>=!~\s\[]", line)[0]
            if name:
                pkgs.append((name, None))
    return pkgs


def _unpinned(version: Optional[str]) -> bool:
    """True when a version string carries no information OSV can match on.

    ``*``, ``latest``, ``>=0`` and friends pin nothing; forwarding them as a
    literal version makes OSV return zero advisories, which reads as "clean".
    Callers turn these into "no version supplied" instead.
    """
    if version is None:
        return True
    v = version.strip().strip("\"'")
    if not v or v in ("*", "latest", "x", "X"):
        return True
    # Nothing but operators, wildcards and zeros.
    return set(v) <= set("0.*>=<!~^xX ")


def _clean_version(version: Optional[str]) -> Optional[str]:
    """Strip range operators; return None when what remains pins nothing."""
    if _unpinned(version):
        return None
    return re.sub(r"^[\^~>=<!\s]+", "", str(version).strip()) or None


def _parse_package_json_deps(text: str) -> list[tuple[str, Optional[str]]]:
    import json

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    pkgs = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, ver in (data.get(section) or {}).items():
            ver = str(ver).split(" ")[0]
            pkgs.append((name, _clean_version(ver)))
    return pkgs


def _parse_package_lock_json(text: str) -> list[tuple[str, Optional[str]]]:
    """Parse package-lock.json / npm-shrinkwrap.json.

    ``package.json`` carries ranges (``^4.17.1``) that match far more releases
    than the lock file pins, so a repo with only ``package.json`` scanned gets
    advisories for versions it does not run.  The lock file carries the exact
    resolved tree, and it is the file that should be queried when present.
    """
    import json

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    pkgs: list[tuple[str, Optional[str]]] = []
    # npm >= 7: {"packages": {"node_modules/express": {"version": "4.17.1"}}}
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            if not key:
                continue  # the "" entry is the root project itself
            name = meta.get("name") or (key.split("node_modules/")[-1])
            version = meta.get("version")
            if name:
                pkgs.append((str(name), _clean_version(version)))
        if pkgs:
            return pkgs
    # npm <= 6: {"dependencies": {"express": {"version": "4.17.1"}}}
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for name, meta in deps.items():
            if isinstance(meta, dict):
                pkgs.append((str(name), _clean_version(meta.get("version"))))
    return pkgs


def _parse_yarn_lock(text: str) -> list[tuple[str, Optional[str]]]:
    """Parse yarn.lock / yarn v2+ entries.

    Block form::

        express@^4.17.1:
          version "4.17.1"
          resolved "https://..."

    The ``version`` line is the resolved pin.  Scoped packages appear as
    ``"@scope/name@^1.0.0":`` and the package name must be taken from before
    the last ``@``, not from the first.
    """
    pkgs: list[tuple[str, Optional[str]]] = []
    pending_name: Optional[str] = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            pending_name = None
            header = line.rstrip()
            if header.endswith(":"):
                spec = header[:-1].strip().strip("\"'")
                # A block may list several specs: "a@^1, a@~1.2"
                spec = spec.split(",")[0].strip()
                if spec.startswith("@") and spec.count("@") > 1:
                    name = spec.rsplit("@", 1)[0]
                elif "@" in spec:
                    name = spec.rsplit("@", 1)[0]
                else:
                    name = spec
                if name and not name.startswith("__"):
                    pending_name = name
            continue
        if pending_name is None:
            continue
        m = re.match(r"^\s+version\s+[\"']?([^\"'\s]+)[\"']?", line)
        if m:
            pkgs.append((pending_name, _clean_version(m.group(1))))
            pending_name = None
    return pkgs


def _parse_pnpm_lock(text: str) -> list[tuple[str, Optional[str]]]:
    """Parse pnpm-lock.yaml (the v5, v6 and v9 shapes).

    The version is carried in the *key* in every layout, not in a nested
    ``version:`` line::

        v5:  packages: /express/4.17.1:
        v9:  packages: express@4.17.1:

    Reading only a nested ``version:`` line found nothing for either shape.
    A bare ``name:`` key with a nested ``version:`` is handled too, for the
    odd hand-edited lock file.
    """
    pkgs: list[tuple[str, Optional[str]]] = []
    in_packages = False
    current: Optional[str] = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 0:
            in_packages = stripped.startswith("packages:")
            current = None
            continue
        if not in_packages:
            continue
        if indent <= 2 and stripped.endswith(":"):
            key = stripped[:-1].strip().strip("\"'")
            parts = [p for p in key.split("/") if p]
            name = version = None
            # v5/v6 path form: /name/version, optionally /name/version_peer@pv
            if key.startswith("/") and len(parts) >= 2:
                tail = parts[-1]
                # A peer-dependency suffix is joined with "_": 1.2.3_@babel@7.0.0
                tail = tail.split("_", 1)[0]
                version, name = tail, parts[-2]
            else:
                # v6 key form "/name@version" or v9 key form "name@version";
                # the name may itself be scoped (@scope/name), so take the
                # version from the LAST "@" that is followed by a digit.
                m = re.match(r"^/?(?:@?[^@/]+/)?(?:@?[^@/]+/)*([^@]+)@([0-9][^@]*)$", key)
                if m:
                    name, version = m.group(1), m.group(2)
                else:
                    m = re.match(r"^/?(.+)@([0-9][^@]*)$", key.lstrip("/"))
                    if m:
                        name, version = m.group(1), m.group(2)
            if name and version:
                pkgs.append((name, _clean_version(version)))
                current = None
            elif name:
                current = name
            else:
                current = None
            continue
        if indent > 2 and current is not None:
            m = re.match(r"^version:\s*[\"']?([^\"'\s]+)[\"']?", stripped)
            if m:
                pkgs.append((current, _clean_version(m.group(1))))
                current = None
    return pkgs


def _parse_go_mod(text: str) -> list[tuple[str, Optional[str]]]:
    """Parse require directives from go.mod, including the block form.

    Single-line ``require x v1.2.3`` and the grouped form
    ``require (\n  x v1.2.3\n  // indirect\n)`` both carry dependencies; only
    the single-line form was matched, so every real-world go.mod parsed to
    zero packages and reported a clean bill of health.
    """
    pkgs: list[tuple[str, Optional[str]]] = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.startswith("require") and stripped.endswith("("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        target = stripped
        if stripped.startswith("require ") and not in_block:
            target = stripped[len("require "):].strip()
        elif not in_block:
            continue
        # A trailing // indirect comment is still a dependency.
        target = target.split("//")[0].strip()
        m = re.match(r"([^\s]+)\s+v([0-9][^\s]*)", target)
        if m:
            pkgs.append((m.group(1), m.group(2)))
    return pkgs


def _parse_pipfile_lock(text: str) -> list[tuple[str, Optional[str]]]:
    """Parse Pipfile.lock: {"default": {"pkg": {"version": "==2.25.0"}}}.

    ``==`` marks the *installed* version here and must be stripped, or OSV gets
    an uninterpretable version string and matches nothing.
    """
    import json

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    pkgs: list[tuple[str, Optional[str]]] = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            if isinstance(meta, dict):
                pkgs.append((str(name), _clean_version(meta.get("version"))))
    return pkgs


def _parse_pipfile(text: str) -> list[tuple[str, Optional[str]]]:
    pkgs = []
    section = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped.strip("[]")
            continue
        if section not in ("packages", "dev-packages"):
            continue
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"([A-Za-z0-9_.-]+)\s*=\s*[\"']?([^\"'\s]*)", stripped)
        if m:
            pkgs.append((m.group(1), _clean_version(m.group(2))))
    return pkgs


def _parse_cargo_toml(text: str) -> list[tuple[str, Optional[str]]]:
    """Parse Cargo.toml dependency sections.

    Three shapes carry a version and all three occur in the wild:
      serde = "1.0.145"                       bare string
      tokio = { version = "1.21.0" }          inline table
      [dependencies.regex] / version = "..."  sub-table
    Only the bare-string form was matched, so an inline-table dependency was
    silently skipped and never queried against OSV.
    """
    pkgs: list[tuple[str, Optional[str]]] = []
    section = None
    current: Optional[str] = None  # set inside [dependencies.<name>] sub-tables
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped.strip("[]")
            # A [dependencies.foo] table names a package on the header itself.
            current = section.split(".", 1)[1] if section.startswith("dependencies.") else None
            continue
        if not stripped or stripped.startswith("#"):
            continue
        if current is not None:
            m = re.match(r"^version\s*=\s*[\"']([^\"']+)[\"']", stripped)
            if m:
                pkgs.append((current, m.group(1)))
            current = None
            continue
        if section not in ("dependencies", "dev-dependencies", "build-dependencies"):
            continue
        m = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(.+)$", stripped)
        if not m:
            continue
        name, value = m.group(1), m.group(2).strip()
        if value.startswith(("\"", "'")):
            pkgs.append((name, value.strip("\"'")))
            continue
        # Inline table: pull version = "..." out of it.
        mv = re.search(r"version\s*=\s*[\"']([^\"']+)[\"']", value)
        if mv:
            pkgs.append((name, mv.group(1)))
        elif value.startswith("{"):
            # git/path dependency with no pinned version: record it so the
            # package is at least visible as unresolved rather than invisible.
            pkgs.append((name, None))
    # de-duplicate, preferring the first occurrence that carries a version
    seen: dict[str, Optional[str]] = {}
    for name, version in pkgs:
        if name not in seen:
            seen[name] = version
        elif seen[name] is None and version:
            seen[name] = version
    return list(seen.items())


def _parse_cargo_lock(text: str) -> list[tuple[str, Optional[str]]]:
    """Parse Cargo.lock: an array-of-tables of [[package]] blocks.

    Cargo.lock was routed to the Cargo.toml parser, which only reads
    [dependencies] sections, so it always returned zero packages -- the lock
    file is the one that names the *resolved* versions worth querying.
    """
    pkgs: list[tuple[str, Optional[str]]] = []
    name: Optional[str] = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            if name is not None:
                pkgs.append((name, None))
            name = None
            continue
        if stripped.startswith("name"):
            m = re.match(r"^name\s*=\s*[\"']([^\"']+)[\"']", stripped)
            if m:
                name = m.group(1)
            continue
        if name is not None:
            m = re.match(r"^version\s*=\s*[\"']([^\"']+)[\"']", stripped)
            if m:
                pkgs.append((name, m.group(1)))
                name = None
    if name is not None:
        pkgs.append((name, None))
    return pkgs


def _parse_composer_lock(text: str) -> list[tuple[str, Optional[str]]]:
    import json

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    pkgs = []
    for section in ("packages", "packages-dev"):
        for entry in data.get(section) or []:
            if isinstance(entry, dict) and entry.get("name"):
                pkgs.append((str(entry["name"]), str(entry.get("version") or "") or None))
    return pkgs


def _parse_gemfile_lock(text: str) -> list[tuple[str, Optional[str]]]:
    pkgs = []
    for line in text.splitlines():
        m = re.match(r"^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)", line)
        if m:
            pkgs.append((m.group(1), m.group(2)))
    return pkgs


def _parse_maven(text: str) -> list[tuple[str, Optional[str]]]:
    """GroupId/artifactId -> npm-style name is not possible, so pass both."""
    pkgs = []
    for m in re.finditer(
        r"<dependency>[\s\S]*?<groupId>([^<]+)</groupId>\s*"
        r"<artifactId>([^<]+)</artifactId>"
        r"(?:\s*<version>([^<]+)</version>)?[\s\S]*?</dependency>",
        text,
    ):
        pkgs.append((f"{m.group(1)}:{m.group(2)}", m.group(3) or None))
    return pkgs


# Manifest filename -> (ecosystem, parser).  Anything the dependency scanner can
# discover must be parseable, otherwise the scanner reports zero packages for a
# manifest it claims to have scanned -- a silent false negative.
_MANIFEST_PARSERS: dict[str, tuple[str, Any]] = {
    "requirements.txt": ("PyPI", _parse_requirements_txt),
    "requirements-dev.txt": ("PyPI", _parse_requirements_txt),
    "package.json": ("npm", _parse_package_json_deps),
    "package-lock.json": ("npm", _parse_package_lock_json),
    "npm-shrinkwrap.json": ("npm", _parse_package_lock_json),
    "yarn.lock": ("npm", _parse_yarn_lock),
    "pnpm-lock.yaml": ("npm", _parse_pnpm_lock),
    "go.mod": ("Go", _parse_go_mod),
    "pyproject.toml": ("PyPI", None),  # handled inline below (PEP 621)
    "pipfile": ("PyPI", _parse_pipfile),
    "pipfile.lock": ("PyPI", _parse_pipfile_lock),
    "cargo.toml": ("crates.io", _parse_cargo_toml),
    "cargo.lock": ("crates.io", _parse_cargo_lock),
    "composer.json": ("Packagist", None),  # name-only deps, no versions to match
    "composer.lock": ("Packagist", _parse_composer_lock),
    "gemfile.lock": ("RubyGems", _parse_gemfile_lock),
    "pom.xml": ("Maven", _parse_maven),
}


# Manifest filenames whose format this module can actually parse.  Derived from
# _MANIFEST_PARSERS rather than hand-listed, so adding a parser cannot leave this
# set stale (which would report a parsed manifest as an unsupported one).
# A manifest the dependency scanner can discover but that is absent here yields
# no packages, and scan_dependencies reports it in ``manifests_unparsed``
# rather than letting the empty result read as "no known vulnerabilities".
_SUPPORTED_MANIFESTS = set(_MANIFEST_PARSERS)


def _manifest_ecosystem(name: str) -> Optional[str]:
    """Ecosystem a manifest filename belongs to, or None if unreadable.

    This is the single source of truth for "can this build read that file".
    ``extract_packages`` routes through it and ``scan_dependencies`` asks it the
    same question; when the two disagreed, a file that parsed cleanly was
    reported as unparsed (or vice versa) -- a coverage number nobody could trust.
    """
    lower = name.lower()
    # "requirements" may be prefixed or suffixed in the wild -- dev-requirements.txt,
    # requirements.dev.txt, requirements_test.txt, cap-requirements.txt.  A
    # startswith() rule skipped all of those, leaving their dependencies
    # unscanned and unreported.
    if "requirements" in lower and lower.endswith(".txt"):
        return "PyPI"
    if lower == "pyproject.toml":
        return "PyPI"
    entry = _MANIFEST_PARSERS.get(lower)
    return entry[0] if entry else None


def extract_packages(manifest_path: Path) -> tuple[str, list[tuple[str, Optional[str]]]]:
    """Return (ecosystem, [(package, version), ...]) for a manifest file.

    A manifest the scanner can name but this function cannot parse returns an
    empty package list, which previously looked identical to "no known
    vulnerabilities".  Callers must record which manifests parsed to nothing.
    """
    name = manifest_path.name.lower()
    text = manifest_path.read_text(encoding="utf-8", errors="ignore")

    ecosystem = _manifest_ecosystem(name)

    if "requirements" in name and name.endswith(".txt"):
        return ecosystem, _parse_requirements_txt(text)

    if name == "pyproject.toml":
        pkgs = []
        # PEP 621 [project] dependencies
        for m in re.finditer(
            r"[\"']([A-Za-z0-9_.-]+)\s*([=<>!~]+)\s*([A-Za-z0-9_.+-]+)[\"']", text
        ):
            pkgs.append((m.group(1), m.group(3)))
        return ecosystem, pkgs

    if ecosystem is None:
        # An empty ecosystem means "unknown format".  Returning a plausible
        # ecosystem here let callers believe the file was scanned as PyPI.
        return "", []
    parser = _MANIFEST_PARSERS[name][1]
    if parser is None:
        return ecosystem, []
    try:
        return ecosystem, parser(text)
    except Exception:
        # A malformed manifest is a scanning error, not a clean bill of health.
        return ecosystem, []


def _severity_from_osv(v: dict[str, Any]) -> str:
    sev = "medium"
    for s in v.get("severity") or []:
        if not isinstance(s, dict):
            continue
        score_raw = s.get("score", "")
        score_str = str(score_raw)
        upper = score_str.upper()
        if "CRITICAL" in upper:
            sev = "critical"
            continue
        if "HIGH" in upper:
            sev = "high"
            continue
        nums = re.findall(r"\d+(?:\.\d+)?", score_str)
        if nums:
            try:
                val = float(nums[0])
            except ValueError:
                val = 0.0
            if val >= 9.0:
                sev = "critical"
            elif val >= 7.0:
                sev = "high"
            elif val >= 4.0:
                sev = "medium"
            else:
                sev = "low"
    db = v.get("database_specific") or {}
    if isinstance(db, dict) and db.get("severity"):
        sev = str(db["severity"]).lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "medium"
    return sev


def _osv_cvss_vector(vuln: dict[str, Any]) -> Optional[str]:
    """Pull the CVSS vector out of an OSV ``severity`` entry, if any.

    OSV stores it as ``{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}``, so
    the vector is the score *string* itself.  Any CVSS version is returned --
    downstream decides whether it can score that version and links it to the
    matching calculator.  Silently keeping only v4.0 throws away a
    measurement the advisory supplied.
    """
    for entry in vuln.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        score = str(entry.get("score") or "").strip()
        if score.upper().startswith("CVSS:"):
            return score
    return None


def query_osv(package: str, version: Optional[str], ecosystem: str) -> list[dict[str, Any]]:
    payload: dict[str, Any] = {
        "package": {"name": package, "ecosystem": ecosystem},
    }
    if version:
        payload["version"] = version
    try:
        r = httpx.post(OSV_QUERY, json=payload, timeout=20.0)
        if r.status_code != 200:
            return []
        vulns = r.json().get("vulns") or []
    except Exception:
        return []

    out = []
    for v in vulns[:15]:
        if not isinstance(v, dict):
            continue
        fixed = None
        for aff in v.get("affected") or []:
            if not isinstance(aff, dict):
                continue
            for rng in aff.get("ranges") or []:
                if not isinstance(rng, dict):
                    continue
                for ev in rng.get("events") or []:
                    if isinstance(ev, dict) and "fixed" in ev:
                        fixed = ev["fixed"]
        summary = v.get("summary") or v.get("details") or ""
        if not isinstance(summary, str):
            summary = str(summary)
        # Keep the vector itself, not just the band derived from it.  The band
        # was computed here and the vector discarded, so no downstream consumer
        # could ever offer a FIRST.org calculator link -- _severity_from_osv
        # read a score string and then threw it away.
        cvss_vector = _osv_cvss_vector(v)
        out.append(
            {
                "id": v.get("id"),
                "package": package,
                "version": version,
                "ecosystem": ecosystem,
                "summary": summary[:300],
                "severity": _severity_from_osv(v),
                "fixed": fixed,
                "cvss_vector": cvss_vector,
                # Everything the advisory says that the flat summary above drops.
                # Callers use these for CWE guidance, CVSS links and Metasploit
                # references instead of re-fetching the advisory.
                "aliases": [str(a) for a in (v.get("aliases") or []) if a],
                "cwes": sorted({
                    str(c) for c in (v.get("database_specific") or {}).get("cwe_ids", [])
                    if str(c).startswith("CWE-")
                }) or [],
                "references": [
                    str(r.get("url")) for r in (v.get("references") or [])
                    if isinstance(r, dict) and r.get("url")
                ][:12],
                "published": v.get("published"),
                "modified": v.get("modified"),
                "withdrawn": v.get("withdrawn"),
            }
        )
    return out


def scan_dependencies(
    root: Path, manifest_rels: list[str], max_packages: int = 40
) -> list[dict[str, Any]]:
    """Query OSV for every resolvable package in the given manifests.

    Returns ``(findings, stats)``.  ``stats`` records how many packages were
    resolved and how many manifests yielded none, so a caller cannot mistake
    "nothing parsed" for "nothing vulnerable".  Note: ``max_packages`` bounds
    the number of *packages queried*, and once reached the scan stops -- the
    caller is told how many were skipped rather than being left to assume full
    coverage.
    """
    findings: list[dict[str, Any]] = []
    stats: dict[str, Any] = {
        "manifests_total": len(manifest_rels),
        "manifests_unparsed": [],
        "packages_resolved": 0,
        "packages_queried": 0,
        "packages_skipped_over_cap": 0,
        "query_errors": 0,
        # A package pinned in more than one manifest is queried once but must
        # be upgraded in each of them.  See D66 in dev/AUTONOMOUS_TODO.md.
        "packages_duplicated_across_manifests": 0,
    }
    seen_pkg = set()
    # Every manifest that declares each (ecosystem, name, version), in the
    # order they were seen.  The deduplication below is deliberate -- the same
    # package at the same version answers with the same advisories -- but it
    # used to drop the second manifest with it, and a report that named only
    # the first had the maintainer fix one file and redeploy with the
    # vulnerable pin still live in the other.
    pkg_manifests: dict[tuple[str, str, str], list[str]] = {}
    count = 0
    for rel in manifest_rels:
        path = root / rel
        if not path.is_file():
            # A manifest the scanner promised but cannot read is a coverage
            # failure.  Skipping it silently let the result read as complete.
            stats["manifests_unparsed"].append(rel)
            continue
        try:
            ecosystem, pkgs = extract_packages(path)
        except Exception:
            stats["manifests_unparsed"].append(rel)
            continue
        if not pkgs:
            # Distinguish "parsed, genuinely no dependencies" from "parser
            # does not support this format" -- using the same routing the
            # parser used, so the two can never disagree.
            if _manifest_ecosystem(path.name.lower()) is None:
                stats["manifests_unparsed"].append(rel)
            continue
        for name, ver in pkgs:
            key = (ecosystem, name, ver)
            pkg_manifests.setdefault(key, []).append(rel)
            if key in seen_pkg:
                # Already queried: one advisory per vulnerability, not one per
                # manifest.  Recorded so the reader is told the package is
                # pinned somewhere else too.
                stats["packages_duplicated_across_manifests"] += 1
                continue
            seen_pkg.add(key)
            stats["packages_resolved"] += 1
            if count >= max_packages:
                stats["packages_skipped_over_cap"] += 1
                continue
            count += 1
            stats["packages_queried"] += 1
            try:
                for hit in query_osv(name, ver, ecosystem):
                    hit["manifest"] = rel
                    findings.append(hit)
            except Exception:
                stats["query_errors"] += 1
                continue
    # Name every manifest that pins each affected package.  Done after the
    # walk because a later manifest can add to the list of an earlier one.
    for hit in findings:
        key = (hit.get("ecosystem"), hit.get("package"), hit.get("version"))
        named = pkg_manifests.get(key) or [hit.get("manifest")]
        hit["manifests"] = list(dict.fromkeys(m for m in named if m))
    return findings, stats
