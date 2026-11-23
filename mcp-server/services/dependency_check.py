"""
Dependency vulnerability checks.

Reads the project's lockfiles, asks OSV.dev (https://osv.dev, a free public
vulnerability database that aggregates GitHub advisories, PyPA, RustSec, Go and
others, with CVE aliases) which pinned versions have known vulnerabilities, and
turns each one into a plain-language finding with the version to upgrade to.

Only package names and versions are sent to OSV.dev, never code.
"""
import json
import logging
import os
import re
import time
import xml.etree.ElementTree as ET
from typing import Dict, Iterable, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
OSV_TTL_SECONDS = 24 * 3600
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build", "target", "vendor"}

LOCKFILES = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "requirements.txt": "PyPI",
    "Pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "Cargo.lock": "crates.io",
    "Gemfile.lock": "RubyGems",
    "go.mod": "Go",
    "pnpm-lock.yaml": "npm",
    "uv.lock": "PyPI",
    "composer.lock": "Packagist",
    "packages.lock.json": "NuGet",
    "Directory.Packages.props": "NuGet",
    "gradle.lockfile": "Maven",
    "pom.xml": "Maven",
}
LOCKFILE_SUFFIXES = (".csproj", ".fsproj", ".vbproj")  # .NET project files with <PackageReference>
PLAIN_VERSION = re.compile(r"^v?\d[\w.+-]*$")  # an exact version, not a range, wildcard or ${variable}

Package = Tuple[str, str, str, str, int]  # (ecosystem, name, version, lockfile, line)


# --------------------------------------------------------------------------- lockfile parsers

def _line_of(text: str, needle: str) -> int:
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def _parse_package_lock(text: str, path: str) -> List[Package]:
    data = json.loads(text)
    found = {}
    for key, info in (data.get("packages") or {}).items():
        if not key or not isinstance(info, dict) or not info.get("version") or info.get("link"):
            continue
        name = info.get("name") or key.split("node_modules/")[-1]
        found[(name, info["version"])] = True

    def walk(deps):
        for name, info in (deps or {}).items():
            if isinstance(info, dict) and info.get("version"):
                found[(name, info["version"])] = True
                walk(info.get("dependencies"))
    if not found:
        walk(data.get("dependencies"))
    return [("npm", n, v, path, _line_of(text, f'"{n}"')) for (n, v) in sorted(found)]


def _parse_yarn_lock(text: str, path: str) -> List[Package]:
    out, current = [], None
    for lineno, line in enumerate(text.splitlines(), 1):
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            spec = line.rstrip(":").split(",")[0].strip().strip('"')
            at = spec.rfind("@")
            current = (spec[:at] if at > 0 else spec, lineno)
        elif current and line.strip().startswith("version"):
            version = line.strip().split(None, 1)[1].strip().strip('"')
            out.append(("npm", current[0], version, path, current[1]))
            current = None
    return sorted(set(out))


def _parse_requirements(text: str, path: str) -> List[Package]:
    out = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.+!_-]+)$", line)
        if m:
            out.append(("PyPI", m.group(1), m.group(2), path, lineno))
    return out


def _parse_pipfile_lock(text: str, path: str) -> List[Package]:
    data, out = json.loads(text), []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = (info or {}).get("version", "")
            if version.startswith("=="):
                out.append(("PyPI", name, version[2:], path, _line_of(text, f'"{name}"')))
    return out


def _from_registry(pkg: Dict, ecosystem: str) -> bool:
    """False for the project itself and for path/git/URL packages: OSV only knows registry releases, and a
    local package that happens to share a name with a public one would be a false alarm"""
    source = pkg.get("source")
    if ecosystem == "crates.io":
        return isinstance(source, str) and source.startswith("registry+")  # workspace crates have no source
    if isinstance(source, dict):  # uv: {registry=...} or {editable|virtual|directory|path|git|url=...}; poetry: {type=...}
        if source.get("type") in ("directory", "file", "git", "url"):
            return False
        return not any(k in source for k in ("editable", "virtual", "directory", "path", "git", "url"))
    return True


def _parse_toml_packages(text: str, path: str, ecosystem: str) -> List[Package]:
    try:
        import tomllib
    except ModuleNotFoundError:  # Python < 3.11
        return []
    data = tomllib.loads(text)
    return [(ecosystem, p["name"], p["version"], path, _line_of(text, f'name = "{p["name"]}"'))
            for p in data.get("package", [])
            if p.get("name") and p.get("version") and _from_registry(p, ecosystem)]


def _parse_gemfile_lock(text: str, path: str) -> List[Package]:
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)\s]+)\)$", line)
        if m:
            out.append(("RubyGems", m.group(1), m.group(2), path, lineno))
    return out


def _parse_go_mod(text: str, path: str) -> List[Package]:
    out, in_block = [], False
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?(\S+)\s+(v\S+)$", line) if (in_block or line.startswith("require ")) else None
        if m:
            out.append(("Go", m.group(1), m.group(2), path, lineno))
    return out


def _parse_pnpm_lock(text: str, path: str) -> List[Package]:
    """pnpm-lock.yaml, lockfile versions 5 to 9, read without a YAML library. Package keys sit two spaces
    deep under `packages:`: `/name/1.2.3_peer@1.0.0` (v5), `/name@1.2.3(peer@1.0.0)` (v6) or `name@1.2.3` (v9)"""
    m = re.search(r"^lockfileVersion:\s*['\"]?(\d+)", text, re.M)
    v5 = bool(m and int(m.group(1)) < 6)
    out, section = [], None
    for lineno, line in enumerate(text.splitlines(), 1):
        if line and not line[0].isspace():
            section = line.split(":", 1)[0].strip()
            continue
        if section != "packages" or not line.startswith("  ") or line.startswith("   ") or not line.rstrip().endswith(":"):
            continue
        key = line.strip()[:-1].strip("'\"").lstrip("/").split("(", 1)[0]
        if v5:
            km = re.match(r"^((?:@[^/]+/)?[^/]+)/(\d[^_/]*)", key)
        else:
            km = re.match(r"^((?:@[^/@]+/)?[^@/]+)@(.+)$", key)
        if km and PLAIN_VERSION.match(km.group(2)):
            out.append(("npm", km.group(1), km.group(2), path, lineno))
    return sorted(set(out))


def _parse_composer_lock(text: str, path: str) -> List[Package]:
    data, out = json.loads(text), []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            name, version = pkg.get("name"), str(pkg.get("version") or "")
            if name and PLAIN_VERSION.match(version):  # skips dev-main and other branch versions
                out.append(("Packagist", name, version.lstrip("vV"), path, _line_of(text, f'"name": "{name}"')))
    return out


def _parse_nuget_lock(text: str, path: str) -> List[Package]:
    """packages.lock.json: {"dependencies": {"net8.0": {"Name": {"type": "Direct", "resolved": "1.2.3"}}}}"""
    data, out = json.loads(text), set()
    for framework in (data.get("dependencies") or {}).values():
        for name, info in (framework or {}).items():
            info = info or {}
            version = str(info.get("resolved") or "")
            if info.get("type") != "Project" and PLAIN_VERSION.match(version):
                out.add(("NuGet", name, version, path, _line_of(text, f'"{name}"')))
    return sorted(out)


def _xml_root(text: str):
    """Parse XML and drop namespaces so tags can be found by plain name"""
    root = ET.fromstring(text)
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def _parse_msbuild(text: str, path: str) -> List[Package]:
    """.csproj/.fsproj/.vbproj <PackageReference> and Directory.Packages.props <PackageVersion>, exact versions only"""
    out = []
    for el in _xml_root(text).iter():
        if el.tag not in ("PackageReference", "PackageVersion"):
            continue
        name = el.get("Include") or el.get("Update")
        version = (el.get("Version") or el.findtext("Version") or "").strip()
        if name and PLAIN_VERSION.match(version):
            out.append(("NuGet", name, version, path, _line_of(text, f'"{name}"')))
    return out


def _parse_gradle_lockfile(text: str, path: str) -> List[Package]:
    """gradle.lockfile lines: group:artifact:version=configurations"""
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        parts = line.split("=", 1)[0].strip().split(":")
        if not line.startswith("#") and len(parts) == 3 and PLAIN_VERSION.match(parts[2]):
            out.append(("Maven", f"{parts[0]}:{parts[1]}", parts[2], path, lineno))
    return out


def _parse_pom(text: str, path: str) -> List[Package]:
    """pom.xml: dependencies declared in this file, with ${properties} defined in the same file resolved.
    Versions inherited from a parent POM or BOM, and packages pulled in by other packages, aren't visible."""
    root = _xml_root(text)
    props = {el.tag: (el.text or "").strip() for el in root.findall("properties/*")}
    for key in ("version", "groupId"):
        value = root.findtext(key) or root.findtext(f"parent/{key}")
        if value:
            props[f"project.{key}"] = props[f"pom.{key}"] = value.strip()

    def resolve(value: str) -> str:
        for _ in range(5):  # properties may refer to other properties
            value = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), value)
        return value.strip()

    out = []
    for dep in root.findall("dependencies/dependency") + root.findall("dependencyManagement/dependencies/dependency"):
        if (dep.findtext("scope") or "").strip() == "import":
            continue  # a BOM, not a library
        raw_artifact = (dep.findtext("artifactId") or "").strip()
        group, artifact = resolve(dep.findtext("groupId") or ""), resolve(raw_artifact)
        version = resolve(dep.findtext("version") or "")
        if group and artifact and PLAIN_VERSION.match(version):
            out.append(("Maven", f"{group}:{artifact}", version, path,
                        _line_of(text, f"<artifactId>{raw_artifact}</artifactId>")))
    return out


def lockfile_note(path: str, display: str) -> Optional[str]:
    """What a manifest can't show, so users know which packages went unchecked"""
    name = os.path.basename(path)
    if name == "pom.xml":
        return (f"{display}: Maven has no lockfile, so only dependencies declared in this pom.xml with a version set "
                "here were checked; packages they pull in, and versions inherited from a parent POM or BOM, were not.")
    if name.endswith(LOCKFILE_SUFFIXES) or name == "Directory.Packages.props":
        if not os.path.exists(os.path.join(os.path.dirname(path), "packages.lock.json")):
            return (f"{display}: only packages listed here with an exact version were checked; packages they pull in "
                    "were not. Turn on NuGet lock files (RestorePackagesWithLockFile) for a full check.")
    return None


def parse_lockfile(path: str, text: str) -> List[Package]:
    name = os.path.basename(path)
    try:
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            return _parse_package_lock(text, path)
        if name == "yarn.lock":
            return _parse_yarn_lock(text, path)
        if name == "Pipfile.lock":
            return _parse_pipfile_lock(text, path)
        if name == "poetry.lock":
            return _parse_toml_packages(text, path, "PyPI")
        if name == "Cargo.lock":
            return _parse_toml_packages(text, path, "crates.io")
        if name == "Gemfile.lock":
            return _parse_gemfile_lock(text, path)
        if name == "go.mod":
            return _parse_go_mod(text, path)
        if re.match(r"^requirements.*\.txt$", name):
            return _parse_requirements(text, path)
        if name == "pnpm-lock.yaml":
            return _parse_pnpm_lock(text, path)
        if name == "uv.lock":
            return _parse_toml_packages(text, path, "PyPI")
        if name == "composer.lock":
            return _parse_composer_lock(text, path)
        if name == "packages.lock.json":
            return _parse_nuget_lock(text, path)
        if name == "Directory.Packages.props" or name.endswith(LOCKFILE_SUFFIXES):
            return _parse_msbuild(text, path)
        if name == "gradle.lockfile":
            return _parse_gradle_lockfile(text, path)
        if name == "pom.xml":
            return _parse_pom(text, path)
    except (ValueError, KeyError, TypeError, ET.ParseError) as e:
        logger.warning("Could not parse %s: %s", path, e)
    return []


def find_lockfiles(project_path: str) -> List[str]:
    found = []
    for root, dirs, files in os.walk(project_path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            if name in LOCKFILES or name.endswith(LOCKFILE_SUFFIXES) or re.match(r"^requirements.*\.txt$", name):
                found.append(os.path.join(root, name))
    return found


# --------------------------------------------------------------------------- OSV client

def _severity(vuln: Dict) -> str:
    sev = str((vuln.get("database_specific") or {}).get("severity") or "").lower()
    if sev in ("critical", "high", "low"):
        return sev
    if sev in ("moderate", "medium"):
        return "medium"
    for affected in vuln.get("affected") or []:
        sev = str((affected.get("ecosystem_specific") or {}).get("severity") or "").lower()
        if sev in ("critical", "high", "medium", "low"):
            return sev
    return "high" if vuln.get("severity") else "medium"


def _vkey(version: str) -> Tuple:
    """Natural sort key: '1.10.0' > '1.9.2'; good enough to pick the next fixed release"""
    parts = re.split(r"(\d+)", version.lstrip("vV"))
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in parts if p not in ("", "."))


def _fixed_versions(vuln: Dict, ecosystem: str, name: str) -> List[str]:
    fixed = []
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or pkg.get("name", "").lower() != name.lower():
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    fixed.append(event["fixed"])
    return sorted(set(fixed))


class OSVClient:
    """Minimal OSV.dev client with a time-limited cache (a dict you can persist)"""

    def __init__(self, cache: Optional[Dict] = None, session=None, timeout: float = 20):
        self.cache = cache if cache is not None else {}
        self.http = session or requests
        self.timeout = timeout

    def _cached(self, key: str):
        entry = self.cache.get(key)
        if entry and time.time() - entry.get("t", 0) < OSV_TTL_SECONDS:
            return entry["v"]
        return None

    def vulnerable(self, packages: List[Tuple[str, str, str]]) -> Dict[Tuple[str, str, str], List[str]]:
        """{(ecosystem, name, version): [vuln ids]} for packages with known vulnerabilities"""
        result, todo = {}, []
        for pkg in packages:
            hit = self._cached("q|" + "|".join(pkg))
            if hit is None:
                todo.append(pkg)
            elif hit:
                result[pkg] = hit
        for start in range(0, len(todo), 500):
            chunk = todo[start:start + 500]
            body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
            resp = self.http.post(OSV_BATCH_URL, json=body, timeout=self.timeout)
            resp.raise_for_status()
            for pkg, item in zip(chunk, resp.json().get("results", [])):
                ids = sorted({v["id"] for v in (item or {}).get("vulns") or [] if v.get("id")})
                self.cache["q|" + "|".join(pkg)] = {"t": time.time(), "v": ids}
                if ids:
                    result[pkg] = ids
        return result

    def details(self, vuln_id: str) -> Dict:
        hit = self._cached("v|" + vuln_id)
        if hit is not None:
            return hit
        resp = self.http.get(OSV_VULN_URL.format(vuln_id), timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        slim = {k: data.get(k) for k in ("id", "summary", "details", "aliases", "affected", "severity", "database_specific")}
        slim["details"] = (slim.get("details") or "")[:500]
        self.cache["v|" + vuln_id] = {"t": time.time(), "v": slim}
        return slim


# --------------------------------------------------------------------------- findings

def check_dependencies(project_path: str, client: Optional[OSVClient] = None,
                       muted: Iterable[str] = ()) -> Dict:
    """Scan every lockfile under project_path. Returns {"packages", "lockfiles", "violations", "error", "notes"};
    notes say what a manifest without a lockfile couldn't show"""
    client = client or OSVClient()
    muted = set(muted)
    packages: List[Package] = []
    notes: List[str] = []
    lockfiles = find_lockfiles(project_path)
    for path in lockfiles:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                packages += parse_lockfile(path, fh.read())
        except OSError:
            continue
        note = lockfile_note(path, os.path.relpath(path, project_path))
        if note:
            notes.append(note)

    unique = sorted({(e, n, v) for e, n, v, _, _ in packages})
    data = {"lockfiles": [os.path.relpath(p, project_path) for p in lockfiles],
            "packages": len(unique), "violations": [], "error": None, "notes": notes}
    if not unique:
        return data

    try:
        hits = client.vulnerable(unique)
        details = {vid: client.details(vid) for ids in hits.values() for vid in ids}
    except requests.RequestException as e:
        data["error"] = f"Could not reach OSV.dev ({e.__class__.__name__}); dependency check skipped."
        return data

    where = {}
    for e, n, v, path, line in packages:
        where.setdefault((e, n, v), (path, line))

    for pkg, ids in sorted(hits.items()):
        finding = _package_finding(pkg, ids, details, muted)
        if finding:
            path, line = where[pkg]
            finding.update({"file_path": os.path.relpath(path, project_path),
                            "line": line, "column": 1, "end_line": line, "end_column": 1})
            data["violations"].append(finding)
    return data


def _package_finding(pkg: Tuple[str, str, str], ids: List[str], details: Dict[str, Dict],
                     muted: set) -> Optional[Dict]:
    """One finding per vulnerable package: every advisory (deduplicated across GHSA/PYSEC/CVE IDs),
    the worst severity, and the single version that fixes all of them"""
    ecosystem, name, version = pkg
    # Prefer GitHub advisories (GHSA) as the main ID; skip advisories that are aliases of one already kept
    ordered = sorted(ids, key=lambda i: (not i.startswith("GHSA-"), i))
    kept, seen = [], set()
    for vid in ordered:
        vuln = details[vid]
        names = {vid, *(vuln.get("aliases") or [])}
        if names & muted or vid in seen:
            continue
        seen |= names
        kept.append(vuln)
    if not kept:
        return None

    severity = min((_severity(v) for v in kept), key=lambda s: ["critical", "high", "medium", "low"].index(s))
    targets, unfixed = [], []
    for v in kept:
        fixed = _fixed_versions(v, ecosystem, name)
        newer = [f for f in fixed if _vkey(f) > _vkey(version)]
        if newer:
            targets.append(min(newer, key=_vkey))
        elif not fixed:
            unfixed.append(v["id"])
    actions = []
    if targets:
        actions.append(f"Upgrade {name} to {max(targets, key=_vkey)} or later (from {version})")
    if unfixed:
        actions.append(f"{len(unfixed)} advisor{'y has' if len(unfixed) == 1 else 'ies have'} no fixed version yet "
                       f"({', '.join(unfixed[:3])}): replace {name} or limit how it's used")
    actions.append("Update the lockfile and re-run the scan")

    summaries = [(v.get("summary") or v.get("details") or "").strip().rstrip(".") for v in kept]
    summaries = [s for s in summaries if s][:3]
    count = len(kept)
    message = (f"{name} {version} ({ecosystem}) has {count} known vulnerabilit{'y' if count == 1 else 'ies'}"
               + (": " + "; ".join(summaries) if summaries else "") + ("; and more" if count > 3 else "") + ".")
    refs = []
    for v in kept:
        for r in [v["id"], *(v.get("aliases") or [])]:
            if r not in refs:
                refs.append(r)
    return {
        "rule_id": kept[0]["id"],
        "title": f"Vulnerable dependency: {name} {version}",
        "severity": severity,
        "message": message,
        "description": message,
        "required_actions": actions,
        "references": refs,
        "matched_code": f"{name} {version}",
        "kind": "dependency",
        "advisories": [v["id"] for v in kept],
    }
