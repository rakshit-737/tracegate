"""Static reachability: which pinned dependencies can the application load?

Runtime facts ("module X was loaded in container Y") are the gold standard and
are consumed by `enrich_reachability`. When a pipeline has no runtime stage we
fall back to a conservative *static* estimate from the repository itself:

  imported    top-level module imported anywhere in the app sources (AST), or
              named in a dotted-path string (Django INSTALLED_APPS, MIDDLEWARE,
              ENGINE, plugin paths...)
  entrypoint  distribution / console-script named in Dockerfile, Procfile,
              shell scripts or CI config (gunicorn, uwsgi, celery, ...)
  referenced  its module name appears as a bare string constant (plugin / scheme
              names such as passlib's "argon2"): weaker evidence, still reachable
  transitive  required (per pip-compile `# via` annotations) by a package that
              is itself reachable
  unreached   none of the above, in a manifest whose dependency edges are recorded
              (pip-compile `# via`) -> findings on it are downgraded block -> warn
  unknown     none of the above, but the manifest records no dependency edges, so the
              package may be required by something the app imports -> no downgrade
              (an audit of 45 such downgrades found every one loaded; see the Evaluation)

The estimate over-approximates (anything imported counts, even on a cold path)
except for plugins loaded purely by entry points or by computed import strings;
those are the documented false-"unreached" risk (see docs/adr/0004).
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from .ids import normalize_name

# distribution -> import names where they differ from the normalised dist name
KNOWN_IMPORTS: dict[str, list[str]] = {
    "pyyaml": ["yaml"], "pillow": ["PIL"], "beautifulsoup4": ["bs4"], "python-dateutil": ["dateutil"],
    "pyjwt": ["jwt"], "psycopg2-binary": ["psycopg2"], "psycopg-binary": ["psycopg"], "psycopg-c": ["psycopg"],
    "psycopg-pool": ["psycopg_pool"], "pycryptodome": ["Crypto"], "pycrypto": ["Crypto"], "pycryptodomex": ["Cryptodome"],
    "scikit-learn": ["sklearn"], "opencv-python": ["cv2"], "protobuf": ["google.protobuf", "google"],
    "google-cloud-storage": ["google.cloud.storage"], "google-auth": ["google.auth"],
    "google-api-core": ["google.api_core"], "googleapis-common-protos": ["google.api", "google.rpc"],
    "grpcio": ["grpc"], "msgpack-python": ["msgpack"], "python-slugify": ["slugify"],
    "django-filter": ["django_filters"], "djangorestframework": ["rest_framework"],
    "django-cors-headers": ["corsheaders"], "django-redis": ["django_redis"], "django-rq": ["django_rq"],
    "social-auth-app-django": ["social_django"], "social-auth-core": ["social_core"],
    "django-debug-toolbar": ["debug_toolbar"], "django-graphiql-debug-toolbar": ["graphiql_debug_toolbar"],
    "django-mptt": ["mptt"], "django-taggit": ["taggit"], "django-tables2": ["django_tables2"],
    "django-timezone-field": ["timezone_field"], "drf-spectacular": ["drf_spectacular"],
    "drf-spectacular-sidecar": ["drf_spectacular_sidecar"], "strawberry-graphql": ["strawberry"],
    "strawberry-graphql-django": ["strawberry_django"], "mkdocs-material": ["material"],
    "markdown": ["markdown"], "pyotp": ["pyotp"], "fido2": ["fido2"], "whitenoise": ["whitenoise"],
    "django-compressor": ["compressor"], "django-stubs-ext": ["django_stubs_ext"],
    "typing-extensions": ["typing_extensions"], "attrs": ["attr", "attrs"], "setuptools": ["setuptools", "pkg_resources"],
    "python-json-logger": ["pythonjsonlogger"], "pynacl": ["nacl"], "pyopenssl": ["OpenSSL"],
    "python-multipart": ["multipart"], "zope-interface": ["zope.interface", "zope"], "zope-sqlalchemy": ["zope.sqlalchemy"],
    "zope-deprecation": ["zope.deprecation"], "pyramid-jinja2": ["pyramid_jinja2"], "sqlalchemy-utils": ["sqlalchemy_utils"],
    "email-validator": ["email_validator"], "python-magic": ["magic"], "readme-renderer": ["readme_renderer"],
    "webauthn": ["webauthn"], "b2sdk": ["b2sdk"], "pymacaroons": ["pymacaroons"], "sentry-sdk": ["sentry_sdk"],
    "opensearch-py": ["opensearchpy"], "elasticsearch-dsl": ["elasticsearch_dsl"], "pip-api": ["pip_api"],
    "rfc3986": ["rfc3986"], "pyparsing": ["pyparsing"], "importlib-metadata": ["importlib_metadata"],
    "importlib-resources": ["importlib_resources"], "charset-normalizer": ["charset_normalizer"],
    "ua-parser": ["ua_parser"], "user-agents": ["user_agents"], "argon2-cffi": ["argon2"],
    "argon2-cffi-bindings": ["_argon2_cffi_bindings"], "cffi": ["cffi", "_cffi_backend"],
    "markupsafe": ["markupsafe"], "jinja2": ["jinja2"], "werkzeug": ["werkzeug"], "flask-babel": ["flask_babel"],
    "flask-sqlalchemy": ["flask_sqlalchemy"], "flask-wtf": ["flask_wtf"], "flask-assets": ["flask_assets"],
    "wtforms": ["wtforms"], "celery-redbeat": ["redbeat"], "hiredis": ["hiredis"], "pretty-bad-protocol": ["pretty_bad_protocol"], "python-gnupg": ["gnupg"],
    "redis": ["redis"], "rq": ["rq"], "mod-wsgi": ["mod_wsgi"],
}
# Packages loaded implicitly by a framework/library the app does import: module prefix -> dists.
IMPLIED_BY_MODULE: dict[str, tuple[str, ...]] = {
    "django.db.backends.postgresql": ("psycopg", "psycopg2", "psycopg2-binary", "psycopg-binary", "psycopg-c"),
    "django": ("tzdata", "sqlparse", "asgiref"),       # zoneinfo data / Django's own runtime deps
    "zoneinfo": ("tzdata",),
    "redis": ("hiredis",),                             # redis-py auto-selects the hiredis parser
    "requests": ("urllib3", "idna", "certifi", "charset-normalizer"),
    # library install_requires that `# via` annotations miss on older, un-annotated manifests
    "paramiko": ("ecdsa", "pycrypto", "pycryptodome", "cryptography", "bcrypt", "pynacl", "pyasn1"),
    "ncclient": ("lxml", "paramiko", "six"),
    "readme_renderer": ("bleach", "docutils", "pygments"),
    "alembic": ("mako", "sqlalchemy"),
    "rsa": ("pyasn1",),
}
# Source tokens that make a framework load a package lazily: token -> dists.
IMPLIED_BY_TOKEN: dict[str, tuple[str, ...]] = {
    "ImageField": ("pillow",),   # Django validates ImageField uploads with Pillow
}


def _token_hits(src_dirs: list[Path]) -> set[str]:
    hits: set[str] = set()
    for d in src_dirs:
        files = [d] if d.is_file() else (d.rglob("*.py") if d.is_dir() else [])
        for p in files:
            try:
                txt = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            hits |= {t for t in IMPLIED_BY_TOKEN if t in txt}
            if len(hits) == len(IMPLIED_BY_TOKEN):
                return hits
    return hits
ENTRYPOINT_FILES = ("Dockerfile", "Procfile", "*.sh", "*.ini", "*.cfg", "*.toml", "*.yml", "*.yaml",
                    "*.conf", "gunicorn*.py", "uwsgi*")
_DOTTED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")


def import_names(dist: str) -> list[str]:
    """Top-level import names a distribution provides."""
    n = normalize_name(dist)
    if n in KNOWN_IMPORTS:
        return KNOWN_IMPORTS[n]
    guesses = [n.replace("-", "_")]
    for pre in ("python-", "py-", "django-", "flask-", "pyramid-"):
        if n.startswith(pre) and len(n) > len(pre) + 2:
            guesses.append(n[len(pre):].replace("-", "_"))
    if n.endswith("-binary"):
        guesses.append(n[:-7].replace("-", "_"))
    parts = n.split("-")
    if len(parts) > 1:  # namespace packages: google-cloud-storage -> google.cloud.storage
        guesses.append(".".join(parts))
        guesses.append(parts[0] + "." + "_".join(parts[1:]))
        if len(parts) > 2:
            guesses.append(".".join(parts[:2]) + "." + "_".join(parts[2:]))
    return guesses


_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,}$")


def app_imports(src_dirs: list[Path], strings: set[str] | None = None) -> set[str]:
    """Module paths (full dotted + every prefix) imported by, or named as dotted strings in, the sources.

    If `strings` is given it is filled with bare identifier-like string constants
    (e.g. passlib schemes "argon2", "bcrypt") - weaker evidence, reported separately.
    """
    mods: set[str] = set()

    def add(dotted: str) -> None:
        parts = dotted.split(".")
        for i in range(1, len(parts) + 1):
            mods.add(".".join(parts[:i]))

    for d in src_dirs:
        for py in d.rglob("*.py"):
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
            except (SyntaxError, ValueError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        add(a.name)
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    add(node.module)
                    for a in node.names:  # `from google.cloud import bigquery`
                        if a.name != "*":
                            add(f"{node.module}.{a.name}")
                elif isinstance(node, ast.Constant) and isinstance(node.value, str) and _DOTTED.match(node.value):
                    add(node.value)
                elif (strings is not None and isinstance(node, ast.Constant) and isinstance(node.value, str)
                      and _IDENT.match(node.value)):
                    strings.add(node.value.lower())
                elif (isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", ""))
                      in ("import_module", "__import__", "include") and node.args
                      and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                    add(node.args[0].value)
    return mods


def entrypoint_text(repo: Path) -> str:
    """Text of the files that can name plugins or entry points (settings, setup.cfg, ...)."""
    chunks = []
    for pat in ENTRYPOINT_FILES:
        for p in repo.rglob(pat):
            if p.is_file() and p.stat().st_size < 2_000_000 and ".git" not in p.parts:
                chunks.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks).lower()


def via_graph(req_text: str) -> dict[str, set[str]]:
    """pip-compile annotations -> {package: set(packages that require it)}.

    Reads both layouts: `# via a` / `#   b` lines after the pin (pip-tools >= 5) and the older
    inline form on the pin line itself (`pyyaml==3.11    # via pymlconf, other`)."""
    pin = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==")
    out: dict[str, set[str]] = {}
    cur = None
    in_via = False
    for raw in req_text.splitlines():
        m = pin.match(raw)
        if m:
            cur, in_via = normalize_name(m.group(1)), False
            out.setdefault(cur, set())
            _, hash_, comment = raw.partition("#")
            comment = comment.strip()
            if hash_ and comment.startswith("via "):
                for parent in comment[4:].split(","):
                    tok = parent.strip().split()
                    if tok and not tok[0].startswith(("-r", "(")):
                        out[cur].add(normalize_name(tok[0]))
            continue
        s = raw.strip()
        if cur is None or not s.startswith("#"):
            continue
        body = s.lstrip("#").strip()
        if body.startswith("via"):
            in_via = True
            body = body[3:].strip()
        if in_via and body and not body.startswith("-r") and not body.startswith("("):
            out[cur].add(normalize_name(body.split()[0]))
    return out


@dataclass
class ReachReport:
    """Per-distribution reachability status of one repository snapshot."""
    status: dict[str, str] = field(default_factory=dict)  # imported|entrypoint|referenced|transitive|unreached|unknown
    evidence: dict[str, str] = field(default_factory=dict)

    def reachable(self, dist: str) -> bool | None:
        """True if imported or loaded, False if unreached, None if unknown."""
        s = self.status.get(normalize_name(dist))
        return None if s in (None, "unknown") else s != "unreached"


def static_reachability(pins: dict[str, str], src_dirs: list[Path], repo: Path,
                        req_text: str = "", mods: set[str] | None = None,
                        ep: str | None = None, strings: set[str] | None = None) -> ReachReport:
    """`mods` / `ep` / `strings` may be passed pre-computed when analysing many snapshots of one repo."""
    if mods is None:
        strings = set()
        mods = app_imports(src_dirs, strings)
    strings = strings or set()
    ep = entrypoint_text(repo) if ep is None else ep
    rep = ReachReport()
    for dist in pins:
        hit = next((m for m in import_names(dist) if m in mods), None)
        if hit:
            rep.status[dist], rep.evidence[dist] = "imported", f"module '{hit}' imported by app sources"
        elif re.search(rf"(?<![a-z0-9_-]){re.escape(dist)}(?![a-z0-9_-])", ep) or any(
                re.search(rf"(?<![a-z0-9_]){re.escape(m.lower())}(?![a-z0-9_])", ep) for m in import_names(dist)):
            rep.status[dist], rep.evidence[dist] = "entrypoint", "named in Dockerfile/Procfile/scripts/config"
    via = via_graph(req_text) if req_text else {}

    def propagate() -> None:
        changed = True
        while changed:  # fixed point over the dependency graph
            changed = False
            for dist in pins:
                if dist in rep.status:
                    continue
                parents = [p for p in via.get(dist, ()) if p in rep.status and rep.status[p] != "unreached"]
                if parents:
                    rep.status[dist], rep.evidence[dist] = "transitive", f"required by reachable {sorted(parents)[0]}"
                    changed = True

    for tok in _token_hits(src_dirs):
        for d in IMPLIED_BY_TOKEN[tok]:
            if d in pins and d not in rep.status:
                rep.status[d], rep.evidence[d] = "transitive", f"loaded lazily for '{tok}' in app sources"
    for prefix, dists in IMPLIED_BY_MODULE.items():
        if prefix in mods or any(m in mods for m in import_names(prefix)) or (
                prefix in rep.status and rep.status[prefix] != "unreached"):
            for d in dists:
                if d in pins and d not in rep.status:
                    rep.status[d], rep.evidence[d] = "transitive", f"loaded implicitly by '{prefix}'"
    propagate()
    # weakest evidence last: a bare string naming the module (passlib schemes, plugin names)
    for dist in pins:
        if dist not in rep.status and any("." not in m and m.lower() in strings for m in import_names(dist)):
            rep.status[dist], rep.evidence[dist] = "referenced", "module name used as a string (plugin/scheme config)"
    propagate()
    edges_known = "# via" in req_text  # pip-compile annotations, either layout
    for dist in pins:
        if dist not in rep.status:
            if edges_known:
                rep.status[dist] = "unreached"
                rep.evidence[dist] = "no import, entrypoint or reachable dependent found"
            else:
                rep.status[dist] = "unknown"
                rep.evidence[dist] = ("not imported, but the manifest records no dependency edges (no pip-compile "
                                      "`# via`), so a reachable package may require it: not downgraded")
    return rep


def reachability_facts(rep: ReachReport) -> dict[str, bool]:
    """Map each distribution to whether it is considered reachable."""
    return {d: s != "unreached" for d, s in rep.status.items() if s != "unknown"}
