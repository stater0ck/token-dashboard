"""Integrity pinning for vendored web assets.

`web/vendor.lock.json` records the exact bytes we ship for every third-party
file under `web/`. The dashboard renders your prompt history, so an unreviewed
change to a 1 MB minified bundle it loads is worth catching: a `git pull` that
swaps the file, or a half-finished manual upgrade, fails loudly instead of
being served into the page.

Two enforcement points, both cheap:
  * `check()` runs the first time the server serves a locked path.
  * `tests/test_hardening.py` asserts the same digests offline.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

LOCK_PATH = Path(__file__).resolve().parent.parent / "web" / "vendor.lock.json"

# rel -> (mtime, size, digest). Keyed on stat so an edited file is re-hashed
# rather than trusted from a stale entry.
_digest_cache: Dict[str, Tuple[float, int, str]] = {}
_lock_cache: Dict[str, dict] = {}

MISMATCH = (
    "{rel} does not match the digest pinned in web/vendor.lock.json.\n"
    "  pinned sha256 {expected}\n"
    "  actual sha256 {actual}\n"
    "Refusing to serve it. If you changed this asset on purpose, verify the new "
    "bytes against the upstream URL in the lock file, then update sha256 and bytes."
)


def load_lock(path: Optional[Union[str, Path]] = None) -> Dict[str, dict]:
    """Return {relative_path: entry} from the lock file, or {} if absent."""
    p = Path(path or LOCK_PATH)
    key = str(p)
    if key not in _lock_cache:
        if not p.is_file():
            _lock_cache[key] = {}
        else:
            data = json.loads(p.read_text(encoding="utf-8"))
            assets = data.get("assets") or {}
            _lock_cache[key] = assets if isinstance(assets, dict) else {}
    return _lock_cache[key]


def sha256_of(path: Union[str, Path]) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check(rel: str, file_path: Union[str, Path]) -> Optional[str]:
    """Return an error message if `rel` is pinned and its bytes don't match.

    Returns None for unpinned paths (every first-party file under `web/`) and
    for pinned files that verify, so static serving stays on the fast path.
    """
    entry = load_lock().get(rel)
    expected = (entry or {}).get("sha256")
    if not expected:
        return None
    p = Path(file_path)
    try:
        stat = p.stat()
    except OSError:
        return None
    cached = _digest_cache.get(rel)
    if cached and cached[0] == stat.st_mtime and cached[1] == stat.st_size:
        actual = cached[2]
    else:
        actual = sha256_of(p)
        _digest_cache[rel] = (stat.st_mtime, stat.st_size, actual)
    if actual == expected:
        return None
    return MISMATCH.format(rel=rel, expected=expected, actual=actual)


def verify_all(web_root: Optional[Union[str, Path]] = None) -> Dict[str, str]:
    """Check every pinned asset. Returns {rel: error} for the ones that fail."""
    root = Path(web_root or (LOCK_PATH.parent))
    errors = {}
    for rel in load_lock():
        p = root / rel
        if not p.is_file():
            errors[rel] = f"{rel} is pinned in web/vendor.lock.json but missing from {root}"
            continue
        err = check(rel, p)
        if err:
            errors[rel] = err
    return errors
