"""
Per-project settings and cache, stored in <project>/.shammah/

  .shammah/config.json   settings people edit and commit:
      {"muted_rules": ["SHAMMAH-0018"], "exclude": ["tests/**", "*.min.js"], "fail_on": "high"}
  .shammah/cache.json    scan results reused between runs (add to .gitignore)
"""
import fnmatch
import json
import os
from typing import Dict, List

DIR_NAME = ".shammah"
CONFIG_NAME = "config.json"
CACHE_NAME = "cache.json"
CACHE_VERSION = 1

DEFAULT_CONFIG = {"muted_rules": [], "exclude": [], "fail_on": "high"}


def _path(project_path: str, name: str) -> str:
    return os.path.join(project_path, DIR_NAME, name)


def load_config(project_path: str) -> Dict:
    config = dict(DEFAULT_CONFIG)
    try:
        with open(_path(project_path, CONFIG_NAME), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            config.update({k: v for k, v in data.items() if k in DEFAULT_CONFIG})
    except (OSError, ValueError):
        pass
    config["muted_rules"] = [str(r) for r in config.get("muted_rules") or []]
    config["exclude"] = [str(p) for p in config.get("exclude") or []]
    return config


def save_config(project_path: str, config: Dict) -> str:
    os.makedirs(os.path.join(project_path, DIR_NAME), exist_ok=True)
    path = _path(project_path, CONFIG_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({k: config.get(k, v) for k, v in DEFAULT_CONFIG.items()}, fh, indent=2)
        fh.write("\n")
    return path


def mute_rule(project_path: str, rule_id: str, unmute: bool = False) -> List[str]:
    config = load_config(project_path)
    muted = [r for r in config["muted_rules"] if r != rule_id]
    if not unmute:
        muted.append(rule_id)
    config["muted_rules"] = sorted(set(muted))
    save_config(project_path, config)
    return config["muted_rules"]


def is_excluded(rel_path: str, patterns: List[str]) -> bool:
    rel = rel_path.replace("\\", "/")
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(os.path.basename(rel), p) for p in patterns)


def load_cache(project_path: str) -> Dict:
    try:
        with open(_path(project_path, CACHE_NAME), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data.get("version") == CACHE_VERSION:
            data.setdefault("files", {})
            data.setdefault("osv", {})
            return data
    except (OSError, ValueError):
        pass
    return {"version": CACHE_VERSION, "files": {}, "osv": {}}


def save_cache(project_path: str, cache: Dict) -> None:
    directory = os.path.join(project_path, DIR_NAME)
    try:
        os.makedirs(directory, exist_ok=True)
        gitignore = os.path.join(directory, ".gitignore")
        if not os.path.exists(gitignore):
            with open(gitignore, "w", encoding="utf-8") as fh:
                fh.write("# Scan cache: safe to delete, don't commit\ncache.json\n")
        tmp = _path(project_path, CACHE_NAME + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
        os.replace(tmp, _path(project_path, CACHE_NAME))
    except OSError:
        pass  # a read-only checkout just means no cache
