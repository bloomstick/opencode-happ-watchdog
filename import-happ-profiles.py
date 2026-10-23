#!/usr/bin/env python3
"""Create profile-keyed cache entries from full Happ/xray JSON captures.

Happ can expose several distinct credentials/transports on the same host:port
(for example Luxembourg and UAE both use 82.40.63.74:443).  The watchdog's
endpoint cache can only keep one template per host:port, so this helper stores
each distinct single-server capture as:

    configs/<host>_<port>__<profileHash>.json

The watchdog reads those files as profile servers with the key
``host:port#profileHash``.  A profile is independently selectable and bannable;
an endpoint ban remains a wildcard covering every profile on that endpoint.

Capture sources
---------------
1. In Happ, open the ``...`` menu and run ``Пинг всех``.  This makes Happ
   materialize server configs in its UI/xray memory; the watchdog's ``R``
   rescan can then import the endpoint-level ones.
2. For a specific missing profile, right-click the server row and choose
   ``Копировать JSON``, then save the clipboard JSON as a file.
3. Put the JSON files in a directory (default:
   ``%TEMP%\\opencode\\happ-capture``) and run this script.

Only captures with exactly one vless/vmess/trojan server outbound are turned
into profiles.  Multi-outbound group captures are skipped because they would
duplicate the same group name across several endpoints; the watchdog's normal
alias import still records their display names.

This script never overwrites an existing cache/profile file.  Use --dry-run
first to see what would be created.
"""

import argparse
import copy
import glob
import hashlib
import json
import os
import tempfile

SERVER_PROTOS = ("vless", "vmess", "trojan")
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CAPTURES = os.path.join(os.environ.get("TEMP", "."), "opencode", "happ-capture")
DEFAULT_CACHE = os.path.join(HERE, "configs")


def load(path):
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def canonical(outbound):
    ident = {k: outbound.get(k) for k in ("protocol", "settings", "streamSettings")}
    return json.dumps(ident, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def ident_hash(outbound):
    return hashlib.sha256(canonical(outbound).encode("utf-8")).hexdigest()[:12]


def endpoints(outbound):
    settings = outbound.get("settings") or {}
    result = []
    for vnext in settings.get("vnext") or []:
        if isinstance(vnext, dict) and vnext.get("address") and vnext.get("port"):
            result.append((str(vnext["address"]), int(vnext["port"])))
    return result


def primary_outbound(cache_dir, host, port):
    path = os.path.join(cache_dir, "%s_%s.json" % (host, port))
    if not os.path.exists(path):
        return None, path
    try:
        cfg = load(path)
    except Exception:
        return None, path
    for outbound in cfg.get("outbounds") or []:
        if outbound.get("protocol") in SERVER_PROTOS and (host, port) in endpoints(outbound):
            return outbound, path
    return None, path


def write_atomic(path, obj):
    fd, tmp = tempfile.mkstemp(prefix=".profile-", suffix=".tmp", dir=os.path.dirname(path))
    os.close(fd)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def main():
    parser = argparse.ArgumentParser(description="Create profile-keyed Happ cache entries")
    parser.add_argument("--captures", default=DEFAULT_CAPTURES, help="directory with captured .json configs")
    parser.add_argument("--cache", default=DEFAULT_CACHE, help="watchdog configs directory")
    parser.add_argument("--dry-run", action="store_true", help="report changes without writing")
    args = parser.parse_args()

    if not os.path.isdir(args.cache):
        parser.error("cache directory does not exist: %s" % args.cache)
    files = sorted(glob.glob(os.path.join(args.captures, "*.json")))
    if not files:
        parser.error("no .json captures in %s" % args.captures)

    created = []
    skipped_same = 0
    skipped_exists = 0
    skipped_group = 0
    seen = set()

    for path in files:
        try:
            cfg = load(path)
        except Exception as exc:
            print("PARSE FAIL %s: %s" % (os.path.basename(path), exc))
            continue
        servers = [ob for ob in cfg.get("outbounds") or [] if ob.get("protocol") in SERVER_PROTOS]
        if len(servers) != 1:
            skipped_group += 1
            continue
        outbound = servers[0]
        eps = endpoints(outbound)
        if len(eps) != 1:
            skipped_group += 1
            continue
        host, port = eps[0]
        digest = ident_hash(outbound)
        marker = (host, port, digest)
        if marker in seen:
            continue
        seen.add(marker)

        primary, _ = primary_outbound(args.cache, host, port)
        if primary is not None and ident_hash(primary) == digest:
            skipped_same += 1
            continue

        target = os.path.join(args.cache, "%s_%s__%s.json" % (host, port, digest))
        if os.path.exists(target):
            skipped_exists += 1
            continue

        name = " ".join(str(cfg.get("remarks", "")).split())
        profile_cfg = copy.deepcopy(cfg)
        profile_cfg["outbounds"] = [copy.deepcopy(outbound)] + [
            copy.deepcopy(ob) for ob in cfg.get("outbounds") or [] if ob.get("protocol") not in SERVER_PROTOS
        ]
        profile_cfg["remarks"] = name
        profile_cfg.pop("remarksAliases", None)
        created.append((host, port, digest, name, target, profile_cfg, os.path.basename(path)))

    print(
        "create=%d skipped_same=%d skipped_exists=%d skipped_group=%d"
        % (len(created), skipped_same, skipped_exists, skipped_group)
    )
    for host, port, digest, name, target, _, source in created:
        print("%s:%s#%s  %s  (from %s)" % (host, port, digest, ascii(name), source))

    if args.dry_run:
        print("dry-run: no files changed")
        return
    for _, _, _, _, target, profile_cfg, _ in created:
        write_atomic(target, profile_cfg)
    print("created %d profile file(s)" % len(created))


if __name__ == "__main__":
    main()
