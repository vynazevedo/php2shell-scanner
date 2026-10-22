#!/usr/bin/env python3
"""Evidence-based PHP2Shell assessment. Python 3.10+, standard library only."""
import argparse
import concurrent.futures
import datetime
import hashlib
import http.client
import json
import re
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

FIXED = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
ADVISORIES = {
    "CVE-2026-109618": "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "CVE-2026-109619": "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
}
INI_KEYS = ("memory_limit", "post_max_size", "upload_max_filesize", "max_input_vars",
            "enable_post_data_reading", "session.upload_progress.enabled", "fatal_error_backtraces")
PHP_CODE = 'echo json_encode(["version"=>PHP_VERSION,"sapi"=>PHP_SAPI,"ini"=>array_intersect_key(ini_get_all(null,false),array_flip(' + json.dumps(list(INI_KEYS)) + '))]);'
LIMITATIONS = [
    "Version correspondence is not proof of exploitation or absence of vendor backports.",
    "CLI version and INI settings do not establish effective web runtime configuration.",
    "HTTP banners can be forged, cached, hidden or supplied by a proxy.",
    "Imported evidence is operator supplied; its origin is not authenticated by this tool.",
    "Hashes detect content changes, not authenticity or patch provenance.",
    "No exploit is attempted; exploitation remains not tested for every result.",
]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def classify(version):
    if not isinstance(version, str):
        return "unknown"
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(.*)", version.strip())
    if not match:
        return "unknown"
    if any(len(v) > 1 and v.startswith("0") for v in match.group(1, 2, 3)):
        return "unknown"
    major, minor, patch = map(int, match.group(1, 2, 3))
    suffix = match.group(4)
    if suffix and not re.fullmatch(r"[-+][A-Za-z0-9.+~_-]+", suffix):
        return "unknown"
    if re.search(r"(?:dev|alpha|beta|RC|preview)", suffix, re.I):
        return "unknown"
    branch = f"{major}.{minor}"
    if branch not in FIXED:
        return "legacy_unassessed" if (major, minor) < (8, 2) else "unknown"
    if suffix:
        return "vendor_build_review"
    return "affected_range" if patch < FIXED[branch] else "fixed_range"


def result(target, method, evidence, error=None):
    version = evidence.get("version")
    state = classify(version)
    notes = []
    ini = evidence.get("ini", {})
    if isinstance(ini, dict):
        if str(ini.get("session.upload_progress.enabled", "")).lower() in ("1", "on"):
            notes.append("Upload progress enabled in observed scope: a conditional lifecycle surface, not proof of a reachable CVE.")
        if str(version).startswith("8.5.") and str(ini.get("fatal_error_backtraces", "")).lower() in ("1", "on"):
            notes.append("PHP 8.5 fatal backtraces enabled in observed scope: review effective web settings and patch.")
    scope = "http_banner" if method == "http_head" else "cli_only"
    return {"target": target, "method": method, "scope": scope,
            "version_status": state, "exploitability": "not_tested",
            "cves": {c: {"version_status": state, "exploitability": "not_tested"} for c in ADVISORIES},
            "evidence": evidence, "evidence_sha256": digest(evidence), "error": error,
            "observations": notes,
            "next_steps": ["Verify the effective web runtime and vendor patch provenance for both CVEs.",
                           "Install the complete upstream fixes or a vendor-confirmed backport; restart every worker.",
                           "Repeat inventory across all replicas and verify deployed image digests and effective web runtime."]}


def validate_url(url):
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError("URL contains whitespace/control characters")
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username is not None or p.password is not None or p.fragment or p.query:
        raise ValueError("Use explicit http(s) URLs without credentials, query or fragment")
    _ = p.port
    return p


def remote(url, timeout):
    conn = None
    try:
        p = validate_url(url)
        cls = http.client.HTTPSConnection if p.scheme == "https" else http.client.HTTPConnection
        kwargs = {"timeout": timeout}
        if p.scheme == "https":
            kwargs["context"] = ssl.create_default_context()
        conn = cls(p.hostname, p.port, **kwargs)
        conn.request("HEAD", p.path or "/", headers={"User-Agent": "php2shell-evidence/1.0", "Connection": "close"})
        response = conn.getresponse()
        headers = response.getheaders()
        versions = sorted(set(v for k, value in headers if k.lower() in ("server", "x-powered-by")
                              for v in re.findall(r"PHP/([^\s;,()]+)", value, re.I)))
        evidence = {"http_status": response.status, "version": versions[0] if len(versions) == 1 else None,
                    "version_candidates": versions, "redirect_followed": False,
                    "proxy_signal": any(k.lower() in ("via", "cf-ray", "x-cache") for k, _ in headers)}
        if len(versions) > 1:
            evidence["conflict"] = "Multiple PHP version claims; cannot select a runtime"
        return result(url, "http_head", evidence)
    except (ValueError, OSError, http.client.HTTPException) as exc:
        return result(url, "http_head", {}, type(exc).__name__)
    finally:
        if conn:
            conn.close()


def command_json(argv, timeout=30):
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=True)
    return json.loads(proc.stdout)


def runtime_evidence(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("version"), str) or not isinstance(raw.get("ini", {}), dict):
        raise ValueError("Malformed runtime evidence")
    return {"version": raw["version"], "sapi": raw.get("sapi"),
            "ini": {key: raw["ini"][key] for key in INI_KEYS if key in raw.get("ini", {})}}


def local(binary):
    try:
        return result("local-cli", "local_cli", runtime_evidence(command_json([binary, "-r", PHP_CODE])))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return result("local-cli", "local_cli", {}, type(exc).__name__)


def imported(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("pods"), list) or not data["pods"]:
        raise ValueError("Inventory must contain a nonempty pods list")
    output = []
    for index, pod in enumerate(data["pods"]):
        target = f"imported-pod-{index}"
        try:
            if not isinstance(pod, dict):
                raise ValueError("Invalid pod")
            target = str(pod.get("uid") or pod.get("name") or target)
            evidence = runtime_evidence(pod.get("runtime_cli"))
            evidence["artifact"] = {k: pod[k] for k in ("image", "image_id", "binary_sha256", "apache_modules") if k in pod}
            output.append(result(target, "imported_inventory", evidence))
        except (ValueError, TypeError) as exc:
            output.append(result(target, "imported_inventory", {}, type(exc).__name__))
    return output


def kubernetes(context, namespace, selector, container):
    base = ["kubectl", "--context", context, "--request-timeout=20s", "-n", namespace]
    pods = command_json(base + ["get", "pods", "-l", selector, "-o", "json"]).get("items", [])
    if not pods:
        raise ValueError("No matching pods")
    output = []
    for index, pod in enumerate(pods):
        name = f"unknown-pod-{index}"
        try:
            name = pod["metadata"]["name"]
            spec = next(c for c in pod["spec"]["containers"] if c["name"] == container)
            raw = command_json(base + ["exec", name, "-c", container, "--", "php", "-r", PHP_CODE])
            evidence = runtime_evidence(raw)
            status = next((s for s in pod.get("status", {}).get("containerStatuses", []) if s["name"] == container), {})
            evidence["artifact"] = {"image": spec["image"], "image_id": status.get("imageID"), "pod_uid": pod["metadata"]["uid"]}
            output.append(result(f"{context}/{namespace}/{name}/{container}", "kubectl_cli", evidence))
        except (KeyError, TypeError, StopIteration, OSError, ValueError, subprocess.SubprocessError) as exc:
            output.append(result(f"{context}/{namespace}/{name}/{container}", "kubectl_cli", {}, type(exc).__name__))
    return output


def exit_status(results):
    if any(r["version_status"] in ("affected_range", "legacy_unassessed") for r in results):
        return 1
    if not results or any(r["error"] or r["version_status"] != "fixed_range" or r["method"] != "local_cli" for r in results):
        return 2
    return 0  # Only the explicitly measured local CLI version range; NOT web security.


def compare(previous, current):
    def indexed(report):
        if not isinstance(report, dict) or not isinstance(report.get("results"), list):
            raise ValueError("Invalid comparison report")
        records = report["results"]
        if any(not isinstance(r, dict) or not isinstance(r.get("target"), str)
               or not isinstance(r.get("evidence"), dict) or "version_status" not in r for r in records):
            raise ValueError("Invalid comparison record")
        mapped = {r["target"]: r for r in records}
        if len(mapped) != len(records):
            raise ValueError("Duplicate target identities prevent comparison")
        return mapped
    before, after = indexed(previous), indexed(current)
    return [{"target": key, "before": before.get(key, {}).get("version_status"),
             "after": after.get(key, {}).get("version_status"),
             "evidence_changed": digest(before.get(key, {}).get("evidence")) != digest(after.get(key, {}).get("evidence"))}
            for key in sorted(before.keys() | after.keys())]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="*")
    parser.add_argument("--targets-file", type=Path)
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--php-binary", default="php")
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--kubernetes", action="store_true")
    for name in ("context", "namespace", "selector", "container"):
        parser.add_argument("--" + name)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args(argv)
    if not 1 <= args.workers <= 16 or not 0 < args.timeout <= 60:
        parser.error("workers must be 1..16 and timeout >0..60")
    if args.kubernetes and not all((args.context, args.namespace, args.selector, args.container)):
        parser.error("Kubernetes requires explicit context, namespace, selector and container")
    try:
        targets = list(args.targets)
        if args.targets_file:
            targets += [line.strip() for line in args.targets_file.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]
        targets = list(dict.fromkeys(targets))
        for url in targets:
            validate_url(url)
        if not (targets or args.local or args.inventory or args.kubernetes):
            parser.error("Select at least one collection mode")
        results = []
        if targets:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
                results += list(pool.map(lambda url: remote(url, args.timeout), targets))
        if args.local:
            results.append(local(args.php_binary))
        if args.inventory:
            try:
                results += imported(args.inventory)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                results.append(result("inventory-source", "imported_inventory", {}, type(exc).__name__))
        if args.kubernetes:
            try:
                results += kubernetes(args.context, args.namespace, args.selector, args.container)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
                results.append(result("kubernetes-source", "kubectl_cli", {}, type(exc).__name__))
        report = {"schema_version": 1, "tool_version": "1.0.0", "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "advisory_reviewed": "2026-10-22", "advisories": ADVISORIES, "fixed_versions": FIXED,
                  "limitations": LIMITATIONS, "results": results, "exit_code": exit_status(results)}
        if args.compare:
            report["comparison"] = compare(json.loads(args.compare.read_text()), report)
        report["report_sha256"] = digest(report)
        serialized = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(serialized)
        print(serialized, end="")
        return report["exit_code"]
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"error": type(exc).__name__, "assessment": "inconclusive", "exit_code": 2}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
