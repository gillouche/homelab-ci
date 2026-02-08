#!/usr/bin/env python3

import json
import sys
import os
import argparse
import fnmatch


def load_trivy_ignores(ignore_file):
    ignores = set()
    if not os.path.exists(ignore_file):
        return ignores

    with open(ignore_file, "r") as f:
        for line in f:
            if "#" in line:
                line = line.split("#", 1)[0]

            line = line.strip()

            if not line:
                continue
            ignores.add(line)
    return ignores


def analyze_trivy_results(data, ignores):
    """
    Analyze Trivy JSON results against ignore list.
    Returns (unignored_findings, used_ignores)
    """
    unignored_findings = []
    used_ignores = set()

    results = data.get("Results", [])

    for result in results:
        target = result.get("Target", "unknown")

        vulns = result.get("Vulnerabilities", [])
        for vuln in vulns:
            vuln_id = vuln.get("VulnerabilityID")
            pkg_name = vuln.get("PkgName", "unknown")
            title = vuln.get("Title", "No title")

            if vuln_id:
                if vuln_id in ignores:
                    used_ignores.add(vuln_id)
                else:
                    unignored_findings.append(f"[VULN] {vuln_id} ({pkg_name}): {title}")

        secrets = result.get("Secrets", [])
        for secret in secrets:
            rule_id = secret.get("RuleID")
            title = secret.get("Title", "No title")
            secret_file = target

            is_ignored = False

            if rule_id and rule_id in ignores:
                used_ignores.add(rule_id)
                is_ignored = True

            if not is_ignored:
                for pattern in ignores:
                    if (
                        pattern.startswith("CVE-")
                        or pattern.startswith("GHSA-")
                        or pattern.startswith("RUSTSEC-")
                    ):
                        continue

                    if fnmatch.fnmatch(secret_file, pattern) or fnmatch.fnmatch(
                        os.path.basename(secret_file), pattern
                    ):
                        used_ignores.add(pattern)
                        is_ignored = True
                        break

            if not is_ignored:
                unignored_findings.append(
                    f"[SECRET] {rule_id} in {secret_file}: {title}"
                )

    return unignored_findings, used_ignores


def send_discord_notification(webhook_url, image_name, version, stale_ignores):
    """Send Discord notification for stale ignores."""
    import urllib.request

    sorted_stale = sorted(stale_ignores)
    message = {
        "username": "Trivy Scanner",
        "content": f"\n**Security Update: {image_name}:{version}**\n\nThe following Trivy ignores are no longer detected and can be removed from `.trivyignore`:\n"
        + "\n".join([f"- `{item}`" for item in sorted_stale]),
    }

    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(message).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Trivy-Check-Script",
        },
    )
    with urllib.request.urlopen(req) as response:
        return response.status, response.reason


def main():
    parser = argparse.ArgumentParser(description="Analyze Trivy scan results")
    parser.add_argument("results_file", help="Path to trivy results JSON file")
    parser.add_argument("ignore_file", help="Path to .trivyignore file")
    parser.add_argument("--webhook", help="Discord webhook URL", default=None)
    parser.add_argument("--image", help="Image name", default="Unknown Image")
    parser.add_argument("--version", help="Image version", default="Unknown Version")

    args = parser.parse_args()

    json_file = args.results_file
    ignore_file = args.ignore_file

    ignores = load_trivy_ignores(ignore_file)
    print(f"Loaded {len(ignores)} ignores from {ignore_file}")

    try:
        with open(json_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON results: {e}")
        sys.exit(1)

    unignored_findings, used_ignores = analyze_trivy_results(data, ignores)

    if unignored_findings:
        print("\n[FAILURE] Unignored High/Critical findings detected:")
        for issue in unignored_findings:
            print(f"  {issue}")
    else:
        print("\n[SUCCESS] No unignored vulnerabilities found.")

    stale_ignores = ignores - used_ignores

    if stale_ignores:
        print(
            "\n[STALE IGNORES] The following ignores are no longer detected and can be removed:"
        )
        sorted_stale = sorted(stale_ignores)
        for item in sorted_stale:
            print(f"  - {item}")

        webhook_url = args.webhook
        if webhook_url:
            print("Sending Discord notification for stale ignores...")
            image_context = args.image
            version_context = args.version

            try:
                status, reason = send_discord_notification(
                    webhook_url, image_context, version_context, stale_ignores
                )
                print(f"Notification sent: {status} {reason}")
            except Exception as e:
                print(f"Failed to send Discord notification: {e}")

    if unignored_findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
