#!/usr/bin/env python3
"""
Trivy Scan Results Analyzer

This script processes JSON output from Trivy security scans, comparing findings
against a .trivyignore allowlist. It detects unignored vulnerabilities and secrets,
and identifies stale ignore rules that are no longer needed.

Usage:
    python3 check_scan_results.py --results <json_file> --ignore <ignore_file> [options]
"""

import argparse
import fnmatch
import json
import os
import sys
import urllib.request
from typing import Dict, List, Set, Tuple, Any, Optional


def load_trivy_ignores(ignore_file: str) -> Set[str]:
    """
    Load ignore patterns from a .trivyignore file.

    Args:
        ignore_file: Path to the .trivyignore file.

    Returns:
        A set of non-empty, non-comment ignore patterns.
    """
    ignores: Set[str] = set()
    if not os.path.exists(ignore_file):
        return ignores

    try:
        with open(ignore_file, "r") as f:
            for line in f:
                # Remove comments
                if "#" in line:
                    line = line.split("#", 1)[0]

                line = line.strip()

                if not line:
                    continue
                ignores.add(line)
    except IOError as e:
        print(
            f"Warning: Failed to read ignore file {ignore_file}: {e}", file=sys.stderr
        )

    return ignores


def analyze_trivy_results(
    data: Dict[str, Any], ignores: Set[str]
) -> Tuple[List[str], Set[str]]:
    """
    Analyze Trivy JSON results against the ignore list.

    Args:
        data: Parsed JSON data from Trivy output.
        ignores: Set of ignore patterns.

    Returns:
        A tuple containing:
        - List of unignored finding strings (vulnerabilities and secrets).
        - Set of used ignore patterns.
    """
    unignored_findings: List[str] = []
    used_ignores: Set[str] = set()

    results = data.get("Results", [])
    if not results:
        return unignored_findings, used_ignores

    for result in results:
        target = result.get("Target", "unknown")

        # Process Vulnerabilities
        vulnerabilities = result.get("Vulnerabilities", [])
        for vuln in vulnerabilities:
            vuln_id = vuln.get("VulnerabilityID")
            pkg_name = vuln.get("PkgName", "unknown")
            title = vuln.get("Title", "No title")

            if vuln_id:
                if vuln_id in ignores:
                    used_ignores.add(vuln_id)
                else:
                    unignored_findings.append(f"[VULN] {vuln_id} ({pkg_name}): {title}")

        # Process Secrets
        secrets = result.get("Secrets", [])
        for secret in secrets:
            rule_id = secret.get("RuleID")
            title = secret.get("Title", "No title")
            # For secrets, the target is usually the file path in the container/fs
            secret_file = target

            is_ignored = False

            # Check exact rule ID match
            if rule_id and rule_id in ignores:
                used_ignores.add(rule_id)
                is_ignored = True

            # Check file path patterns
            if not is_ignored:
                for pattern in ignores:
                    # Skip vulnerability IDs when checking file patterns
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


def send_discord_notification(
    webhook_url: str, image_name: str, version: str, stale_ignores: Set[str]
) -> Tuple[int, str]:
    """
    Send a Discord notification reporting stale ignore rules.
    If the message exceeds Discord's 2000-character limit, it splits it into multiple messages.

    Args:
        webhook_url: The Discord webhook URL.
        image_name: Name of the scanned image.
        version: Version/tag of the scanned image.
        stale_ignores: Set of ignore rules that were not encountered.

    Returns:
        Tuple of (HTTP status code, reason phrase) of the last sent message.

    Raises:
        urllib.error.URLError: If a request fails.
    """
    sorted_stale = sorted(stale_ignores)
    header = (
        f"\n**Security Update: {image_name}:{version}**\n\n"
        f"The following Trivy ignores are no longer detected and can be removed from `.trivyignore`:\n"
    )

    # Discord limit is 2000. We use 1900 to be safe and account for "Part X/Y" suffix.
    max_length = 1900

    chunks: List[List[str]] = []
    current_chunk_items: List[str] = []
    current_length = len(header)

    for item in sorted_stale:
        line = f"- `{item}`\n"
        line_length = len(line)

        if current_length + line_length > max_length:
            # Chunk full, save it
            chunks.append(current_chunk_items)
            current_chunk_items = [line]
            current_length = len(header) + line_length
        else:
            current_chunk_items.append(line)
            current_length += line_length

    if current_chunk_items:
        chunks.append(current_chunk_items)

    total_chunks = len(chunks)
    last_status = (200, "OK")

    for i, chunk_items in enumerate(chunks, 1):
        content = header + "".join(chunk_items)

        if total_chunks > 1:
            content += f"\n**(Part {i}/{total_chunks})**"

        message = {
            "username": "Trivy Scanner",
            "content": content,
        }

        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(message).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Homelab-CI-Trivy-Check/1.0",
            },
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            last_status = (response.status, response.reason)

    return last_status


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Trivy scan results and validate ignore rules.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--results", required=True, help="Path to trivy results JSON file"
    )
    parser.add_argument("--ignore", required=True, help="Path to .trivyignore file")
    parser.add_argument(
        "--webhook", help="Discord webhook URL for notifications", default=None
    )
    parser.add_argument("--image", help="Image name context", default="Unknown Image")
    parser.add_argument("--version", help="Image version/tag context", default=None)

    args = parser.parse_args()

    if args.version is None:
        if ":" in args.image:
            args.version = args.image.rsplit(":", 1)[1][:12]
        else:
            args.version = "latest"
    image_parts = args.image.rsplit(":", 1)[0] if ":" in args.image else args.image
    args.image = image_parts.rsplit("/", 1)[-1] if "/" in image_parts else image_parts

    json_file: str = args.results
    ignore_file: str = args.ignore

    # 1. Load ignores
    ignores = load_trivy_ignores(ignore_file)
    print(f"Loaded {len(ignores)} ignores from {ignore_file}")

    # 2. Parse results
    try:
        with open(json_file, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Results file not found: {json_file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in results file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading results: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Analyze
    unignored_findings, used_ignores = analyze_trivy_results(data, ignores)

    # 4. Report Failures
    exit_code = 0
    if unignored_findings:
        print("\n[FAILURE] Unignored High/Critical findings detected:")
        for issue in unignored_findings:
            print(f"  {issue}")
        exit_code = 1
    else:
        print("\n[SUCCESS] No unignored vulnerabilities found.")

    # 5. Report Stale Ignores
    stale_ignores = ignores - used_ignores
    if stale_ignores:
        print(
            "\n[STALE IGNORES] The following ignores are no longer detected and can be removed:"
        )
        for item in sorted(stale_ignores):
            print(f"  - {item}")

        webhook_url: Optional[str] = args.webhook
        if webhook_url:
            print("Sending Discord notification for stale ignores...")
            try:
                status, reason = send_discord_notification(
                    webhook_url, args.image, args.version, stale_ignores
                )
                print(f"Notification sent: {status} {reason}")
            except Exception as e:
                print(f"Failed to send Discord notification: {e}", file=sys.stderr)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
