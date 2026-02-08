#!/usr/bin/env python3
"""
Discord Notification Script for Container Pushes

This script sends a formatted Discord notification with details about a newly pushed
container image, including its tag and digest.

Usage:
    python3 notify_push.py <image_name> <tag> <digest> [--webhook <url>]
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from typing import Dict, Optional, Tuple


def format_push_message(image_name: str, tag: str, digest: str) -> Dict[str, str]:
    """
    Format the Discord message for a pushed image.

    Args:
        image_name: The name of the container image.
        tag: The tag of the image (e.g., 'latest', 'v1.0.0').
        digest: The SHA256 digest of the image manifest.

    Returns:
        A dictionary payload suitable for a Discord webhook.
    """
    content = (
        f"**New Image Pushed**\n"
        f"**Image:** `{image_name}`\n"
        f"**Tag:** `{tag}`\n"
        f"**Digest:** `{digest}`\n"
        f"\nUpdate your manifests to use this secure pinning!"
    )
    return {"username": "Container Factory", "content": content}


def send_discord_notification(
    webhook_url: str, message: Dict[str, str], timeout: int = 10
) -> Tuple[int, str]:
    """
    Send a message to a Discord webhook.

    Args:
        webhook_url: The Discord webhook URL.
        message: The JSON payload to send.
        timeout: Request timeout in seconds (default: 10).

    Returns:
        A tuple containing (status_code, reason_phrase).

    Raises:
        urllib.error.URLError: If the request fails (network error, timeout).
        urllib.error.HTTPError: If the server returns 4xx/5xx (though this is a subclass of URLError,
                                it has code/reason attributes).
    """
    if not webhook_url:
        raise ValueError("Webhook URL cannot be empty")

    payload = json.dumps(message).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Homelab-CI-Notify/1.0",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.status, response.reason


def main():
    parser = argparse.ArgumentParser(
        description="Send Discord notification for pushed container image.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("image_name", help="Name of the container image")
    parser.add_argument("tag", help="Tag of the container image")
    parser.add_argument("digest", help="SHA256 digest of the image")
    parser.add_argument(
        "--webhook",
        help="Discord webhook URL (optional, skips notification if missing)",
        default=None,
    )

    args = parser.parse_args()

    webhook_url: Optional[str] = args.webhook

    if not webhook_url:
        print("Skipping notification: --webhook not provided.")
        sys.exit(0)

    print(f"Sending Discord notification for {args.image_name}:{args.tag}...")

    message = format_push_message(args.image_name, args.tag, args.digest)

    try:
        status, reason = send_discord_notification(webhook_url, message)
        print(f"Notification sent successfully: {status} {reason}")
    except urllib.error.HTTPError as e:
        print(f"Failed to send notification: HTTP {e.code} {e.reason}", file=sys.stderr)
        # No CI pipeline failed if notification failed
        sys.exit(0)
    except urllib.error.URLError as e:
        print(
            f"Failed to send notification: Connection error: {e.reason}",
            file=sys.stderr,
        )
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
