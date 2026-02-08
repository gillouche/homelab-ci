#!/usr/bin/env python3

import json
import sys
import argparse
import urllib.request


def format_push_message(image_name: str, tag: str, digest: str) -> dict:
    """Format the Discord message for a pushed image."""
    content = (
        f"**New Image Pushed**\n"
        f"**Image:** `{image_name}`\n"
        f"**Tag:** `{tag}`\n"
        f"**Digest:** `{digest}`\n"
        f"\nUpdate your manifests to use this secure pinning!"
    )
    return {"username": "Container Factory", "content": content}


def send_discord_notification(webhook_url: str, message: dict) -> tuple[int, str]:
    """Send a message to Discord webhook. Returns (status_code, reason)."""
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(message).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Container-Factory-Notifier",
        },
    )
    with urllib.request.urlopen(req) as response:
        return response.status, response.reason


def main():
    parser = argparse.ArgumentParser(
        description="Send Discord notification for pushed image."
    )
    parser.add_argument("image_name", help="Image name")
    parser.add_argument("tag", help="Image tag")
    parser.add_argument("digest", help="Image digest")
    parser.add_argument("--webhook", help="Discord webhook URL", default=None)

    args = parser.parse_args()

    webhook_url = args.webhook
    if not webhook_url:
        print("Skipping notification: --webhook not provided.")
        sys.exit(0)

    print(f"Sending Discord notification for {args.image_name}:{args.tag}...")

    message = format_push_message(args.image_name, args.tag, args.digest)

    try:
        status, reason = send_discord_notification(webhook_url, message)
        print(f"Notification sent: {status} {reason}")
    except Exception as e:
        print(f"Failed to send Discord notification: {e}")
        sys.exit(0)


if __name__ == "__main__":
    main()
