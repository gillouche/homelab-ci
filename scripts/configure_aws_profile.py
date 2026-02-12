#!/usr/bin/env python3
import argparse
import configparser
import os
import subprocess
import sys
from io import StringIO


def update_config(path, section, values, is_config=False, use_sudo=False):
    """Updates or appends a section in an INI-style config file.

    Reads the existing file (if any), merges the new values into the
    specified section, and writes back. This is safe to call multiple
    times with different profiles — each call only touches its own section.
    """
    dir_path = os.path.dirname(path)

    if use_sudo:
        subprocess.run(["sudo", "mkdir", "-p", dir_path], check=True)
        # Read existing file via sudo if it exists
        config = configparser.ConfigParser()
        result = subprocess.run(["sudo", "cat", path], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            config.read_file(StringIO(result.stdout))
    else:
        os.makedirs(dir_path, exist_ok=True)
        config = configparser.ConfigParser()
        if os.path.exists(path):
            config.read(path)

    # For config file, sections are prefixed with 'profile ' (except default)
    sect_name = section
    if is_config and section != "default" and not section.startswith("profile "):
        sect_name = f"profile {section}"

    if not config.has_section(sect_name):
        config.add_section(sect_name)

    for k, v in values.items():
        config.set(sect_name, k, v)

    if use_sudo:
        buf = StringIO()
        config.write(buf)
        subprocess.run(
            ["sudo", "tee", path],
            input=buf.getvalue(),
            capture_output=True,
            text=True,
            check=True,
        )
    else:
        with open(path, "w") as f:
            config.write(f)


def main():
    parser = argparse.ArgumentParser(
        description="Configure AWS profile credentials and config"
    )
    parser.add_argument("--profile", required=True, help="Name of the AWS profile")
    parser.add_argument("--access-key-id", required=True, help="AWS Access Key ID")
    parser.add_argument(
        "--secret-access-key", required=True, help="AWS Secret Access Key"
    )
    parser.add_argument(
        "--region", default="us-east-1", help="AWS Region (default: us-east-1)"
    )
    parser.add_argument(
        "--mirror-to-root",
        action="store_true",
        help="Also merge the profile into /root/.aws/ (for Nix daemon)",
    )

    args = parser.parse_args()

    creds = {
        "aws_access_key_id": args.access_key_id,
        "aws_secret_access_key": args.secret_access_key,
    }

    conf = {
        "region": args.region,
        "output": "json",
    }

    try:
        # Update user's AWS files
        user_creds = os.path.expanduser("~/.aws/credentials")
        user_config = os.path.expanduser("~/.aws/config")
        update_config(user_creds, args.profile, creds)
        update_config(user_config, args.profile, conf, is_config=True)
        print(f"Successfully configured AWS profile: {args.profile}")

        # Mirror to /root/.aws/ for Nix daemon (merge, not overwrite)
        if args.mirror_to_root:
            root_creds = "/root/.aws/credentials"
            root_config = "/root/.aws/config"
            update_config(root_creds, args.profile, creds, use_sudo=True)
            update_config(
                root_config, args.profile, conf, is_config=True, use_sudo=True
            )
            print(f"Mirrored profile '{args.profile}' to /root/.aws/")

    except Exception as e:
        print(f"Error configuring AWS profile: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
