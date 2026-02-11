#!/usr/bin/env python3
import argparse
import configparser
import os
import sys


def update_config(path, section, values, is_config=False):
    """Updates or appends a section in an INI-style config file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
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
        "--credentials-path",
        default="~/.aws/credentials",
        help="Path to credentials file",
    )
    parser.add_argument(
        "--config-path", default="~/.aws/config", help="Path to config file"
    )

    args = parser.parse_args()

    creds_path = os.path.expanduser(args.credentials_path)
    config_path = os.path.expanduser(args.config_path)

    creds = {
        "aws_access_key_id": args.access_key_id,
        "aws_secret_access_key": args.secret_access_key,
    }
    conf = {"region": args.region}

    try:
        update_config(creds_path, args.profile, creds)
        update_config(config_path, args.profile, conf, is_config=True)
        print(f"Successfully configured AWS profile: {args.profile}")
    except Exception as e:
        print(f"Error configuring AWS profile: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
