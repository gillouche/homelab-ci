import os
import tempfile
import configparser
import unittest
from configure_aws_profile import update_config


class TestConfigureAWSProfile(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.creds_path = os.path.join(self.test_dir.name, "credentials")
        self.config_path = os.path.join(self.test_dir.name, "config")

    def tearDown(self):
        self.test_dir.cleanup()

    def test_new_profile_creation(self):
        profile = "test-nix"
        creds = {"aws_access_key_id": "key", "aws_secret_access_key": "secret"}

        update_config(self.creds_path, profile, creds)

        config = configparser.ConfigParser()
        config.read(self.creds_path)

        self.assertTrue(config.has_section(profile))
        self.assertEqual(config.get(profile, "aws_access_key_id"), "key")
        self.assertEqual(config.get(profile, "aws_secret_access_key"), "secret")

    def test_incremental_append(self):
        # Create first profile
        update_config(
            self.creds_path,
            "nix",
            {"aws_access_key_id": "nix-key", "aws_secret_access_key": "nix-secret"},
        )
        # Create second profile
        update_config(
            self.creds_path,
            "bazel",
            {"aws_access_key_id": "bazel-key", "aws_secret_access_key": "bazel-secret"},
        )

        config = configparser.ConfigParser()
        config.read(self.creds_path)

        self.assertTrue(config.has_section("nix"))
        self.assertTrue(config.has_section("bazel"))
        self.assertEqual(config.get("nix", "aws_access_key_id"), "nix-key")
        self.assertEqual(config.get("bazel", "aws_access_key_id"), "bazel-key")

    def test_profile_update(self):
        profile = "nix"
        update_config(
            self.creds_path,
            profile,
            {"aws_access_key_id": "old-key", "aws_secret_access_key": "old-secret"},
        )
        update_config(
            self.creds_path, profile, {"aws_access_key_id": "new-key"}
        )  # Only update key

        config = configparser.ConfigParser()
        config.read(self.creds_path)

        self.assertEqual(config.get(profile, "aws_access_key_id"), "new-key")
        self.assertEqual(config.get(profile, "aws_secret_access_key"), "old-secret")

    def test_config_profile_prefixing(self):
        profile = "nix"
        update_config(
            self.config_path, profile, {"region": "us-east-1"}, is_config=True
        )

        config = configparser.ConfigParser()
        config.read(self.config_path)

        # In ~/.aws/config, non-default profiles must be prefixed with 'profile '
        self.assertTrue(config.has_section("profile nix"))
        self.assertEqual(config.get("profile nix", "region"), "us-east-1")

    def test_default_profile_unprefixed(self):
        profile = "default"
        update_config(
            self.config_path, profile, {"region": "us-west-2"}, is_config=True
        )

        config = configparser.ConfigParser()
        config.read(self.config_path)

        self.assertTrue(config.has_section("default"))
        self.assertEqual(config.get("default", "region"), "us-west-2")


if __name__ == "__main__":
    unittest.main()
