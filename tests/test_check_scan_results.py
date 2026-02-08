from unittest.mock import patch, MagicMock
import pytest
from check_scan_results import (
    load_trivy_ignores,
    analyze_trivy_results,
    send_discord_notification,
)
import json


class TestLoadTrivyIgnores:
    def test_empty_file(self, tmp_path):
        ignore_file = tmp_path / ".trivyignore"
        ignore_file.write_text("")

        result = load_trivy_ignores(str(ignore_file))

        assert result == set()

    def test_nonexistent_file(self, tmp_path):
        result = load_trivy_ignores(str(tmp_path / "nonexistent"))

        assert result == set()

    def test_simple_cves(self, tmp_path):
        ignore_file = tmp_path / ".trivyignore"
        ignore_file.write_text("CVE-2024-1234\nCVE-2024-5678\n")

        result = load_trivy_ignores(str(ignore_file))

        assert result == {"CVE-2024-1234", "CVE-2024-5678"}

    def test_strips_comments(self, tmp_path):
        ignore_file = tmp_path / ".trivyignore"
        ignore_file.write_text(
            "CVE-2024-1234  # Some reason\nCVE-2024-5678 # Another reason\n"
        )

        result = load_trivy_ignores(str(ignore_file))

        assert result == {"CVE-2024-1234", "CVE-2024-5678"}

    def test_skips_comment_lines(self, tmp_path):
        ignore_file = tmp_path / ".trivyignore"
        ignore_file.write_text(
            "# Header comment\nCVE-2024-1234\n# Another comment\nCVE-2024-5678\n"
        )

        result = load_trivy_ignores(str(ignore_file))

        assert result == {"CVE-2024-1234", "CVE-2024-5678"}

    def test_skips_empty_lines(self, tmp_path):
        ignore_file = tmp_path / ".trivyignore"
        ignore_file.write_text("CVE-2024-1234\n\n\nCVE-2024-5678\n")

        result = load_trivy_ignores(str(ignore_file))

        assert result == {"CVE-2024-1234", "CVE-2024-5678"}

    def test_glob_patterns(self, tmp_path):
        ignore_file = tmp_path / ".trivyignore"
        ignore_file.write_text("/nix/store/**/ssh_host_*\n*.pem\n")

        result = load_trivy_ignores(str(ignore_file))

        assert result == {"/nix/store/**/ssh_host_*", "*.pem"}


class TestAnalyzeTrivyResults:
    def test_empty_results(self):
        data = {"Results": []}
        ignores = set()

        unignored, used = analyze_trivy_results(data, ignores)

        assert unignored == []
        assert used == set()

    def test_no_results_key(self):
        data = {}
        ignores = set()

        unignored, used = analyze_trivy_results(data, ignores)

        assert unignored == []
        assert used == set()

    def test_vulnerability_not_ignored(self):
        data = {
            "Results": [
                {
                    "Target": "test-image",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "openssl",
                            "Title": "Buffer overflow",
                        }
                    ],
                }
            ]
        }
        ignores = set()

        unignored, used = analyze_trivy_results(data, ignores)

        assert len(unignored) == 1
        assert "CVE-2024-1234" in unignored[0]
        assert used == set()

    def test_vulnerability_ignored(self):
        data = {
            "Results": [
                {
                    "Target": "test-image",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "openssl",
                            "Title": "Buffer overflow",
                        }
                    ],
                }
            ]
        }
        ignores = {"CVE-2024-1234"}

        unignored, used = analyze_trivy_results(data, ignores)

        assert unignored == []
        assert used == {"CVE-2024-1234"}

    def test_secret_ignored_by_rule_id(self):
        data = {
            "Results": [
                {
                    "Target": "/app/config.json",
                    "Secrets": [
                        {"RuleID": "aws-access-key", "Title": "AWS Access Key"}
                    ],
                }
            ]
        }
        ignores = {"aws-access-key"}

        unignored, used = analyze_trivy_results(data, ignores)

        assert unignored == []
        assert used == {"aws-access-key"}

    def test_secret_ignored_by_glob(self):
        data = {
            "Results": [
                {
                    "Target": "/nix/store/abc123/ssh_host_ed25519_key",
                    "Secrets": [{"RuleID": "private-key", "Title": "Private Key"}],
                }
            ]
        }
        ignores = {"/nix/store/**/ssh_host_*"}

        unignored, used = analyze_trivy_results(data, ignores)

        assert unignored == []
        assert used == {"/nix/store/**/ssh_host_*"}

    def test_stale_ignores_detected(self):
        data = {"Results": []}
        ignores = {"CVE-2024-1234", "CVE-2024-5678"}

        unignored, used = analyze_trivy_results(data, ignores)

        stale = ignores - used
        assert stale == {"CVE-2024-1234", "CVE-2024-5678"}

    def test_mixed_findings(self):
        data = {
            "Results": [
                {
                    "Target": "test-image",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1111",
                            "PkgName": "pkg1",
                            "Title": "Vuln 1",
                        },
                        {
                            "VulnerabilityID": "CVE-2024-2222",
                            "PkgName": "pkg2",
                            "Title": "Vuln 2",
                        },
                        {
                            "VulnerabilityID": "CVE-2024-3333",
                            "PkgName": "pkg3",
                            "Title": "Vuln 3",
                        },
                    ],
                }
            ]
        }
        ignores = {"CVE-2024-1111", "CVE-2024-3333", "CVE-2024-9999"}

        unignored, used = analyze_trivy_results(data, ignores)

        assert len(unignored) == 1
        assert "CVE-2024-2222" in unignored[0]
        assert used == {"CVE-2024-1111", "CVE-2024-3333"}

        stale = ignores - used
        assert stale == {"CVE-2024-9999"}


class TestEdgeCases:
    def test_ghsa_vulnerability_ids(self):
        data = {
            "Results": [
                {
                    "Target": "test-image",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "GHSA-1234-5678-abcd",
                            "PkgName": "axios",
                            "Title": "SSRF vulnerability",
                        }
                    ],
                }
            ]
        }
        ignores = {"GHSA-1234-5678-abcd"}

        unignored, used = analyze_trivy_results(data, ignores)

        assert unignored == []
        assert used == {"GHSA-1234-5678-abcd"}

    def test_rustsec_vulnerability_ids(self):
        data = {
            "Results": [
                {
                    "Target": "test-image",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "RUSTSEC-2024-0001",
                            "PkgName": "hyper",
                            "Title": "Memory leak",
                        }
                    ],
                }
            ]
        }
        ignores = {"RUSTSEC-2024-0001"}

        unignored, used = analyze_trivy_results(data, ignores)

        assert unignored == []
        assert used == {"RUSTSEC-2024-0001"}

    def test_multiple_targets(self):
        data = {
            "Results": [
                {
                    "Target": "layer1",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgName": "pkg1",
                            "Title": "Vuln 1",
                        }
                    ],
                },
                {
                    "Target": "layer2",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0002",
                            "PkgName": "pkg2",
                            "Title": "Vuln 2",
                        }
                    ],
                },
            ]
        }
        ignores = {"CVE-2024-0001"}

        unignored, used = analyze_trivy_results(data, ignores)

        assert len(unignored) == 1
        assert "CVE-2024-0002" in unignored[0]
        assert used == {"CVE-2024-0001"}

    def test_vulnerability_without_title(self):
        data = {
            "Results": [
                {
                    "Target": "test-image",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2024-0001", "PkgName": "pkg"}
                    ],
                }
            ]
        }
        ignores = set()

        unignored, used = analyze_trivy_results(data, ignores)

        assert len(unignored) == 1
        assert "CVE-2024-0001" in unignored[0]
        assert "No title" in unignored[0]

    def test_secret_not_ignored(self):
        data = {
            "Results": [
                {
                    "Target": "/app/secrets.json",
                    "Secrets": [
                        {"RuleID": "generic-api-key", "Title": "Generic API Key"}
                    ],
                }
            ]
        }
        ignores = set()

        unignored, used = analyze_trivy_results(data, ignores)

        assert len(unignored) == 1
        assert "[SECRET]" in unignored[0]
        assert "generic-api-key" in unignored[0]

    def test_basename_glob_match(self):
        data = {
            "Results": [
                {
                    "Target": "/some/path/to/key.pem",
                    "Secrets": [{"RuleID": "private-key", "Title": "Private Key"}],
                }
            ]
        }
        ignores = {"*.pem"}

        unignored, used = analyze_trivy_results(data, ignores)

        assert unignored == []
        assert used == {"*.pem"}

    def test_empty_vulnerabilities_list(self):
        data = {"Results": [{"Target": "test-image", "Vulnerabilities": []}]}
        ignores = {"CVE-2024-0001"}

        unignored, used = analyze_trivy_results(data, ignores)

        assert unignored == []
        assert used == set()

    def test_no_vulnerabilities_key(self):
        data = {"Results": [{"Target": "test-image"}]}
        ignores = set()

        unignored, used = analyze_trivy_results(data, ignores)

        assert unignored == []
        assert used == set()


class TestTrivyIgnoresFormat:
    def test_whitespace_handling(self, tmp_path):
        ignore_file = tmp_path / ".trivyignore"
        ignore_file.write_text("  CVE-2024-0001  \n\tCVE-2024-0002\t\n")

        result = load_trivy_ignores(str(ignore_file))

        assert result == {"CVE-2024-0001", "CVE-2024-0002"}

    def test_inline_comment_with_spaces(self, tmp_path):
        ignore_file = tmp_path / ".trivyignore"
        ignore_file.write_text("CVE-2024-0001   #   spaced comment  \n")

        result = load_trivy_ignores(str(ignore_file))

        assert result == {"CVE-2024-0001"}

    def test_comment_only_file(self, tmp_path):
        ignore_file = tmp_path / ".trivyignore"
        ignore_file.write_text("# Just a comment\n# Another comment\n")

        result = load_trivy_ignores(str(ignore_file))

        assert result == set()


class TestDiscordNotification:
    @patch("check_scan_results.urllib.request.urlopen")
    def test_basic_notification(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.reason = "OK"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=None)
        mock_urlopen.return_value = mock_response

        status, reason = send_discord_notification(
            "http://webhook", "image", "v1", {"CVE-1", "CVE-2"}
        )

        assert status == 200
        assert reason == "OK"
        mock_urlopen.assert_called_once()

    @patch("check_scan_results.urllib.request.urlopen")
    def test_notification_with_pagination(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.reason = "OK"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=None)
        mock_urlopen.return_value = mock_response

        # Create many ignores to force pagination
        # Each item is like "- `CVE-XXXX-YYYY`\n", approx 20 chars
        # 1900 max length -> ~90 items per chunk
        # We'll make 200 items to ensure at least 3 chunks
        many_ignores = {f"CVE-2024-{i:04d}" for i in range(200)}

        status, reason = send_discord_notification(
            "http://webhook", "image", "v1", many_ignores
        )

        assert status == 200
        assert reason == "OK"

        # Should be called multiple times (likely 3 times for 200 items)
        assert mock_urlopen.call_count >= 2

        # Verify pagination headers in calls
        calls = mock_urlopen.call_args_list
        messages = [json.loads(call[0][0].data.decode())["content"] for call in calls]

        assert "(Part 1/" in messages[0]
        assert f"(Part {len(messages)}/{len(messages)})" in messages[-1]

    @patch("check_scan_results.urllib.request.urlopen")
    def test_notification_failure(self, mock_urlopen):
        mock_urlopen.side_effect = Exception("Network error")

        with pytest.raises(Exception, match="Network error"):
            send_discord_notification("http://webhook", "image", "v1", {"CVE-1"})


class TestMainIntegration:
    @patch(
        "check_scan_results.sys.argv",
        [
            "check_scan_results.py",
            "--results",
            "trivy.json",
            "--ignore",
            ".trivyignore",
        ],
    )
    @patch("check_scan_results.load_trivy_ignores")
    @patch("check_scan_results.analyze_trivy_results")
    @patch("builtins.open", new_callable=MagicMock)
    @patch("json.load")
    def test_main_success_no_findings(
        self, mock_json_load, mock_open, mock_analyze, mock_load_ignores
    ):
        mock_load_ignores.return_value = set()
        mock_analyze.return_value = ([], set())

        with pytest.raises(SystemExit) as e:
            from check_scan_results import main

            main()

        assert e.value.code == 0

    @patch(
        "check_scan_results.sys.argv",
        [
            "check_scan_results.py",
            "--results",
            "trivy.json",
            "--ignore",
            ".trivyignore",
        ],
    )
    @patch("check_scan_results.load_trivy_ignores")
    @patch("check_scan_results.analyze_trivy_results")
    @patch("builtins.open", new_callable=MagicMock)
    @patch("json.load")
    def test_main_failure_with_findings(
        self, mock_json_load, mock_open, mock_analyze, mock_load_ignores
    ):
        mock_load_ignores.return_value = set()
        mock_analyze.return_value = (["Found CVE-123"], set())

        with pytest.raises(SystemExit) as e:
            from check_scan_results import main

            main()

        assert e.value.code == 1

    @patch(
        "check_scan_results.sys.argv",
        [
            "check_scan_results.py",
            "--results",
            "trivy.json",
            "--ignore",
            ".trivyignore",
            "--webhook",
            "http://hook",
        ],
    )
    @patch("check_scan_results.load_trivy_ignores")
    @patch("check_scan_results.analyze_trivy_results")
    @patch("builtins.open", new_callable=MagicMock)
    @patch("json.load")
    @patch("check_scan_results.send_discord_notification")
    def test_main_stale_ignores_notification(
        self, mock_notify, mock_json_load, mock_open, mock_analyze, mock_load_ignores
    ):
        # Setup: have some stale ignores
        ignores = {"CVE-1", "CVE-2"}
        mock_load_ignores.return_value = ignores
        # Analyze returns no used ignores, so all are stale
        mock_analyze.return_value = ([], set())

        with pytest.raises(SystemExit) as e:
            from check_scan_results import main

            main()

        assert e.value.code == 0
        mock_notify.assert_called_once()
