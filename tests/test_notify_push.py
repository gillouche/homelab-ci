import pytest
from unittest.mock import patch, MagicMock
from notify_push import format_push_message, send_discord_notification


class TestFormatPushMessage:
    def test_basic_format(self):
        result = format_push_message(
            "nexus.example.com/app/service", "v1.0.0", "sha256:abc123"
        )

        assert result["username"] == "Container Factory"
        assert "**New Image Pushed**" in result["content"]
        assert "`nexus.example.com/app/service`" in result["content"]
        assert "`v1.0.0`" in result["content"]
        assert "`sha256:abc123`" in result["content"]

    def test_contains_pinning_reminder(self):
        result = format_push_message("image", "tag", "digest")

        assert "secure pinning" in result["content"]

    def test_special_characters_in_image_name(self):
        result = format_push_message(
            "registry.io/namespace/app-name_v2", "latest", "sha256:12345"
        )

        assert "registry.io/namespace/app-name_v2" in result["content"]

    def test_long_digest(self):
        long_digest = "sha256:" + "a" * 64
        result = format_push_message("image", "tag", long_digest)

        assert long_digest in result["content"]


class TestSendDiscordNotification:
    @patch("notify_push.urllib.request.urlopen")
    def test_successful_send(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.reason = "OK"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        message = {"username": "Test", "content": "Hello"}
        status, reason = send_discord_notification("https://webhook.url", message)

        assert status == 200
        assert reason == "OK"
        mock_urlopen.assert_called_once()

    @patch("notify_push.urllib.request.urlopen")
    def test_request_format(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.reason = "OK"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        message = {"username": "Bot", "content": "Test message"}
        send_discord_notification("https://discord.com/webhook", message)

        call_args = mock_urlopen.call_args[0][0]
        assert call_args.full_url == "https://discord.com/webhook"
        assert call_args.get_header("Content-type") == "application/json"
        assert call_args.get_header("User-agent") == "Homelab-CI-Notify/1.0"

    @patch("notify_push.urllib.request.urlopen")
    def test_raises_on_network_error(self, mock_urlopen):
        mock_urlopen.side_effect = Exception("Network error")

        with pytest.raises(Exception, match="Network error"):
            send_discord_notification("https://webhook.url", {"content": "test"})


class TestIntegration:
    def test_format_and_structure(self):
        message = format_push_message(
            "nexus.homelab/docker-hosted/app/service", "2.0.0", "sha256:deadbeef"
        )

        assert isinstance(message, dict)
        assert "username" in message
        assert "content" in message
        assert isinstance(message["content"], str)
        assert len(message["content"]) < 2000
