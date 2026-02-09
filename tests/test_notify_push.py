import pytest
from unittest.mock import patch, MagicMock
from notify_push import format_push_message, send_discord_notification


class TestFormatPushMessage:
    def test_basic_format(self):
        result = format_push_message(
            "nexus.example.com/app/service", "v1.0.0", "sha256:abc123"
        )

        assert result["username"] == "Container Factory"
        assert "embeds" in result
        embed = result["embeds"][0]
        assert embed["title"] == "New Image Pushed"

        fields = {f["name"]: f["value"] for f in embed["fields"]}
        assert "`nexus.example.com/app/service`" == fields["Image"]
        assert "`v1.0.0`" == fields["Tag"]
        assert "`sha256:abc123`" == fields["Digest"]

    def test_special_characters_in_image_name(self):
        result = format_push_message(
            "registry.io/namespace/app-name_v2", "latest", "sha256:12345"
        )
        embed = result["embeds"][0]
        fields = {f["name"]: f["value"] for f in embed["fields"]}
        assert "`registry.io/namespace/app-name_v2`" == fields["Image"]

    def test_long_digest_truncation(self):
        long_digest = "sha256:" + "a" * 200
        result = format_push_message("image", "tag", long_digest)
        embed = result["embeds"][0]
        fields = {f["name"]: f["value"] for f in embed["fields"]}

        assert "..." in fields["Digest"]
        assert len(fields["Digest"]) < 200


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
        assert "embeds" in message
        assert isinstance(message["embeds"], list)
        assert len(message["embeds"]) == 1
        assert "color" in message["embeds"][0]
