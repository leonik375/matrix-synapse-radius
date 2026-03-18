import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

# Stub out synapse and twisted before importing the module under test
synapse_mod = ModuleType("synapse")
synapse_module_api = ModuleType("synapse.module_api")
synapse_module_api.ModuleApi = MagicMock  # type: ignore[attr-defined]
synapse_logging = ModuleType("synapse.logging")
synapse_logging_context = ModuleType("synapse.logging.context")


async def _fake_defer_to_thread(_reactor, f, *args, **kwargs):
    return f(*args, **kwargs)


synapse_logging_context.defer_to_thread = _fake_defer_to_thread  # type: ignore[attr-defined]
sys.modules["synapse"] = synapse_mod
sys.modules["synapse.module_api"] = synapse_module_api
sys.modules["synapse.logging"] = synapse_logging
sys.modules["synapse.logging.context"] = synapse_logging_context

twisted_mod = ModuleType("twisted")
twisted_internet = ModuleType("twisted.internet")
twisted_internet.reactor = MagicMock()  # type: ignore[attr-defined]
sys.modules["twisted"] = twisted_mod
sys.modules["twisted.internet"] = twisted_internet

import pyrad.packet
import pytest

from radius_auth_provider import RadiusAuthProvider, make_dictionary


BASIC_CONFIG = {
    "secret": "testing123",
    "server": "127.0.0.1",
    "port": 1812,
}


def make_provider(config_overrides=None):
    config = {**BASIC_CONFIG, **(config_overrides or {})}
    api = MagicMock()
    api.register_password_auth_provider_callbacks = MagicMock()
    api.get_qualified_user_id = MagicMock(
        side_effect=lambda lp: f"@{lp}:example.com"
    )
    api.check_user_exists = AsyncMock(return_value=True)
    api.register_user = AsyncMock(
        side_effect=lambda localpart: f"@{localpart}:example.com"
    )
    provider = RadiusAuthProvider(config, api)
    return provider, api


def make_login_dict(password="secret"):
    return {"password": password}


class TestParseConfig:
    def test_missing_secret_raises(self):
        with pytest.raises(ValueError, match="secret"):
            RadiusAuthProvider.parse_config({})

    def test_valid_config_passes(self):
        result = RadiusAuthProvider.parse_config({"secret": "s3cret"})
        assert result["secret"] == "s3cret"


class TestInit:
    def test_registers_auth_callback(self):
        provider, api = make_provider()
        api.register_password_auth_provider_callbacks.assert_called_once()

    def test_defaults(self):
        provider, _ = make_provider()
        assert provider.create_users is True
        assert provider.nas_ip == "127.0.0.1"
        assert provider._radius_timeout == 3
        assert provider._radius_retries == 1

    def test_custom_config(self):
        provider, _ = make_provider({
            "create_users": False,
            "nas_ip": "10.0.0.1",
            "timeout": 5,
            "retries": 2,
        })
        assert provider.create_users is False
        assert provider.nas_ip == "10.0.0.1"
        assert provider._radius_timeout == 5
        assert provider._radius_retries == 2


class TestCheckPassword:
    @pytest.fixture
    def provider_and_api(self):
        return make_provider()

    @pytest.fixture
    def accept_reply(self):
        reply = MagicMock()
        reply.code = pyrad.packet.AccessAccept
        return reply

    @pytest.fixture
    def reject_reply(self):
        reply = MagicMock()
        reply.code = pyrad.packet.AccessReject
        return reply

    @pytest.mark.asyncio
    async def test_successful_auth(self, provider_and_api, accept_reply):
        provider, api = provider_and_api
        with patch.object(provider, "_make_client") as mock_make:
            client = MagicMock()
            client.SendPacket.return_value = accept_reply
            mock_make.return_value = client

            result = await provider.check_password(
                "@alice:example.com", "m.login.password", make_login_dict()
            )

        assert result == ("@alice:example.com", None)
        client.CreateAuthPacket.assert_called_once()
        client.SendPacket.assert_called_once()

    @pytest.mark.asyncio
    async def test_failed_auth(self, provider_and_api, reject_reply):
        provider, api = provider_and_api
        with patch.object(provider, "_make_client") as mock_make:
            client = MagicMock()
            client.SendPacket.return_value = reject_reply
            mock_make.return_value = client

            result = await provider.check_password(
                "@alice:example.com", "m.login.password", make_login_dict()
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_missing_password(self, provider_and_api):
        provider, _ = provider_and_api
        result = await provider.check_password(
            "@alice:example.com", "m.login.password", {}
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_empty_password(self, provider_and_api):
        provider, _ = provider_and_api
        result = await provider.check_password(
            "@alice:example.com", "m.login.password", {"password": ""}
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_radius_timeout(self, provider_and_api):
        provider, _ = provider_and_api
        with patch.object(provider, "_make_client") as mock_make:
            client = MagicMock()
            client.SendPacket.side_effect = pyrad.packet.PacketError("timeout")
            mock_make.return_value = client

            result = await provider.check_password(
                "@alice:example.com", "m.login.password", make_login_dict()
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_radius_generic_exception(self, provider_and_api):
        provider, _ = provider_and_api
        with patch.object(provider, "_make_client") as mock_make:
            client = MagicMock()
            client.SendPacket.side_effect = OSError("network error")
            mock_make.return_value = client

            result = await provider.check_password(
                "@alice:example.com", "m.login.password", make_login_dict()
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_auto_create_user(self, provider_and_api, accept_reply):
        provider, api = provider_and_api
        api.check_user_exists.return_value = False

        with patch.object(provider, "_make_client") as mock_make:
            client = MagicMock()
            client.SendPacket.return_value = accept_reply
            mock_make.return_value = client

            result = await provider.check_password(
                "@newuser:example.com", "m.login.password", make_login_dict()
            )

        api.register_user.assert_called_once_with(localpart="newuser")
        assert result == ("@newuser:example.com", None)

    @pytest.mark.asyncio
    async def test_create_users_disabled(self, accept_reply):
        provider, api = make_provider({"create_users": False})
        api.check_user_exists.return_value = False

        with patch.object(provider, "_make_client") as mock_make:
            client = MagicMock()
            client.SendPacket.return_value = accept_reply
            mock_make.return_value = client

            result = await provider.check_password(
                "@newuser:example.com", "m.login.password", make_login_dict()
            )

        assert result is None
        api.register_user.assert_not_called()

    @pytest.mark.asyncio
    async def test_username_parsing(self, provider_and_api, accept_reply):
        provider, api = provider_and_api
        with patch.object(provider, "_make_client") as mock_make:
            client = MagicMock()
            client.SendPacket.return_value = accept_reply
            mock_make.return_value = client

            await provider.check_password(
                "@bob:matrix.org", "m.login.password", make_login_dict()
            )

        call_kwargs = client.CreateAuthPacket.call_args
        assert call_kwargs[1]["User_Name"] == "bob"
