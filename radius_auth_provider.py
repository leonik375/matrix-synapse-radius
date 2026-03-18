import logging
from collections.abc import Callable

import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary, Attribute
from synapse.logging.context import defer_to_thread
from synapse.module_api import ModuleApi
from twisted.internet import reactor

logger = logging.getLogger(__name__)


def make_dictionary():
    d = Dictionary()
    for name, code, datatype in [
        ("User-Name", 1, "string"),
        ("User-Password", 2, "string"),
        ("NAS-IP-Address", 4, "ipaddr"),
        ("NAS-Port", 5, "integer"),
    ]:
        attr = Attribute(name, code, datatype, False, None)
        d.attributes[name] = attr
        d.attrindex.Add(("", code), name)
    return d


class RadiusAuthProvider:
    """RADIUS authentication provider for Matrix Synapse.

    Authenticates users against a RADIUS server and optionally creates
    Matrix accounts for successfully authenticated users.
    """

    def __init__(self, config: dict, api: ModuleApi):
        self.api = api
        self.create_users = config.get("create_users", True)
        self.nas_ip = config.get("nas_ip", "127.0.0.1")
        self.dict = make_dictionary()

        self._radius_server = config.get("server", "127.0.0.1")
        self._radius_secret = config["secret"].encode()
        self._radius_port = config.get("port", 1812)
        self._radius_timeout = config.get("timeout", 3)
        self._radius_retries = config.get("retries", 1)

        api.register_password_auth_provider_callbacks(
            auth_checkers={
                ("m.login.password", ("password",)): self.check_password
            },
        )

    def _make_client(self) -> Client:
        client = Client(
            server=self._radius_server,
            secret=self._radius_secret,
            dict=self.dict,
            authport=self._radius_port,
        )
        client.timeout = self._radius_timeout
        client.retries = self._radius_retries
        return client

    async def check_password(
        self,
        username: str,
        login_type: str,
        login_dict: dict,
    ) -> tuple[str, Callable | None] | None:
        password = login_dict.get("password")
        if not password:
            return None

        localpart = username.split(":", 1)[0].lstrip("@")

        try:
            client = self._make_client()
            req = client.CreateAuthPacket(
                code=pyrad.packet.AccessRequest,
                User_Name=localpart,
            )
            req["User-Password"] = req.PwCrypt(password)
            req["NAS-IP-Address"] = self.nas_ip
            req["NAS-Port"] = 0

            reply = await defer_to_thread(reactor, client.SendPacket, req)
            if reply.code != pyrad.packet.AccessAccept:
                logger.warning("RADIUS auth failed for %s", localpart)
                return None
        except pyrad.packet.PacketError as e:
            logger.error("RADIUS error for %s: %s", localpart, e, exc_info=True)
            return None
        except Exception as e:
            logger.error("RADIUS error for %s: %s", localpart, e, exc_info=True)
            return None

        user_id = self.api.get_qualified_user_id(localpart)

        if not await self.api.check_user_exists(user_id):
            if not self.create_users:
                return None
            user_id = await self.api.register_user(localpart=localpart)

        return user_id, None

    @staticmethod
    def parse_config(config: dict) -> dict:
        if "secret" not in config:
            raise ValueError(
                "radius_auth_provider: 'secret' is required in the configuration"
            )
        return config
