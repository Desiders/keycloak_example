import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import orjson
from adaptix import Retort, name_mapping
from aiohttp import ClientSession
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError

logger = logging.getLogger(__name__)


@dataclass
class OpenIDConfiguration:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    introspection_endpoint: str
    userinfo_endpoint: str
    end_session_endpoint: str
    jwks_uri: str
    check_session_iframe: str
    grant_types_supported: list[str]
    acr_values_supported: list[str]
    response_types_supported: list[str]
    subject_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]
    id_token_encryption_alg_values_supported: list[str]
    id_token_encryption_enc_values_supported: list[str]
    userinfo_signing_alg_values_supported: list[str]
    userinfo_encryption_alg_values_supported: list[str]
    userinfo_encryption_enc_values_supported: list[str]
    request_object_signing_alg_values_supported: list[str]
    request_object_encryption_alg_values_supported: list[str]
    request_object_encryption_enc_values_supported: list[str]
    response_modes_supported: list[str]
    registration_endpoint: str
    token_endpoint_auth_methods_supported: list[str]
    token_endpoint_auth_signing_alg_values_supported: list[str]
    introspection_endpoint_auth_methods_supported: list[str]
    introspection_endpoint_auth_signing_alg_values_supported: list[str]
    authorization_signing_alg_values_supported: list[str]
    authorization_encryption_alg_values_supported: list[str]
    authorization_encryption_enc_values_supported: list[str]
    claims_supported: list[str]
    claim_types_supported: list[str]
    claims_parameter_supported: bool
    scopes_supported: list[str]
    request_parameter_supported: bool
    request_uri_parameter_supported: bool
    require_request_uri_registration: bool
    code_challenge_methods_supported: list[str]
    tls_client_certificate_bound_access_tokens: bool
    revocation_endpoint: str
    revocation_endpoint_auth_methods_supported: list[str]
    revocation_endpoint_auth_signing_alg_values_supported: list[str]
    backchannel_logout_supported: bool
    backchannel_logout_session_supported: bool
    device_authorization_endpoint: str
    backchannel_token_delivery_modes_supported: list[str]
    backchannel_authentication_endpoint: str
    backchannel_authentication_request_signing_alg_values_supported: list[str]
    require_pushed_authorization_requests: bool
    pushed_authorization_request_endpoint: str
    mtls_endpoint_aliases: dict[str, str]


@dataclass
class IDToken:
    # `openid` scope (required)
    iss: str
    sub: str
    aud: str
    exp: int
    iat: int

    # `openid` scope (optional)
    auth_time: int | None = None
    acr: str | None = None
    amr: list[str] | None = None
    azp: str | None = None

    # `openid` scope (optional) and `hybrid` flow
    nonce: str | None = None
    at_hash: str | None = None
    c_hash: str | None = None

    # `profile` scope
    name: str | None = None
    family_name: str | None = None
    given_name: str | None = None
    middle_name: str | None = None
    nickname: str | None = None
    preferred_username: str | None = None
    profile: str | None = None
    picture: str | None = None
    website: str | None = None
    gender: str | None = None
    birthdate: str | None = None
    zoneinfo: str | None = None
    locale: str | None = None
    updated_at: int | None = None

    # `email` scope
    email: str | None = None
    email_verified: bool | None = None

    # `address` scope
    address: str | dict[str, str] | None = None

    # `phone` scope
    phone_number: str | None = None
    phone_number_verified: bool | None = None

    scope: str | None = None
    realm_access: dict | None = None
    resource_access: dict | None = None

    @property
    def scopes(self) -> list[str]:
        return self.scope.split(" ") if self.scope is not None else []

    @property
    def realm_roles(self) -> list[str]:
        return self.realm_access["roles"] if self.realm_access is not None else []

    @property
    def client_roles(self) -> dict[str, list[str]]:
        return self.resource_access if self.resource_access is not None else {}


@dataclass
class KeycloakTokens:
    access_token: str
    expires_in: int
    refresh_expires_in: int
    refresh_token: str
    token_type: str
    not_before_policy: int
    session_state: str
    scope: str

    @property
    def scopes(self) -> list[str]:
        return self.scope.split(" ")

    @property
    def access_token_claims(self) -> dict[str, Any]:
        return jwt.get_unverified_claims(self.access_token)

    @property
    def refresh_token_claims(self) -> dict[str, Any]:
        return jwt.get_unverified_claims(self.refresh_token)


class KeycloakClient:
    def __init__(
        self,
        base_url: str,
        realm_id: str,
        client_id: str,
        client_secret: str,
        admin_client_id: str,
        admin_client_secret: str,
        callback_url: str,
    ):
        self.base_url = base_url
        self.realm_id = realm_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.admin_client_id = admin_client_id
        self.admin_client_secret = admin_client_secret
        self.callback_url = callback_url

        # This will be set when `fetch_access_token` is called
        self.access_token: str | None = None

        # This will be set when `fetch_realm_public_key` is called
        self.public_key: str | None = None

        # This will be set when `fetch_openid_configuration` is called
        self.openid_configuration: OpenIDConfiguration | None = None

        self.retort = Retort(
            recipe=[
                name_mapping(
                    KeycloakTokens,
                    # The `not_before_policy` field is s
                    map={"not_before_policy": "not-before-policy"},
                )
            ]
        )

        self._session: ClientSession | None = None

    def get_session(self) -> ClientSession:
        if self._session is None or self._session.closed:
            self._session = ClientSession()

        return self._session

    async def fetch_openid_configuration(self) -> None:
        url = f"{self.base_url}/realms/{self.realm_id}/.well-known/openid-configuration"

        session = self.get_session()
        response = await session.get(url)
        try:
            response.raise_for_status()
        finally:
            await session.close()

        json = await response.json(loads=orjson.loads)

        self.openid_configuration = self.retort.load(json, OpenIDConfiguration)

    async def get_openid_configuration(self) -> OpenIDConfiguration:
        """
        Get the OpenID configuration for the realm.
        If the configuration has not been fetched yet, it will be fetched.
        """
        if self.openid_configuration is None:
            logger.debug("OpenID configuration is `None`. Fetching...")

            await self.fetch_openid_configuration()

        return self.openid_configuration  # type: ignore

    async def fetch_access_token(self) -> None:
        openid_configuration = await self.get_openid_configuration()

        url = openid_configuration.token_endpoint
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "client_credentials",
            "client_id": self.admin_client_id,
            "client_secret": self.admin_client_secret,
        }

        session = self.get_session()
        response = await session.post(url, data=data, headers=headers)
        try:
            response.raise_for_status()
        finally:
            await session.close()

        json = await response.json(loads=orjson.loads)
        access_token = json["access_token"]

        logger.debug(
            "Got access token", extra={"access_token": access_token, "json": json}
        )

        self.access_token = access_token

    async def get_access_token(self) -> str:
        """
        Get the access token for the admin client.
        If the access token has not been fetched yet, it will be fetched.
        """
        if self.access_token is None:
            logger.debug("Access token is `None`. Fetching...")

            await self.fetch_access_token()

        return self.access_token  # type: ignore

    async def fetch_realm_public_key(self) -> None:
        url = f"{self.base_url}/realms/{self.realm_id}"

        session = self.get_session()
        response = await session.get(url)
        try:
            response.raise_for_status()
        finally:
            await session.close()

        json = await response.json(loads=orjson.loads)
        public_key = json["public_key"]

        logger.debug("Got public key", extra={"public_key": public_key, "json": json})

        self.public_key = public_key

    def wrap_public_key_in_pem_markers(self, public_key: str) -> str:
        """
        Wrap the public key in PEM markers.
        """
        return f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"

    async def get_realm_public_key(self, wrap_in_pem_markers: bool = False) -> str:
        """
        Get the public key for the realm.
        If the public key has not been fetched yet, it will be fetched.

        :param wrap_in_pem_markers: Whether to wrap the public key in PEM markers.
        """
        if self.public_key is None:
            logger.debug("Public key is `None`. Fetching...")

            await self.fetch_realm_public_key()

        if wrap_in_pem_markers:
            return self.wrap_public_key_in_pem_markers(self.public_key)  # type: ignore

        return self.public_key  # type: ignore

    async def get_access_token_claims(
        self, token: str, audience: str | None
    ) -> dict[str, Any]:
        public_key = await self.get_realm_public_key(wrap_in_pem_markers=True)

        options = {
            "verify_signature": True,
            "verify_aud": audience is not None,
            "verify_exp": True,
        }

        return jwt.decode(
            token,
            key=public_key,
            options=options,
            audience=audience,
        )

    async def access_token_is_valid(self, token: str) -> bool:
        try:
            await self.get_access_token_claims(token, None)
        except (ExpiredSignatureError, JWTClaimsError, JWTError):
            return False
        return True

    async def get_id_token_by_access_token(self, token: str) -> IDToken:
        audience = "account"
        claims = await self.get_access_token_claims(token, audience)

        return self.retort.load(claims, IDToken)

    async def get_authorization_url(self) -> str:
        """
        Get the authorization URL with the correct parameters.
        """
        openid_configuration = await self.get_openid_configuration()

        url = openid_configuration.authorization_endpoint

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.callback_url,
        }

        return f"{url}?{urlencode(params)}"

    async def get_tokens_by_username_and_password(
        self,
        username: str,
        password: str,
        scopes: list[str] | None = None,
    ) -> KeycloakTokens:
        """
        Get tokens by username and password.
        """
        openid_configuration = await self.get_openid_configuration()

        url = openid_configuration.token_endpoint
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": username,
            "password": password,
            "scope": " ".join(scopes) if scopes is not None else [],
        }

        session = self.get_session()
        response = await session.post(url, data=data, headers=headers)
        try:
            response.raise_for_status()
        finally:
            await session.close()

        json = await response.json(loads=orjson.loads)

        return self.retort.load(json, KeycloakTokens)

    async def exchange_authorization_code(
        self, session_state: str, code: str
    ) -> KeycloakTokens:
        """
        Exchange an authorization code for a token.
        This is used in the callback URL to get the users' tokens after they have logged in.
        """
        openid_configuration = await self.get_openid_configuration()

        url = openid_configuration.token_endpoint
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.callback_url,
            "session_state": session_state,
            "code": code,
        }

        session = self.get_session()
        response = await session.post(url, data=data, headers=headers)
        try:
            response.raise_for_status()
        finally:
            await session.close()

        json = await response.json(loads=orjson.loads)

        return self.retort.load(json, KeycloakTokens)

    async def refresh_tokens(self, refresh_token: str) -> KeycloakTokens:
        """
        Refresh tokens.
        This is used to get new tokens after the access token has expired.
        If the refresh token has expired, the user will have to log in again.
        """
        openid_configuration = await self.get_openid_configuration()

        url = openid_configuration.token_endpoint
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token,
        }

        session = self.get_session()
        response = await session.post(url, data=data, headers=headers)
        try:
            response.raise_for_status()
        finally:
            await session.close()

        json = await response.json(loads=orjson.loads)

        return self.retort.load(json, KeycloakTokens)
