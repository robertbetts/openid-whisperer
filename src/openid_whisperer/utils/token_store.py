""" Module for Private Key and Certificate Management
"""
import json
from typing import List, Dict, Any, Literal, Optional, TypedDict, Tuple
import base64
import datetime
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
import jwt
from jwt.utils import to_base64url_uint

from openid_whisperer.utils.common import (
    GeneralPackageException,
    generate_s256_hash,
    get_now_seconds_epoch,
    get_seconds_epoch,
)
from openid_whisperer.utils.common import package_get_logger

logger = package_get_logger(__name__)

TokenTypes = Literal["token", "refresh_token"]


class CertificatePairType(TypedDict):
    certificate: x509.Certificate
    private_key: Optional[CertificateIssuerPrivateKeyTypes]


""" This code is not currently in use
class TokenKeyType(TypedDict):
    kty: str
    use: str
    alg: str
    kid: str
    x5t: str
    n: str
    e: str
    x5c: List[str]
"""


class TokenIssuerCertificateStoreException(GeneralPackageException):
    """Exception raised when TokenIssueCertificateStore requirements are not met, other runtime
    exceptions are passed through.
    """


class TokenIssuerCertificateStore:
    """A class that contains the certificates and private keys required to encrypt and validate
    the issuance and support of jwt tokens

    TokenIssueCertificateStoreException is raised when TokenIssueCertificateStore requirements
    are not met, other runtime exceptions are passed through.

    certificates are the center of the universe here, as they have expiry and other validation
    attributes every private_key+certificate pair might likely have many of the same private_keys.
    A potential future optimisation, not required within the scope of this project at present.
    """

    def __init__(self, **kwargs):
        """
        Parameters
        ----------
        """
        self.token_issuer_key_id: str | None = None
        self.ca_cert_filename: str = ""
        self.org_key_filename: str = ""
        self.org_key_password: str = ""
        self.org_cert_filename: str = ""
        self.token_expiry_seconds: int | None = 600
        self.refresh_token_expiry_seconds: int | None = None

        # Update class properties from kwargs
        for key, value in kwargs.items():
            if not hasattr(self, key):
                logger.warning(
                    "Invalid initialization parameter, ignoring. %s: %s",
                    key,
                    str(value)[:100],
                )
                continue
            setattr(self, key, value)

        # Check config and update with reasonable defaults
        if self.token_expiry_seconds is None or self.token_expiry_seconds <= 0:
            self.token_expiry_seconds = 600  # 10 minutes
        if (
            self.refresh_token_expiry_seconds is None
            or self.refresh_token_expiry_seconds <= 0
        ):
            self.refresh_token_expiry_seconds = 60*60*14   # 24 hours

        # This value is hardcoded to RS256 and should not be changed after class initialisation
        self.token_issuer_algorithm: str = "RS256"

        # ca certificates Indexed on certificate serial number
        self.ca_certificates: Dict[str, x509.Certificate] = {}
        # org certificate/private key pairs Indexed on certificate serial number
        self.token_certificates: Dict[str, CertificatePairType] = {}

        # Required to be set during certificate initialisation
        self.token_issuer_key_id: str | None = None

        # TODO: Track these in the background, processing expiry, revocation etc.
        self.tokens_issued: Dict[
            str, Tuple[Any, str]
        ] = {}  # (expires_in, authorization_code) indexed by jti
        self.refresh_tokens_issued: Dict[
            str, Dict[str, Any]
        ] = {}  # dict{expires_in, client_id, jti} indexed by refresh_token
        self.token_requests: Dict[
            str, Dict[str, Any]
        ] = {}  # token_request Dict indexed by authorisation_code

        # Client secret keys, this is experimental, self.add_client_secret(client_id, algorithm, public_key)
        self.client_secret_keys: Dict[str, List[Dict[str, Any]]] = {}

        self.init_certificate_store()

    @property
    def token_issuer_private_key(self):
        return self.token_certificates[self.token_issuer_key_id]["private_key"]

    @property
    def token_issuer_certificate(self):
        return self.token_certificates[self.token_issuer_key_id]["certificate"]

    @classmethod
    def load_certificate_pair(
        cls,
        cert_filename: str | None = None,
        key_filename: str | None = None,
        key_password: str | None = None,
    ) -> Optional[CertificatePairType]:
        """returns a Private Key / certificate pair, where:
            * cert_filename is None, then return None
            * key_filename is None, the return  CertificatePairType with only the certificate populated.

        :param cert_filename:
        :param key_filename:
        :param key_password:
        :return:
        """
        if cert_filename is None:
            return None
        certificate: x509.Certificate
        with open(cert_filename, "rb") as cert_file:
            certificate = x509.load_pem_x509_certificate(
                cert_file.read(), default_backend()
            )

        private_key: CertificateIssuerPrivateKeyTypes | None = None
        if key_filename:
            with open(key_filename, "rb") as key_file:
                password: bytes = key_password.encode() if key_password else None
                private_key = serialization.load_pem_private_key(
                    data=key_file.read(),
                    backend=default_backend(),
                    password=password,
                )
                if not isinstance(private_key, CertificateIssuerPrivateKeyTypes):
                    raise TokenIssuerCertificateStoreException(
                        "invalid_private_key",
                        "Only private keys that support x509 certificates are allowed",
                    )  # pragma: no cover

        return {
            "private_key": private_key,
            "certificate": certificate,
        }

    def init_certificate_store(self) -> None:
        """Loads ca certificate and org private keys and certificate pairs."""
        # Loading ca certificate if provided
        certificate_pair = self.load_certificate_pair(self.ca_cert_filename, None, None)
        if certificate_pair is not None:
            certificate = certificate_pair["certificate"]
            certificate_id = str(certificate.serial_number)
            self.ca_certificates[certificate_id] = certificate

        # Init org cert-key pairs
        certificate_pair = self.load_certificate_pair(
            self.org_cert_filename, self.org_key_filename, self.org_key_password
        )
        certificate = certificate_pair["certificate"]
        certificate_id = str(certificate.serial_number)
        self.token_certificates[certificate_id] = certificate_pair

        # Set active certificate-pair to token signing
        self.token_issuer_key_id = certificate_id

    def get_keys(self) -> Dict[str, Any]:
        """Returns a list of public key information required to validate a signed jwk token"""
        key_list = []
        pn_n: str
        pn_e: str
        for certificate_id, certificate_pair in self.token_certificates.items():
            certificate = certificate_pair["certificate"]
            public_key: CertificatePublicKeyTypes = certificate.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                public_numbers: rsa.RSAPublicNumbers = public_key.public_numbers()
                pn_n = to_base64url_uint(public_numbers.n).decode("ascii")
                pn_e = to_base64url_uint(public_numbers.e).decode("ascii")
            else:
                raise TokenIssuerCertificateStoreException(
                    "invalid_public_key",
                    "Only public keys that support x509 certificates are allowed",
                )  # pragma: no cover
            public_cert: bytes = certificate.public_bytes(
                encoding=serialization.Encoding.DER
            )
            x5c: str = base64.b64encode(public_cert).decode("ascii")
            key_list.append(
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": self.token_issuer_algorithm,
                    "kid": certificate_id,
                    "x5t": certificate_id,
                    "n": pn_n,
                    "e": pn_e,
                    "x5c": [x5c],
                }
            )
        return {"keys": key_list}

    def add_client_secret(
        self,
        client_id: str,
        key_id: str,
        algorithm: str,
        public_key: Any,
        key_issuer: Optional[str] = None,
    ) -> None:
        """Returns None after storing the information regarding a client's secret. if key_issuer is None,
        it is defaulted to client_id

        If the below are True, a KeyError is raised:
            * existing key id
            * existing (algorithm, public_key) combination

        :param client_id:
        :param key_id:
        :param algorithm:
        :param public_key:
        :param key_issuer:
        :return: None
        """
        for key_info in self.client_secret_keys.setdefault(client_id, []):
            if key_id == key_info["key_id"]:
                raise KeyError("input key_id exists")
            if (
                algorithm == key_info["algorith"]
                and public_key == key_info["public_key"]
            ):
                raise KeyError("input public_key exists")

        self.client_secret_keys.setdefault(client_id, []).append(
            {
                "key_id": key_id,
                "key_issuer": key_issuer if key_issuer else client_id,
                "algorithm": algorithm,
                "public_key": public_key,
            }
        )

    def create_client_secret_token(
        self,
        client_id: str,
        client_secret: str,
        token_endpoint_url: str,
        token_key_id: str,
        token_expiry: int = 60,
        token_algorithm: str = "RS256",
        client_id_iss: Optional[str] = None,
        token_claims: Optional[Dict[str, Any]] = None,
        token_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Returns a Dict that includes a JWT issued by the client to authenticate with an upstream identity provider.
        This would typically be used by the implementation of this class when acting as a authentication relay.

        The claims iss, sub, sud, exp, nbf, iat, jti are included in the token created.

        https://datatracker.ietf.org/doc/html/rfc7523

        :param client_id:
            the valued for client_id in requests to the upstream identity provider
        :param client_secret:
            a secret shared only with the Identity provider
        :param token_endpoint_url:
            a value that identifies the authorization server as an intended audience. This is typically
            the url of the token endpoint at the IP for inspection or verification of the token
        :param token_key_id:
            a reference to the public key required to validate the token signature.
        :param token_expiry:
            time in seconds after which the token expires, defaults to 60
        :param token_algorithm:
            cryptographic algorithm for signing, defaults to RS256
        :param client_id_iss:
            an alternative client identifier, defaults to client_id
        :param token_claims:
            optional additional claims to embed in the token
        :param token_id:
            a unique reference for identifying the token, defaulted to uuid4()
        :return:
            Dict that includes the JWT client_secret
        """
        client_id_iss = client_id_iss if client_id_iss else client_id
        jti = token_id if token_id else uuid4().hex

        auth_time = datetime.datetime.utcnow()
        expires_in = auth_time + datetime.timedelta(seconds=token_expiry)
        payload = token_claims if token_claims else {}

        payload.update(
            {
                "sub": client_id,
                "iss": client_id_iss,
                "aud": token_endpoint_url,
                "exp": get_seconds_epoch(expires_in),
                "nbf": get_seconds_epoch(auth_time),
                "iat": get_seconds_epoch(auth_time),
                "jti": jti,
            }
        )
        """ TODO: this may be upstream identity provider specific, however it should be assessed
            what key identifier fields are required or optional for client secret JWTs.
            
            "kid": some_issuer_key_id
        """
        headers = {
            "typ": "JWT",
            "alg": token_algorithm,
            "kid": token_key_id,
            "x5t": token_key_id,
        }
        token = jwt.encode(
            payload=payload,
            key=client_secret,
            algorithm=token_algorithm,
            headers=headers,
        )
        token_response = {
            "jti": jti,
            "exp": get_seconds_epoch(expires_in),
            "token": token,
        }
        return token_response

    def get_client_keys(self, client_id: str) -> List[Dict[str, Any]]:
        """Returns a list if dictionaries with the keys:
                key_issuer, key_id, algorithm, public_key | hashed_secret

        :param client_id:
        :return:
        """
        client_keys = self.client_secret_keys.setdefault(client_id, [])
        return client_keys

    def decode_client_secret_token(self, token: str) -> Dict[str, Any]:
        """Returns a dict of claims embedded in the token provided

        exceptions raised are:
            KeyError = Missing required JWT headers and claims
            ValueError = unknown client or Missing client secret
            jwt token validation exceptions

        :param token:
        :return:
        """

        input_claims = jwt.decode(token, options={"verify_signature": False})
        token_client_id = input_claims["sub"]
        token_audience = input_claims["aud"]

        # TODO: Audience check, is token_audience a valid token endpoint url

        token_headers = jwt.get_unverified_header(token)
        token_algorith = token_headers["alg"]
        _token_key_id = token_headers.get("kid")
        _token_key_x5t = token_headers.get("x5t")
        key_id = _token_key_x5t if _token_key_x5t else _token_key_id
        if not key_id:
            raise ValueError("Missing public key reference")

        issuer = None
        public_key = None
        algorithm = None
        for client_key in self.get_client_keys(token_client_id):
            if (
                key_id
                and client_key["key_id"] != key_id
                or token_algorith != client_key["algorithm"]
            ):
                continue
            issuer = client_key["key_issuer"]
            algorithm = client_key["algorithm"]
            public_key = client_key["public_key"]

        if issuer is None or algorithm is None or public_key is None:
            raise ValueError("No valid key to validate the client secret JWT")

        claims = jwt.decode(
            jwt=token,
            key=public_key,
            algorithms=[algorithm],
            issuer=issuer,
            audience=token_audience,
        )
        logger.debug(claims)
        return claims

    def create_refresh_token(self, client_id: str, jti: str, expiry_seconds: Optional[int] = None) -> str:
        """ Returns a refresh_token, its expiry is defaulted to 24 hours,
        is stored locally, until a refresh is requested.
        :param client_id:
        :param jti:
        :param expiry_seconds:
        """
        expiry_seconds = expiry_seconds if expiry_seconds else self.token_expiry_seconds
        expires_in = datetime.datetime.utcnow() + datetime.timedelta(seconds=expiry_seconds)
        refresh_token = uuid4().hex
        self.refresh_tokens_issued[refresh_token] = {
            "expires_in": expires_in,
            "client": client_id,
            "jti": jti,
        }
        return refresh_token

    def create_new_token(
        self,
        client_id,
        issuer: str,
        sub: str,
        user_claims: Dict[str, Any],
        audience: List[str],
        nonce: str,
        refresh_token: Optional[str] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """Returns a response that includes an id_token and access_token JWTs.

        The claims iss, sun, exp, iat, auth_time, appid, ver are overriden by the TokenIssuerCertificateStore

        :param client_id:
        :param issuer:
        :param sub:
        :param user_claims:
        :param audience:
        :param nonce:
        :param refresh_token:
        :return:
        """

        auth_time = datetime.datetime.utcnow()
        expires_in = get_seconds_epoch(auth_time + datetime.timedelta(seconds=self.token_expiry_seconds))
        auth_time_epoch = get_seconds_epoch(auth_time)
        expires_in_epoch = expires_in
        auth_time_str = auth_time.isoformat()
        aud = audience
        jti = uuid4().hex

        if refresh_token:
            previous_refresh = self.refresh_tokens_issued.get(refresh_token)
            if previous_refresh is None:
                raise TokenIssuerCertificateStoreException("invalid_refresh_token", "refresh token request is invalid")
            if previous_refresh["jti"] not in self.tokens_issued:
                raise TokenIssuerCertificateStoreException("invalid_refresh_token", "refresh token request is invalid")
            prev_expiry, prev_auth_code = self.tokens_issued[previous_refresh["jti"]]
            if prev_auth_code not in self.token_requests:
                raise TokenIssuerCertificateStoreException("invalid_refresh_token", "refresh token request is invalid")
            previous_token = self.token_requests[prev_auth_code]["id_token"]
            refresh_claims = jwt.decode(previous_token, options={"verify_signature": False})
            sub = refresh_claims["sub"]
            aud = refresh_claims["aud"]
            auth_time_str = refresh_claims["auth_time"]
            user_claims.update(refresh_claims)


        # For now both the access_token and id_token have the same claims
        access_token_payload = {}
        access_token_payload.update(user_claims)
        access_token_payload["nonce"] = nonce
        access_token_payload.update(
            {
                "iss": issuer,
                "sub": sub,
                "aud": aud,
                "exp": expires_in_epoch,
                "nbf": auth_time_epoch,
                "iat": auth_time_epoch,
                "auth_time": auth_time_str,
                "appid": client_id,
                "jti": jti,
                "ver": "1.0",
            }
        )
        headers = {
            "typ": "JWT",
            "alg": self.token_issuer_algorithm,
            "kid": self.token_issuer_key_id,
            "x5t": self.token_issuer_key_id,
        }
        access_token = jwt.encode(
            payload=access_token_payload,
            key=self.token_issuer_private_key,
            algorithm=self.token_issuer_algorithm,
            headers=headers,
        )
        id_token_payload = {}
        id_token_payload.update(access_token_payload)
        id_token = jwt.encode(
            payload=id_token_payload,
            key=self.token_issuer_private_key,
            algorithm=self.token_issuer_algorithm,
            headers=headers,
        )
        refresh_token = self.create_refresh_token(client_id, jti)
        # TODO: Check when not required to have both access_token and id_token in the response
        token_response = {
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": expires_in_epoch,
            "refresh_token": refresh_token,
        }
        authorisation_code = generate_s256_hash(json.dumps(token_response))
        self.tokens_issued[jti] = (expires_in, authorisation_code)
        self.token_requests[authorisation_code] = token_response
        return authorisation_code, token_response

    def decode_token(
        self, token, issuer: Optional[str] = None, audience: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        return jwt.decode(
            jwt=token,
            key=self.token_issuer_certificate.public_key(),
            algorithms=[self.token_issuer_algorithm],
            issuer=issuer,
            audience=audience,
        )

    def validate_jwt_token(
        self, token: str, token_type: TokenTypes, issuer: str, audience: List[str]
    ) -> bool:
        """Validate the token using cert-pairs from the TokenIssuerCertificateStore or
        validate a refresh token against those issued.

        issuer and audience are required for proper validation
        """
        if token_type == "token":
            try:
                claims = self.decode_token(
                    token=token, issuer=issuer, audience=audience
                )
                if claims["jti"] not in self.tokens_issued:
                    return False  # pragma: no cover
                if get_now_seconds_epoch() > claims["exp"]:
                    return False  # pragma: no cover
                return True
            except Exception as e:
                logger.exception(e)
                return False
        else:
            return token in self.refresh_tokens_issued
