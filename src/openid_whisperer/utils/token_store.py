""" Module for Private Key and Certificate Management
"""
import json
import logging
from typing import List, Dict, Any, Literal, Optional, Tuple, TypedDict
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

logger = logging.getLogger(__name__)

TokenTypes = Literal["token", "refresh_token"]


class CertificatePairType(TypedDict):
    certificate: x509.Certificate
    private_key: Optional[CertificateIssuerPrivateKeyTypes]


class TokenKeyType(TypedDict):
    kty: str
    use: str
    alg: str
    kid: str
    x5t: str
    n: str
    e: str
    x5c: List[str]


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
        self.ca_cert_filename: str = ""
        self.org_key_filename: str = ""
        self.org_key_password: str = ""
        self.org_cert_filename: str = ""
        self.token_expiry_seconds: int | None = 600
        self.refresh_token_expiry_seconds: int | None = 3600

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
            self.refresh_token_expiry_seconds = 3600  # 1 hour

        self.ca_certificates: Dict[
            str, x509.Certificate
        ] = {}  # ca certificates Indexed on certificate serial number
        self.token_certificates: Dict[
            str, CertificatePairType
        ] = {}  # org certificate/private key pairs Indexed on certificate serial number

        self.token_issuer_key_id: str | None = (
            None  # expected to be set during certificate initialisation
        )
        self.token_issuer_algorithm: str = "RS256"

        # TODO: Track these
        self.tokens_issued: Dict[
            str, Tuple[Any, str]
        ] = {}  # (expires_in, authorization_code) indexed by jti
        self.refresh_tokens_issued: Dict[
            str, Tuple[int, str]
        ] = {}  # (expires_in, authorization_code) indexed by jti
        self.token_requests: Dict[
            str, Dict[str, Any]
        ] = {}  # token_request Dict indexed by authorisation_code

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

    def create_new_token(
        self,
        client_id,
        issuer: str,
        sub: str,
        user_claims: Dict[str, Any],
        audience: List[str],
        nonce: str,
    ) -> Tuple[str, Dict[str, Any]]:
        """Returns a new JWT response using the parameters given.

        The claims iss, sun, exp, iat, auth_time, appid, ver are overriden by the TokenIssuerCertificateStore

        :param client_id:
        :param issuer:
        :param sub:
        :param user_claims:
        :param audience:
        :param nonce:
        :return:
        """
        auth_time = datetime.datetime.utcnow()
        expires_in = auth_time + datetime.timedelta(seconds=self.token_expiry_seconds)
        payload = {}
        payload.update(user_claims)
        payload["nonce"] = nonce
        jti = uuid4().hex
        payload.update(
            {
                "iss": issuer,
                "sub": sub,
                "aud": audience,
                "exp": get_seconds_epoch(expires_in),
                "nbf": get_seconds_epoch(auth_time),
                "iat": get_seconds_epoch(auth_time),
                "auth_time": auth_time.isoformat(sep=" "),
                "appid": client_id,
                "jti": jti,
                "ver": "1.0",
            }
        )
        headers = {
            "kid": self.token_issuer_key_id,
            "x5t": self.token_issuer_key_id,
        }
        token = jwt.encode(
            payload=payload,
            key=self.token_issuer_private_key,
            algorithm=self.token_issuer_algorithm,
            headers=headers,
        )
        # TODO: Check conditions when to complete and return a refresh token
        refresh_token = ""
        refresh_token_expires_in = get_seconds_epoch(auth_time)
        # TODO: Check when required to have both access_token and id_token in the return below
        token_response = {
            "access_token": token,
            "id_token": token,
            "token_type": "Bearer",
            "expires_in": get_seconds_epoch(expires_in),
            "refresh_token": refresh_token,
            "refresh_token_expires_in": refresh_token_expires_in,
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
