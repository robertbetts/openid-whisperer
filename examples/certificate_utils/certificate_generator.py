""" Sample Self-signed Certificate generation
"""
import logging
import os
from typing import Optional, List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from openid_whisperer.cert_utils import (
    generate_ca_key_and_certificate,
    generate_org_key_and_certificate,
    dump_cert_and_ca_bundle,
    check_sha256_certificate,
)

logger = logging.getLogger(__name__)


class PatternExistsError(Exception):
    ...


def any_patterns_exist(index: int, patterns: List[str]) -> bool:
    """Return True if any file path evaluated by applying the index to each
    pattern exists.
    Every pattern is expected to have one and only one %s
    """
    return any([os.path.exists(item % index) for item in patterns])


def all_paths_do_not_exist(paths: List[str]) -> bool:
    """Return True if all the paths do not exist"""
    return all([not os.path.exists(item) for item in paths])


def next_path(
    path_patterns: str | List[str], appendix: Optional[str] = "-%s"
) -> List[str]:
    """
    Tweaked the original example to name files in batches with the same pattern appendix

    https://stackoverflow.com/questions/17984809/how-do-i-create-an-incrementing-filename-in-python

    Finds the next free path in an sequentially named list of files

    e.g. path_pattern = 'file-%s.txt':

    file-1.txt
    file-2.txt
    file-3.txt

    Runs in log(n) time, where n is the number of existing files in sequence
    """
    if appendix is None:
        appendix = "-%s"

    if isinstance(path_patterns, str):
        path_patterns = [item.strip() for item in path_patterns.split(",")]

    if all_paths_do_not_exist(path_patterns):
        return path_patterns
    else:
        if "%s" not in appendix:
            error_message: str = "Unable to find a set of unique paths that don't exits with an appendix does not contain '%s'"
            logger.error(error_message)
            raise (PatternExistsError(error_message))

    patterns_with_prefix: List[str] = []
    for path_pattern in path_patterns:
        pattern_name, pattern_ext = os.path.splitext(path_pattern)
        path_pattern = f"{pattern_name}{appendix}{pattern_ext}"
        patterns_with_prefix.append(path_pattern)
        i = 1

    # First do an exponential search
    while any_patterns_exist(i, patterns_with_prefix):
        i = i * 2

    # Result lies somewhere in the interval (i/2..i]
    # We call this interval (a..b] and narrow it down until a + 1 = b
    a, b = (i // 2, i)
    while a + 1 < b:
        c = (a + b) // 2  # interval midpoint
        a, b = (c, b) if any_patterns_exist(c, patterns_with_prefix) else (a, c)

    return [pattern % b for pattern in patterns_with_prefix]


def creat_sample_cert_files(
    organization_name=None,
    common_name=None,
    host_names=None,
    ca_key=None,
    ca_cert=None,
    org_key=None,
    overwrite_existing_files: bool = False,
):
    if ca_key is None:
        ca_key, ca_cert = generate_ca_key_and_certificate()
        dump_cert_and_ca_bundle(
            private_key=ca_key,
            certificate=ca_cert,
            ca_certificate=ca_cert,
            cert_filename="ca_cert.pem",
            primary_key_filename="ca_key.pem",
            location="./",
            overwrite_existing_files=overwrite_existing_files,
        )

    org_key, org_cert = generate_org_key_and_certificate(
        ca_key,
        ca_cert,
        org_key=org_key,
        organization_name=organization_name,
        common_name=common_name,
        host_names=host_names,
    )

    assert check_sha256_certificate(org_cert, ca_cert)

    location = "./"
    key_pattern = "org_key.pem"
    key_pattern = os.path.join(location, key_pattern)

    location = "./"
    cert_pattern = "org_cert.pem"
    cert_pattern = os.path.join(location, cert_pattern)

    chain_pattern = "org_cert-chain.pem"
    chain_pattern = os.path.join(location, chain_pattern)

    key_filename, cert_filename, chain_filename = next_path(
        [key_pattern, cert_pattern, chain_pattern]
    )

    dump_cert_and_ca_bundle(
        ca_certificate=ca_cert,
        private_key=org_key,
        certificate=org_cert,
        location="./",
        primary_key_filename=key_filename,
        cert_filename=cert_filename,
        ca_chain_filename=chain_filename,
        overwrite_existing_files=overwrite_existing_files,
    )


def gen_ord_certs_from_ca(
    ca_key_filename: str,
    ca_cert_filename: str,
    org_key_filename: Optional[str] = None,
    host_names: Optional[str] = None,
    organization_name: Optional[str] = None,
    common_name: Optional[str] = None,
    key_password: Optional[str] = None,
    overwrite_existing_files: bool = False,
):
    with open(ca_key_filename, "rb") as ca_key_file:
        with open(ca_cert_filename, "rb") as ca_cert_file:
            ca_key: rsa.RSAPrivateKey = serialization.load_pem_private_key(
                data=ca_key_file.read(),
                password=key_password,
                backend=default_backend(),
            )
            ca_cert: x509.Certificate = x509.load_pem_x509_certificate(
                ca_cert_file.read(), default_backend()
            )
            org_key: rsa.RSAPrivateKey | None = None
            if org_key_filename:
                with open(org_key_filename, "rb") as org_key_file:
                    org_key = serialization.load_pem_private_key(
                        data=org_key_file.read(),
                        backend=default_backend(),
                        password=key_password,
                    )
            creat_sample_cert_files(
                organization_name=organization_name,
                common_name=common_name,
                host_names=host_names,
                ca_key=ca_key,
                ca_cert=ca_cert,
                org_key=org_key,
                overwrite_existing_files=overwrite_existing_files,
            )


def main():
    """Utility for creating self-signed CA and SSL certificates.
    NOTE: Do not uncomment the root_ca_* parameters below, use as is
    """
    ca_key_filename: str = "root_ca_key.pem"
    ca_cert_filename: str = "root_ca_cert.pem"

    organization_name = common_name = "OpenID Provider"
    host_name = "10.95.55.84"  # Dev env IP

    org_key_filename: str | None = None

    overwrite_existing_files: bool = False

    gen_ord_certs_from_ca(
        ca_key_filename=ca_key_filename,
        ca_cert_filename=ca_cert_filename,
        org_key_filename=org_key_filename,
        organization_name=organization_name,
        common_name=common_name,
        host_names=host_name,
        overwrite_existing_files=overwrite_existing_files,
    )


if __name__ == "__main__":
    main()
