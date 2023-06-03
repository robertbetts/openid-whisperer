import ssl
import socket
from pprint import pprint

server_hostname = "openid-whisperer"
server_address = ("localhost", 5000)
cert_pem = ssl.get_server_certificate(server_address)
pprint(cert_pem)

context = ssl.create_default_context()
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# context.load_verify_locations("/etc/ssl/certs/ca-bundle.crt")
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=server_hostname
            )
conn.connect(server_address)
pprint(context.cert_store_stats())
cert = conn.getpeercert(binary_form=True)
pprint(cert)
