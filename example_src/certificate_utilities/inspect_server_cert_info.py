import ssl

server_address = ("localhost", 5005)
cert_pem = ssl.get_server_certificate(server_address)
print(cert_pem)
