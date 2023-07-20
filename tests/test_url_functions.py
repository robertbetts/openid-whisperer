from urllib.parse import urlsplit, urlunsplit


def test_url_split_and_composition():
    base_url = "/mock-api/api/endpoint"
    url_parts = urlsplit(base_url)
    assert url_parts.scheme == ""

    base_url = "http://localhost:8888/mock-api/api/endpoint"
    url_parts = urlsplit(base_url)
    new_basee_url = urlunsplit(
        ("https", url_parts.netloc, url_parts.path, url_parts.query, url_parts.fragment)
    )
    assert new_basee_url == "https://localhost:8888/mock-api/api/endpoint"
