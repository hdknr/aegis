from unittest.mock import MagicMock


def make_flow(
    url: str = "https://example.com/page.html",
    host: str = "example.com",
    content_type: str | None = None,
    body: bytes | None = None,
    status_code: int | None = None,
):
    """Create a mocked mitmproxy HTTPFlow for testing."""
    flow = MagicMock()
    flow.request.pretty_url = url
    flow.request.pretty_host = host
    flow.request.path = url.split(host, 1)[-1] if host in url else "/"
    flow.request.method = "GET"
    flow.client_conn.peername = ("127.0.0.1", 12345)
    flow.metadata = {}

    if status_code is not None:
        flow.response.status_code = status_code
        flow.response.headers = {"content-type": content_type or "text/html"}
        flow.response.content = body or b""
    else:
        flow.response = None

    return flow
