import re

_SCRIPT_TYPES = frozenset({
    "text/x-shellscript",
    "text/x-python",
    "text/x-perl",
    "text/x-ruby",
    "application/x-sh",
    "application/x-csh",
    "text/javascript",
    "application/javascript",
})

_BINARY_TYPES = frozenset({
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-mach-binary",
    "application/octet-stream",
    "application/gzip",
    "application/zip",
    "application/x-tar",
    "application/x-bzip2",
    "application/x-xz",
    "application/x-rpm",
    "application/x-deb",
})

_PASS_THROUGH_EXACT = frozenset({
    "text/html",
    "text/plain",
    "text/css",
    "application/json",
    "application/xml",
})

_PASS_THROUGH_PREFIXES = ("image/",)


def _base_type(content_type: str) -> str:
    return content_type.split(";")[0].strip().lower()


def is_script_content(content_type: str) -> bool:
    return _base_type(content_type) in _SCRIPT_TYPES


def is_binary_content(content_type: str) -> bool:
    return _base_type(content_type) in _BINARY_TYPES


def is_pass_through(content_type: str) -> bool:
    base = _base_type(content_type)
    return base in _PASS_THROUGH_EXACT or any(base.startswith(p) for p in _PASS_THROUGH_PREFIXES)


def check_dangerous_patterns(body: bytes, patterns: list[dict]) -> str | None:
    text = body.decode("utf-8", errors="replace")
    for pattern_def in patterns:
        regex = pattern_def.get("pattern", "")
        try:
            if re.search(regex, text, re.IGNORECASE):
                return pattern_def.get("name", regex)
        except re.error:
            continue
    return None
