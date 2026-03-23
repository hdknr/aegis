import ipaddress

from proxy.rules_loader import load_c2_blocklist, load_domain_whitelist, load_rules


class TestLoadDomainWhitelist:
    def test_basic(self, tmp_path):
        f = tmp_path / "whitelist.txt"
        f.write_text("github.com\npypi.org\n")
        result = load_domain_whitelist(f)
        assert result == {"github.com", "pypi.org"}

    def test_comments_and_blanks(self, tmp_path):
        f = tmp_path / "whitelist.txt"
        f.write_text("# comment\n\ngithub.com\n  # another\n\npypi.org\n")
        result = load_domain_whitelist(f)
        assert result == {"github.com", "pypi.org"}

    def test_case_insensitive(self, tmp_path):
        f = tmp_path / "whitelist.txt"
        f.write_text("GitHub.COM\n")
        result = load_domain_whitelist(f)
        assert "github.com" in result

    def test_strips_whitespace(self, tmp_path):
        f = tmp_path / "whitelist.txt"
        f.write_text("  github.com  \n")
        result = load_domain_whitelist(f)
        assert "github.com" in result


class TestLoadC2Blocklist:
    def test_basic(self, tmp_path):
        f = tmp_path / "blocklist.txt"
        f.write_text("198.51.100.0/24\n203.0.113.0/24\n")
        result = load_c2_blocklist(f)
        assert len(result) == 2
        assert ipaddress.ip_network("198.51.100.0/24") in result

    def test_comments_and_blanks(self, tmp_path):
        f = tmp_path / "blocklist.txt"
        f.write_text("# comment\n\n198.51.100.0/24\n")
        result = load_c2_blocklist(f)
        assert len(result) == 1

    def test_invalid_entries_skipped(self, tmp_path):
        f = tmp_path / "blocklist.txt"
        f.write_text("198.51.100.0/24\nnot-a-cidr\n203.0.113.0/24\n")
        result = load_c2_blocklist(f)
        assert len(result) == 2

    def test_ipv6(self, tmp_path):
        f = tmp_path / "blocklist.txt"
        f.write_text("2001:db8::/32\n")
        result = load_c2_blocklist(f)
        assert len(result) == 1
        assert ipaddress.ip_network("2001:db8::/32") in result


class TestLoadRules:
    def test_valid_yaml(self, tmp_path):
        f = tmp_path / "rules.yml"
        f.write_text(
            "dangerous_patterns:\n"
            "  - name: test\n"
            "    pattern: 'curl.*|.*bash'\n"
            "    severity: critical\n"
            "    description: test pattern\n"
        )
        result = load_rules(f)
        assert len(result["dangerous_patterns"]) == 1
        assert result["dangerous_patterns"][0]["name"] == "test"
