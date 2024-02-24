
from whoislookup import whois_lookup
import pytest
class TestWhoisLookup:
    def test_valid_domain_name(self):
        domain_name = "example.com"
        whois_lookup(domain_name)
    def test_print_whois_information(self, capsys):
        domain_name = "example.com"
        whois_lookup(domain_name)
        captured = capsys.readouterr()
        assert captured.out != ""
    def test_nonexistent_domain_name(self, capsys):
        domain_name = "nonexistentdomain.com"
        whois_lookup(domain_name)
        captured = capsys.readouterr()
        assert captured.out != ""
    def test_invalid_domain_name(self, capsys):
        domain_name = "invalid_domain_name"
        whois_lookup(domain_name)
        captured = capsys.readouterr()
        assert captured.out != ""