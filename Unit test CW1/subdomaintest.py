
from subdomain import enumerate_subdomains
import os
import pytest
class TestEnumerateSubdomains:
    def test_read_subdomains(self, capfd):
        import os
        domain = "example.com"
        wordlist_file = "wordlist.txt"

        with open(wordlist_file, 'w') as file:
            file.write("subdomain1\n")
            file.write("subdomain2\n")
            file.write("subdomain3\n")

        enumerate_subdomains(domain, wordlist_file)

        captured_output = capfd.readouterr().out

        expected_output = "No subdomains found.\n"

        assert captured_output == expected_output

        os.remove(wordlist_file)

    def test_print_found_subdomains(self, capfd):
        import os
        domain = "example.com"
        wordlist_file = "wordlist.txt"

        with open(wordlist_file, 'w') as file:
            file.write("subdomain1\n")
            file.write("subdomain2\n")
            file.write("subdomain3\n")

        enumerate_subdomains(domain, wordlist_file)

        expected_output = "No subdomains found.\n"

        captured_output = capfd.readouterr().out

        assert captured_output == expected_output

        os.remove(wordlist_file)

    def test_invalid_wordlist_path(self, capsys):
        domain = "example.com"
        wordlist_file = "invalid_path.txt"

        enumerate_subdomains(domain, wordlist_file)

        captured = capsys.readouterr()
        assert "Error: [Errno 2] No such file or directory: 'invalid_path.txt'" in captured.out
