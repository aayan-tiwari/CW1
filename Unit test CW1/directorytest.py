
from directory import directory_bruteforce
import pytest
class TestDirectoryBruteforce:

    def test_existing_directories(self):
        base_url = "http://example.com"
        wordlist = "wordlist.txt"
        directory_bruteforce(base_url, wordlist)
    def test_base_url_trailing_slash(self):
        base_url = "http://example.com/"
        wordlist = "wordlist.txt"
        directory_bruteforce(base_url, wordlist)
    def test_wordlist_whitespace(self):
        base_url = "http://example.com"
        wordlist = " wordlist.txt "
        directory_bruteforce(base_url, wordlist)
    def test_non_existing_directories(self):
        base_url = "http://example.com"
        wordlist = "wordlist.txt"
        directory_bruteforce(base_url, wordlist)
    def test_invalid_base_url(self):
        base_url = "invalid_url"
        wordlist = "wordlist.txt"
        directory_bruteforce(base_url, wordlist)
    def test_invalid_wordlist_path(self):
        base_url = "http://example.com"
        wordlist = "invalid_path.txt"
        directory_bruteforce(base_url, wordlist)
