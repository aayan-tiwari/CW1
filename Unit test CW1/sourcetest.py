
from source import get_source_code
import pytest
class TestGetSourceCode:
    def test_valid_url_with_status_code_200(self):
        url = "https://www.example.com"
        expected_source_code = "<!doctype html>\n<html>\n<head>\n    <title>Example Domain</title>\n\n    <meta charset=\"utf-8\" />\n    <meta http-equiv=\"Content-type\" content=\"text/html; charset=utf-8\" />\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n    <style type=\"text/css\">\n    body {\n        background-color: #f0f0f2;\n        margin: 0;\n        padding: 0;\n        font-family: -apple-system, system-ui, BlinkMacSystemFont, \"Segoe UI\", \"Open Sans\", \"Helvetica Neue\", Helvetica, Arial, sans-serif;\n        \n    }\n    div {\n        width: 600px;\n        margin: 5em auto;\n        padding: 2em;\n        background-color: #fdfdff;\n        border-radius: 0.5em;\n        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);\n    }\n    a:link, a:visited {\n        color: #38488f;\n        text-decoration: none;\n    }\n    @media (max-width: 700px) {\n        div {\n            margin: 0 auto;\n            width: auto;\n        }\n    }\n    </style>    \n</head>\n\n<body>\n<div>\n    <h1>Example Domain</h1>\n    <p>This domain is for use in illustrative examples in documents. You may use this\n    domain in literature without prior coordination or asking for permission.</p>\n    <p><a href=\"https://www.iana.org/domains/example\">More information...</a></p>\n</div>\n</body>\n</html>\n"

        source_code = get_source_code(url)

        assert source_code == expected_source_code

    def test_url_with_non_200_status_code(self):
        url = "https://www.example.com/404"
        expected_error_message = "Failed to retrieve source code. Status code: 404"
    
        error_message = get_source_code(url)
    
        assert error_message == expected_error_message

    def test_invalid_url(self):
        url = "invalid_url"
        expected_error_message = "Error: Invalid URL 'invalid_url': No scheme supplied. Perhaps you meant https://invalid_url?"

        error_message = get_source_code(url)

        assert error_message == expected_error_message

    def test_empty_url(self):
        url = ""
        expected_error_message = "Error: Invalid URL '': No scheme supplied. Perhaps you meant https://?"

        error_message = get_source_code(url)

        assert error_message == expected_error_message

    def test_url_with_missing_protocol(self):
        url = "www.example.com"
        expected_error_message = "Error: Invalid URL 'www.example.com': No scheme supplied. Perhaps you meant https://www.example.com?"

        error_message = get_source_code(url)

        assert error_message == expected_error_message

    def test_url_with_missing_domain(self):
        url = "https://"
        expected_error_message = "Error: Invalid URL 'https://': No host supplied"

        error_message = get_source_code(url)

        assert error_message == expected_error_message
        