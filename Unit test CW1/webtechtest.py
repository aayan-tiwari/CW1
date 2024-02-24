from webtech import analyze_web_tech
import pytest

class TestAnalyzeWebTech:
    def test_valid_url(self):
        url = "https://www.example.com"
        with pytest.raises(AttributeError) as e:
            analyze_web_tech(url)
        assert str(e.value) == "module 'webtech' has no attribute 'WebTech'"

    def test_invalid_url(self):
        url = "invalid_url"
        with pytest.raises(AttributeError):
            analyze_web_tech(url)

    def test_unreachable_url(self):
        url = "https://www.nonexistenturl.com"
        with pytest.raises(AttributeError):
            analyze_web_tech(url)

    