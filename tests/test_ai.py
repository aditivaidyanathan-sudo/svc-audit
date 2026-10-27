from types import SimpleNamespace

from conftest import make_account

from warden.ai import build_prompt, suggest_purpose


class FakeClient:
    def __init__(self, text):
        self.text = text
        self.calls = 0
        self.messages = self

    def create(self, **kwargs):
        self.calls += 1
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=self.text)])


def test_suggestion_is_labelled_unverified():
    client = FakeClient('{"purpose": "payments API", "likely_team": "Finance", "confidence": "medium"}')
    result = suggest_purpose(make_account(), client=client)
    assert result.startswith("UNVERIFIED:")
    assert "team=Finance" in result


def test_bad_model_output_is_ignored():
    assert suggest_purpose(make_account(), client=FakeClient("not json")) is None


def test_no_description_means_no_call():
    client = FakeClient("{}")
    assert suggest_purpose(make_account(description=""), client=client) is None
    assert client.calls == 0


def test_prompt_contains_no_owner_data():
    prompt = build_prompt(make_account(owner_email="ann.lee@corp.example"))
    assert "ann.lee" not in prompt
