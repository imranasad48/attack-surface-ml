from asm.config import Settings


def test_settings_loads_from_env() -> None:
    s = Settings()  # type: ignore[call-arg]
    assert s.api_key == "test-key"
    assert s.app_env == "development"
