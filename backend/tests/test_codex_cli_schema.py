def test_provider_type_includes_codex_cli() -> None:
    from models.schemas import ProviderType

    assert hasattr(ProviderType, "CODEX_CLI")
    assert ProviderType.CODEX_CLI.value == "codex_cli"


def test_provider_config_accepts_codex_path() -> None:
    from models.schemas import ProviderConfig, ProviderType

    cfg = ProviderConfig(provider=ProviderType.CODEX_CLI, model="gpt-5.2-codex", codex_path="codex")
    assert cfg.codex_path == "codex"
