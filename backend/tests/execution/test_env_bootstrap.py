from execution.env_bootstrap import get_environment_spec, list_supported_engines

def test_list_supported_engines():
    engines = list_supported_engines()
    assert len(engines) >= 14
    assert "schemathesis" in engines
    assert "aflpp" in engines

def test_get_schemathesis_spec():
    spec = get_environment_spec("schemathesis")
    assert spec.engine == "schemathesis"
    assert spec.needs_network is True
    assert spec.resource_profile == "light"

def test_get_aflpp_spec():
    spec = get_environment_spec("aflpp")
    assert spec.engine == "aflpp"
    assert spec.resource_profile == "heavy"

def test_get_spec_with_target():
    spec = get_environment_spec("atheris", target={"language": "python"})
    assert "pip install" in spec.install_commands[0]

def test_unknown_engine_raises():
    import pytest
    with pytest.raises(ValueError):
        get_environment_spec("nonexistent")

def test_all_engines_have_specs():
    for engine in list_supported_engines():
        spec = get_environment_spec(engine)
        assert spec.dockerfile is not None
        assert spec.base_image is not None
