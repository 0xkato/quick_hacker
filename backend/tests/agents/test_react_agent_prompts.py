import pytest
from agents.react import ReActSecurityAgent
from services.prompt_router import PromptRouter
from models.schemas import AgentCreateRequest, AgentType, ProviderConfig, ProviderType

def test_react_agent_uses_prompt_router_for_sql_injection():
    """Test ReAct agent assembles prompts with SQL injection checklist."""
    router = PromptRouter()
    modules = router.route(category="SQL_INJECTION")
    prompt = router.assemble_from_paths(modules, task="Find SQL injection vulnerabilities")

    # Verify checklist is included
    assert "sink_present" in prompt
    assert "source_controlled_input" in prompt
    assert "SQL Injection Proof Checklist" in prompt

def test_react_agent_uses_prompt_router_for_xss():
    """Test ReAct agent assembles prompts with XSS checklist."""
    router = PromptRouter()
    modules = router.route(category="XSS")
    prompt = router.assemble_from_paths(modules, task="Find XSS vulnerabilities")

    # Verify XSS-specific items
    assert "security_control_bypassed" in prompt
    assert "XSS" in prompt

def test_react_agent_detects_category_from_focus_areas():
    """Test ReAct agent detects category from focus_areas."""
    request = AgentCreateRequest(
        repo_id="test-repo",
        agent_type=AgentType.DEEP_AUDIT,
        provider_config=ProviderConfig(
            provider=ProviderType.ANTHROPIC,
            model="claude-sonnet-4-5-20250929",
            api_key="test-key"
        ),
        focus_areas=["SQL injection", "database queries"]
    )

    agent = ReActSecurityAgent(
        request=request,
        repo_path="/tmp/test"
    )

    # Test category detection
    category = agent._detect_category_from_focus_areas()
    assert category == "SQL_INJECTION"

def test_react_agent_builds_prompt_with_checklist():
    """Test ReAct agent builds system prompt with validity checklist when category is detected."""
    request = AgentCreateRequest(
        repo_id="test-repo",
        agent_type=AgentType.DEEP_AUDIT,
        provider_config=ProviderConfig(
            provider=ProviderType.ANTHROPIC,
            model="claude-sonnet-4-5-20250929",
            api_key="test-key"
        ),
        focus_areas=["XSS vulnerabilities"]
    )

    agent = ReActSecurityAgent(
        request=request,
        repo_path="/tmp/test"
    )

    # Detect category
    category = agent._detect_category_from_focus_areas()
    assert category == "XSS"

    # Build prompt with checklist
    repo_info = "Test repository"
    prompt = agent._build_system_prompt_with_checklist(category, repo_info)

    # Verify checklist items are included
    assert "security_control_bypassed" in prompt
    assert "sink_present" in prompt
    assert "XSS" in prompt

def test_react_agent_falls_back_without_focus_areas():
    """Test ReAct agent uses default prompt when no focus areas provided."""
    request = AgentCreateRequest(
        repo_id="test-repo",
        agent_type=AgentType.DEEP_AUDIT,
        provider_config=ProviderConfig(
            provider=ProviderType.ANTHROPIC,
            model="claude-sonnet-4-5-20250929",
            api_key="test-key"
        ),
        focus_areas=None
    )

    agent = ReActSecurityAgent(
        request=request,
        repo_path="/tmp/test"
    )

    # Should return None when no focus areas
    category = agent._detect_category_from_focus_areas()
    assert category is None

    # Should use default prompt
    repo_info = "Test repository"
    prompt = agent._build_system_prompt_with_checklist(category, repo_info)

    # Should not include specific checklist items
    assert "security_control_bypassed" not in prompt
    # But should include generic ReAct instructions
    assert len(prompt) > 0

def test_react_agent_detects_command_injection_not_sql():
    """Test that 'command injection' focus detects COMMAND_INJECTION, not SQL_INJECTION."""
    request = AgentCreateRequest(
        repo_id="test-repo",
        agent_type=AgentType.DEEP_AUDIT,
        provider_config=ProviderConfig(
            provider=ProviderType.ANTHROPIC,
            model="claude-sonnet-4-5-20250929",
            api_key="test-key"
        ),
        focus_areas=["command injection"]
    )

    agent = ReActSecurityAgent(
        request=request,
        repo_path="/tmp/test"
    )

    # Should detect COMMAND_INJECTION
    category = agent._detect_category_from_focus_areas()
    assert category == "COMMAND_INJECTION", f"Expected COMMAND_INJECTION but got {category}"

def test_react_agent_detects_code_injection_not_sql():
    """Test that 'code injection' focus detects CODE_INJECTION, not SQL_INJECTION."""
    request = AgentCreateRequest(
        repo_id="test-repo",
        agent_type=AgentType.DEEP_AUDIT,
        provider_config=ProviderConfig(
            provider=ProviderType.ANTHROPIC,
            model="claude-sonnet-4-5-20250929",
            api_key="test-key"
        ),
        focus_areas=["code injection"]
    )

    agent = ReActSecurityAgent(
        request=request,
        repo_path="/tmp/test"
    )

    # Should detect CODE_INJECTION
    category = agent._detect_category_from_focus_areas()
    assert category == "CODE_INJECTION", f"Expected CODE_INJECTION but got {category}"
