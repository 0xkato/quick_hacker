"""Integration tests for agent flow tree end-to-end functionality."""
import pytest
from unittest.mock import Mock, AsyncMock, patch
from agents.react import ReActSecurityAgent
from models.schemas import AgentCreateRequest, AgentType, ProviderConfig, ProviderType
from services.flow_service import flow_service


@pytest.fixture
def agent_id():
    """Fixture providing unique agent ID."""
    return "test-agent-e2e"


@pytest.fixture(autouse=True)
def cleanup(agent_id):
    """Clean up flow after each test."""
    yield
    flow_service.clear_flow(agent_id)


@pytest.fixture
def mock_provider():
    """Mock LLM provider."""
    provider = Mock()
    provider.provider_type = "mock"
    provider.model = "mock-model"
    provider.chat_with_tools = AsyncMock(return_value={
        "content": "AUDIT_COMPLETE",
        "tool_calls": None,
        "usage": None
    })
    return provider


@pytest.fixture
def agent_request():
    """Create a test agent request."""
    return AgentCreateRequest(
        repo_id="test-repo",
        agent_type=AgentType.DEEP_AUDIT,
        provider_config=ProviderConfig(
            provider=ProviderType.ANTHROPIC,
            model="claude-sonnet-4-5-20250929"
        )
    )


@pytest.mark.asyncio
async def test_extract_functions_from_python_code(agent_request, mock_provider):
    """Test that _extract_functions_from_code extracts Python functions correctly."""
    # Create agent
    with patch('agents.react_agent.get_provider', return_value=mock_provider):
        agent = ReActSecurityAgent(
            request=agent_request,
            repo_path="/tmp/test",
            on_message=None
        )

    # Test Python code
    python_code = """
def simple_function():
    pass

async def async_function(param1, param2):
    return True

def function_with_args(x, y, z=None):
    print(x)
"""

    functions = agent._extract_functions_from_code(python_code)

    assert len(functions) == 3
    assert functions[0]["name"] == "simple_function"
    assert functions[0]["line_number"] == 2
    assert functions[1]["name"] == "async_function"
    assert functions[1]["line_number"] == 5
    assert functions[2]["name"] == "function_with_args"
    assert functions[2]["line_number"] == 8


@pytest.mark.asyncio
async def test_extract_functions_from_javascript_code(agent_request, mock_provider):
    """Test that _extract_functions_from_code extracts JavaScript functions correctly."""
    # Create agent
    with patch('agents.react_agent.get_provider', return_value=mock_provider):
        agent = ReActSecurityAgent(
            request=agent_request,
            repo_path="/tmp/test",
            on_message=None
        )

    # Test JavaScript code
    js_code = """
function handleUpload(req, res) {
    return true;
}

export async function validateFile(file) {
    return true;
}

function* generator() {
    yield 1;
}
"""

    functions = agent._extract_functions_from_code(js_code)

    assert len(functions) == 3
    assert functions[0]["name"] == "handleUpload"
    assert functions[0]["line_number"] == 2
    assert functions[1]["name"] == "validateFile"
    assert functions[1]["line_number"] == 6
    assert functions[2]["name"] == "generator"
    assert functions[2]["line_number"] == 10


@pytest.mark.asyncio
async def test_extract_calls_from_analysis(agent_request, mock_provider):
    """Test that _extract_calls_from_analysis extracts function calls from analysis text."""
    # Create agent
    with patch('agents.react_agent.get_provider', return_value=mock_provider):
        agent = ReActSecurityAgent(
            request=agent_request,
            repo_path="/tmp/test",
            on_message=None
        )

    # Test analysis text with various call patterns
    analysis = """
    This function calls validate_input() to check the data.
    It also invokes process_data() for processing.
    Finally, it executes database.save() to persist the results.
    """

    calls = agent._extract_calls_from_analysis(analysis)

    assert len(calls) == 3
    assert calls[0]["target_function"] == "validate_input"
    assert calls[0]["call_type"] == "internal"
    assert calls[1]["target_function"] == "process_data"
    assert calls[1]["call_type"] == "internal"
    assert calls[2]["target_function"] == "database.save"
    assert calls[2]["call_type"] == "internal"


@pytest.mark.asyncio
async def test_extract_functions_handles_empty_code(agent_request, mock_provider):
    """Test that _extract_functions_from_code handles empty or invalid input."""
    # Create agent
    with patch('agents.react_agent.get_provider', return_value=mock_provider):
        agent = ReActSecurityAgent(
            request=agent_request,
            repo_path="/tmp/test",
            on_message=None
        )

    # Test empty code
    assert agent._extract_functions_from_code("") == []
    assert agent._extract_functions_from_code(None) == []

    # Test code without functions
    code_without_functions = """
x = 1
y = 2
print(x + y)
"""
    assert agent._extract_functions_from_code(code_without_functions) == []


@pytest.mark.asyncio
async def test_extract_calls_handles_empty_analysis(agent_request, mock_provider):
    """Test that _extract_calls_from_analysis handles empty or invalid input."""
    # Create agent
    with patch('agents.react_agent.get_provider', return_value=mock_provider):
        agent = ReActSecurityAgent(
            request=agent_request,
            repo_path="/tmp/test",
            on_message=None
        )

    # Test empty analysis
    assert agent._extract_calls_from_analysis("") == []
    assert agent._extract_calls_from_analysis(None) == []

    # Test analysis without calls
    analysis_without_calls = "This is just plain text without any function references."
    assert agent._extract_calls_from_analysis(analysis_without_calls) == []


@pytest.mark.asyncio
async def test_flow_integration_with_file_read(agent_request, mock_provider, agent_id):
    """Test that file reading creates proper flow tree structure."""
    # Create agent with specific ID for tracking
    with patch('agents.react_agent.get_provider', return_value=mock_provider):
        agent = ReActSecurityAgent(
            request=agent_request,
            repo_path="/tmp/test",
            on_message=None
        )
        agent.id = agent_id  # Override ID for testing

    # Initialize flow
    flow_service.initialize_flow(agent_id)

    # Create scan node
    scan_node = flow_service.add_node(
        agent_id,
        "scan",
        "Attack Surface Scan",
        {}
    )

    # Create candidate node
    candidate_node = flow_service.add_node(
        agent_id,
        "entry_point",
        "POST /api/upload",
        {"file_path": "routes/api.py", "line_number": 45},
        parent_id=scan_node.id,
        set_current=False
    )

    # Set context
    flow_service.update_context(
        agent_id,
        current_candidate_node_id=candidate_node.id
    )

    # Simulate file read: Create file node
    file_path = "routes/api.py"
    file_node = flow_service.add_node(
        agent_id,
        "file",
        f"📄 api.py",
        {"file_path": file_path, "full_path": file_path},
        auto_parent=True,
        set_current=False
    )

    # Update context to current file
    flow_service.update_context(agent_id, current_file=file_path)

    # Extract functions using agent's helper method
    code = """
def handle_upload(request):
    file = request.files['upload']
    validate_file(file)
    return save_file(file)

def validate_file(file):
    if not file.filename.endswith('.jpg'):
        raise ValueError("Invalid file type")
"""

    functions = agent._extract_functions_from_code(code)

    # Create function nodes
    for func in functions[:10]:  # Limit like the real implementation
        func_node = flow_service.add_node(
            agent_id,
            "function",
            f"⚡ {func['name']}()",
            {
                "function_name": func["name"],
                "line_number": func.get("line_number"),
                "signature": func.get("signature"),
            },
            parent_id=file_node.id,
            auto_parent=False,
            set_current=False
        )

    # Verify tree structure
    flow = flow_service.get_flow(agent_id)

    # Should have: scan, candidate, file, and 2 functions = 5 nodes
    assert len(flow.nodes) == 5

    # Verify edges
    edges_by_target = {e.target: e.source for e in flow.edges}

    assert edges_by_target[candidate_node.id] == scan_node.id
    assert edges_by_target[file_node.id] == candidate_node.id

    # Verify function nodes are children of file node
    function_nodes = [n for n in flow.nodes if n.type == "function"]
    assert len(function_nodes) == 2
    assert function_nodes[0].label == "⚡ handle_upload()"
    assert function_nodes[1].label == "⚡ validate_file()"

    for func_node in function_nodes:
        assert edges_by_target[func_node.id] == file_node.id


@pytest.mark.asyncio
async def test_extract_functions_multiline_limitation(agent_request, mock_provider):
    """Test and document the behavior with multiline function signatures."""
    # Create agent
    with patch('agents.react_agent.get_provider', return_value=mock_provider):
        agent = ReActSecurityAgent(
            request=agent_request,
            repo_path="/tmp/test",
            on_message=None
        )

    # Multiline function signatures are detected, but signature is incomplete
    multiline_code = """
def multiline_function(
    param1,
    param2
):
    pass
"""

    functions = agent._extract_functions_from_code(multiline_code)

    # Function is detected, but signature is incomplete (only first line)
    assert len(functions) == 1
    assert functions[0]["name"] == "multiline_function"
    assert "def multiline_function(" in functions[0]["signature"]
    # Note: The full signature "(param1, param2)" is not captured

    # Single-line signatures work the same way (captures "def name(")
    single_line_code = """
def multiline_function(param1, param2):
    pass
"""

    functions = agent._extract_functions_from_code(single_line_code)
    assert len(functions) == 1
    assert functions[0]["name"] == "multiline_function"
    # Signature captures up to opening paren, not full parameter list
    assert functions[0]["signature"] == "def multiline_function("


@pytest.mark.asyncio
async def test_extract_arrow_functions_from_typescript(agent_request, mock_provider):
    """Should extract TypeScript arrow functions."""
    # Create agent
    with patch('agents.react_agent.get_provider', return_value=mock_provider):
        agent = ReActSecurityAgent(
            request=agent_request,
            repo_path="/tmp/test",
            on_message=None
        )

    code = """
const handleRequest = () => {}
export const processData = async (data) => {}
const validateInput = (input: string) => {}
    """

    functions = agent._extract_functions_from_code(code)

    assert len(functions) == 3
    assert functions[0]["name"] == "handleRequest"
    assert functions[0]["language"] == "typescript"
    assert functions[1]["name"] == "processData"
    assert functions[1]["language"] == "typescript"
    assert functions[2]["name"] == "validateInput"
    assert functions[2]["language"] == "typescript"


@pytest.mark.asyncio
async def test_extract_class_methods_from_typescript(agent_request, mock_provider):
    """Should extract TypeScript class methods."""
    # Create agent
    with patch('agents.react_agent.get_provider', return_value=mock_provider):
        agent = ReActSecurityAgent(
            request=agent_request,
            repo_path="/tmp/test",
            on_message=None
        )

    code = """
class RequestHandler {
    handleRequest() {}
    async processData() {}
    private validateInput() {}
    static getInstance() {}
}
    """

    functions = agent._extract_functions_from_code(code)

    assert len(functions) == 4
    assert functions[0]["name"] == "handleRequest"
    assert functions[0]["language"] == "typescript"
    assert functions[1]["name"] == "processData"
    assert functions[1]["language"] == "typescript"
    assert functions[2]["name"] == "validateInput"
    assert functions[2]["language"] == "typescript"
    assert functions[3]["name"] == "getInstance"
    assert functions[3]["language"] == "typescript"


@pytest.mark.asyncio
async def test_extract_decorated_methods_from_typescript(agent_request, mock_provider):
    """Should extract TypeScript decorated methods."""
    # Create agent
    with patch('agents.react_agent.get_provider', return_value=mock_provider):
        agent = ReActSecurityAgent(
            request=agent_request,
            repo_path="/tmp/test",
            on_message=None
        )

    code = """
class Controller {
    @route('/api/upload')
    handleUpload() {}

    @Get('/users/:id')
    async getUserById() {}
}
    """

    functions = agent._extract_functions_from_code(code)

    assert len(functions) == 2
    assert functions[0]["name"] == "handleUpload"
    assert "@route" in functions[0]["signature"]
    assert functions[1]["name"] == "getUserById"
    assert "@Get" in functions[1]["signature"]
