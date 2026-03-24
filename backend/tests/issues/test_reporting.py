import pytest
from issues.reporting import generate_campaign_report, generate_issue_report


class TestCampaignReport:
    @pytest.mark.asyncio
    async def test_markdown_report(self):
        report = await generate_campaign_report(
            "camp_1", format="md",
            campaign_data={"preset": "quick", "status": "completed"},
            issues=[{"severity": "high", "title": "SQL Injection", "disposition": "confirmed_security_issue", "description": "test"}],
            targets=[{"entrypoint": "GET /api/users", "kind": "api_route", "language": "python", "stateful": False, "priority_score": 0.8}],
        )
        assert "# Campaign Report" in report
        assert "SQL Injection" in report
        assert "GET /api/users" in report

    @pytest.mark.asyncio
    async def test_json_report(self):
        report = await generate_campaign_report("camp_1", format="json")
        import json
        data = json.loads(report)
        assert data["campaign_id"] == "camp_1"

    @pytest.mark.asyncio
    async def test_empty_report(self):
        report = await generate_campaign_report("camp_1")
        assert "No validated issues found" in report


class TestIssueReport:
    @pytest.mark.asyncio
    async def test_issue_report_with_data(self):
        report = await generate_issue_report("iss_1", issue_data={
            "title": "XSS", "severity": "high", "disposition": "confirmed_security_issue",
            "description": "Reflected XSS", "root_cause": "Missing escaping",
            "recommended_fix": "Escape output", "proof": {"target_real": True, "reproduced_cleanly": True},
        })
        assert "XSS" in report
        assert "Missing escaping" in report
        assert "\u2705" in report

    @pytest.mark.asyncio
    async def test_issue_report_no_data(self):
        report = await generate_issue_report("iss_1")
        assert "No data available" in report
