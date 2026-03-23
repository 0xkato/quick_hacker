"""Campaign report generation.

v1: Basic markdown report from campaign issues + coverage.
"""


async def generate_campaign_report(campaign_id: str, format: str = "md") -> str:
    """Generate a campaign report.

    v1: Returns a basic markdown template.
    """
    return f"# Campaign Report\n\nCampaign: {campaign_id}\n\nReport generation coming soon."


async def generate_issue_report(issue_id: str, format: str = "md") -> str:
    """Generate a single issue report.

    v1: Returns a basic markdown template.
    """
    return f"# Issue Report\n\nIssue: {issue_id}\n\nReport generation coming soon."
