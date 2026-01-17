"""Default protocol policies for submission evaluation."""

from models.schemas import (
    ProtocolPolicy,
    Disposition,
    VulnerabilityCategory,
)


def get_default_policies() -> dict[str, ProtocolPolicy]:
    """Get all default protocol policies."""
    return {
        "internal": get_internal_policy(),
        "osvrp_strict": get_osvrp_strict_policy(),
        "hackerone_strict": get_hackerone_strict_policy(),
        "bugcrowd_standard": get_bugcrowd_standard_policy(),
        "research_disclosure": get_research_disclosure_policy(),
    }


def get_internal_policy() -> ProtocolPolicy:
    """Internal / permissive policy for dev/QA environments."""
    return ProtocolPolicy(
        id="internal",
        display_name="Internal (Permissive)",
        default_threat_model_preset="ABC",
        min_disposition_to_submit={
            Disposition.VALID_SECURITY_ISSUE,
            Disposition.BUG,
            Disposition.MISCONFIGURATION,
            Disposition.HARDENING
        },
        require_cross_boundary_for_local_bugs=False,
        reject_social_engineering_only=False,
        require_repro_steps=False,
        require_impact_statement=False,
        require_realistic_attacker_model=False,
        min_checklist_proven_count=3,
        allow_unknown_in_checklist=True,
        category_rules={},
        enable_evidence_quests=True,
        quest_categories=[]
    )


def get_osvrp_strict_policy() -> ProtocolPolicy:
    """Google Open Source VRP (strict interpretation)."""
    return ProtocolPolicy(
        id="osvrp_strict",
        display_name="Google VRP (Strict)",
        default_threat_model_preset="AB",
        min_disposition_to_submit={Disposition.VALID_SECURITY_ISSUE},
        require_cross_boundary_for_local_bugs=True,
        reject_social_engineering_only=True,
        require_repro_steps=True,
        require_impact_statement=True,
        require_realistic_attacker_model=True,
        min_checklist_proven_count=6,
        allow_unknown_in_checklist=False,
        category_rules={
            VulnerabilityCategory.COMMAND_INJECTION: {
                "requires_shell": True,
                "reject_argument_injection": True,
            },
            VulnerabilityCategory.SQL_INJECTION: {
                "requires_structure_taint": True,
                "reject_if_parameterized": True,
            },
            VulnerabilityCategory.HARDCODED_SECRET: {
                "reject_test_files": True,
                "reject_example_files": True,
                "reject_vendored": True,
            },
        },
        enable_evidence_quests=True,
        quest_categories=[
            VulnerabilityCategory.COMMAND_INJECTION,
            VulnerabilityCategory.SQL_INJECTION,
            VulnerabilityCategory.CODE_INJECTION,
        ]
    )


def get_hackerone_strict_policy() -> ProtocolPolicy:
    """HackerOne standard triage policy."""
    return ProtocolPolicy(
        id="hackerone_strict",
        display_name="HackerOne Standard",
        default_threat_model_preset="AB",
        min_disposition_to_submit={
            Disposition.VALID_SECURITY_ISSUE,
            Disposition.BUG
        },
        require_cross_boundary_for_local_bugs=True,
        reject_social_engineering_only=True,
        require_repro_steps=True,
        require_impact_statement=True,
        require_realistic_attacker_model=True,
        min_checklist_proven_count=5,
        allow_unknown_in_checklist=True,
        category_rules={
            VulnerabilityCategory.COMMAND_INJECTION: {
                "requires_shell": True,
            },
        },
        enable_evidence_quests=True,
        quest_categories=[]
    )


def get_bugcrowd_standard_policy() -> ProtocolPolicy:
    """Bugcrowd standard VDP policy."""
    return ProtocolPolicy(
        id="bugcrowd_standard",
        display_name="Bugcrowd Standard",
        default_threat_model_preset="AB",
        min_disposition_to_submit={
            Disposition.VALID_SECURITY_ISSUE,
            Disposition.BUG
        },
        require_cross_boundary_for_local_bugs=True,
        reject_social_engineering_only=True,
        require_repro_steps=True,
        require_impact_statement=True,
        require_realistic_attacker_model=True,
        min_checklist_proven_count=5,
        allow_unknown_in_checklist=True,
        category_rules={},
        enable_evidence_quests=True,
        quest_categories=[]
    )


def get_research_disclosure_policy() -> ProtocolPolicy:
    """Security research / responsible disclosure policy."""
    return ProtocolPolicy(
        id="research_disclosure",
        display_name="Research Disclosure",
        default_threat_model_preset="ABC",
        min_disposition_to_submit={
            Disposition.VALID_SECURITY_ISSUE,
            Disposition.BUG,
            Disposition.HARDENING
        },
        require_cross_boundary_for_local_bugs=False,
        reject_social_engineering_only=False,
        require_repro_steps=True,
        require_impact_statement=True,
        require_realistic_attacker_model=False,
        min_checklist_proven_count=4,
        allow_unknown_in_checklist=True,
        category_rules={},
        enable_evidence_quests=True,
        quest_categories=[]
    )


class ProtocolPolicyLoader:
    """Load and manage protocol policies."""

    def __init__(self, db_conn):
        self.db = db_conn

    async def seed_default_policies(self):
        """Seed database with default policies."""
        import json

        policies = get_default_policies()

        for policy_id, policy in policies.items():
            # Check if exists
            cursor = await self.db.execute(
                "SELECT id FROM protocol_policies WHERE id = ?",
                (policy_id,)
            )
            existing = await cursor.fetchone()

            # Convert to JSON-serializable format (sets -> lists)
            config_json = json.dumps(policy.model_dump(mode='json'))

            if existing:
                # Update
                await self.db.execute("""
                    UPDATE protocol_policies
                    SET config = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (config_json, policy_id))
            else:
                # Insert
                await self.db.execute("""
                    INSERT INTO protocol_policies (id, display_name, config, is_default)
                    VALUES (?, ?, ?, ?)
                """, (
                    policy.id,
                    policy.display_name,
                    config_json,
                    policy.id == "internal"
                ))

        await self.db.commit()

    async def get_policy(self, policy_id: str) -> ProtocolPolicy:
        """Load policy from database."""
        import json

        cursor = await self.db.execute(
            "SELECT config FROM protocol_policies WHERE id = ?",
            (policy_id,)
        )
        row = await cursor.fetchone()

        if not row:
            raise ValueError(f"Protocol policy not found: {policy_id}")

        config = json.loads(row[0])
        return ProtocolPolicy(**config)
