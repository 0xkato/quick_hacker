"""Seed default protocol policies into the database."""

import asyncio
import json
from sqlalchemy import text

import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database.connection import engine


DEFAULT_POLICIES = [
    {
        "id": "internal",
        "display_name": "Internal (Permissive)",
        "is_default": True,
        "config": {
            "id": "internal",
            "display_name": "Internal (Permissive)",
            "default_threat_model_preset": "ABC",
            "min_disposition_to_submit": ["VALID_SECURITY_ISSUE", "BUG", "HARDENING"],
            "require_cross_boundary_for_local_bugs": False,
            "reject_social_engineering_only": False,
            "require_repro_steps": False,
            "require_impact_statement": False,
            "require_realistic_attacker_model": False,
            "min_checklist_proven_count": 3,
            "allow_unknown_in_checklist": True,
            "category_rules": {},
            "enable_evidence_quests": True,
            "quest_categories": ["command_injection", "sql_injection", "memory_safety"]
        }
    },
    {
        "id": "osvrp_strict",
        "display_name": "Google VRP (Strict)",
        "is_default": False,
        "config": {
            "id": "osvrp_strict",
            "display_name": "Google VRP (Strict)",
            "default_threat_model_preset": "AB",
            "min_disposition_to_submit": ["VALID_SECURITY_ISSUE"],
            "require_cross_boundary_for_local_bugs": True,
            "reject_social_engineering_only": True,
            "require_repro_steps": True,
            "require_impact_statement": True,
            "require_realistic_attacker_model": True,
            "min_checklist_proven_count": 6,
            "allow_unknown_in_checklist": False,
            "category_rules": {
                "command_injection": {"requires_shell": True},
                "sql_injection": {"requires_structure_taint": True},
                "hardcoded_secrets": {"reject_test_examples": True}
            },
            "enable_evidence_quests": True,
            "quest_categories": ["command_injection", "sql_injection"]
        }
    },
    {
        "id": "hackerone_strict",
        "display_name": "HackerOne Standard",
        "is_default": False,
        "config": {
            "id": "hackerone_strict",
            "display_name": "HackerOne Standard",
            "default_threat_model_preset": "AB",
            "min_disposition_to_submit": ["VALID_SECURITY_ISSUE", "BUG"],
            "require_cross_boundary_for_local_bugs": True,
            "reject_social_engineering_only": True,
            "require_repro_steps": True,
            "require_impact_statement": True,
            "require_realistic_attacker_model": True,
            "min_checklist_proven_count": 5,
            "allow_unknown_in_checklist": True,
            "category_rules": {
                "command_injection": {"requires_shell": True}
            },
            "enable_evidence_quests": True,
            "quest_categories": ["command_injection", "sql_injection"]
        }
    },
    {
        "id": "bugcrowd_standard",
        "display_name": "Bugcrowd Standard",
        "is_default": False,
        "config": {
            "id": "bugcrowd_standard",
            "display_name": "Bugcrowd Standard",
            "default_threat_model_preset": "AB",
            "min_disposition_to_submit": ["VALID_SECURITY_ISSUE", "BUG"],
            "require_cross_boundary_for_local_bugs": True,
            "reject_social_engineering_only": True,
            "require_repro_steps": True,
            "require_impact_statement": False,
            "require_realistic_attacker_model": True,
            "min_checklist_proven_count": 5,
            "allow_unknown_in_checklist": True,
            "category_rules": {},
            "enable_evidence_quests": True,
            "quest_categories": ["command_injection", "sql_injection"]
        }
    },
    {
        "id": "research_disclosure",
        "display_name": "Research Disclosure",
        "is_default": False,
        "config": {
            "id": "research_disclosure",
            "display_name": "Research Disclosure",
            "default_threat_model_preset": "ABC",
            "min_disposition_to_submit": ["VALID_SECURITY_ISSUE", "BUG", "HARDENING"],
            "require_cross_boundary_for_local_bugs": False,
            "reject_social_engineering_only": False,
            "require_repro_steps": True,
            "require_impact_statement": True,
            "require_realistic_attacker_model": False,
            "min_checklist_proven_count": 4,
            "allow_unknown_in_checklist": True,
            "category_rules": {},
            "enable_evidence_quests": True,
            "quest_categories": ["command_injection", "sql_injection", "memory_safety"]
        }
    }
]


async def seed_policies():
    """Seed default protocol policies."""
    print("🌱 Seeding protocol policies...")

    async with engine.begin() as conn:
        # Check if policies already exist
        result = await conn.execute(text("SELECT COUNT(*) FROM protocol_policies"))
        count = result.scalar()

        if count > 0:
            print(f"⚠️  Found {count} existing policies, skipping seed")
            return

        # Insert default policies
        for policy in DEFAULT_POLICIES:
            await conn.execute(
                text("""
                    INSERT INTO protocol_policies (id, display_name, is_default, config, created_at, updated_at)
                    VALUES (:id, :display_name, :is_default, :config, NOW(), NOW())
                """),
                {
                    "id": policy["id"],
                    "display_name": policy["display_name"],
                    "is_default": policy["is_default"],
                    "config": json.dumps(policy["config"])
                }
            )
            print(f"✅ Seeded policy: {policy['display_name']}")

    print(f"🎉 Successfully seeded {len(DEFAULT_POLICIES)} protocol policies")


async def main():
    """Main entry point."""
    try:
        await seed_policies()
    except Exception as e:
        print(f"❌ Error seeding policies: {e}")
        sys.exit(1)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
