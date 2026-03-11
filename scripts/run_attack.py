#!/usr/bin/env python3
"""
AegisLLM Attack Suite Runner

Bridges AegisLLM's internal API with ThreatForge's attack orchestrator.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, AsyncIterator, List

BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

from threatforge.core.profile import ThreatForgeProfile
from threatforge.attacks.base import get_all_attack_modules
from threatforge.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse
from scripts.prompt_tester import send_chat_message

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("aegis_attack")


class AegisProvider(ProviderAdapter):
    """Wraps AegisLLM's internal API caller."""
    name = "aegis_backend"

    def __init__(self, url: str, request_config: dict | None = None, repeat: int = 1):
        self.url = url
        self.request_config = request_config or {}
        self.repeat = repeat

    async def send(
        self,
        messages: List[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> ProviderResponse:
        prompt = ""
        for msg in reversed(messages):
            if msg.role == "user":
                prompt = msg.content
                break

        loop = asyncio.get_event_loop()
        success, data, status_code = await loop.run_in_executor(
            None, send_chat_message, self.url, prompt, "attack_scan", "atk-0", self.request_config
        )

        response = ProviderResponse(model=model or "unknown")
        
        if success:
            response.content = data.get('extracted_response', data.get('response', ''))
        else:
            response.error = data.get('error', f'HTTP {status_code}')
            
        return response

    async def send_streaming(self, *args, **kwargs) -> AsyncIterator[str]:
        raise NotImplementedError("Streaming not supported.")

    async def close(self):
        pass


class MockSession:
    """A lightweight mock session to capture findings from attacks without needing a DB."""
    def __init__(self):
        self.findings = []
        self.errors = []
        
    async def add_finding(self, finding):
        self.findings.append(finding)
        
    async def add_error(self, module, error, severity="error"):
        self.errors.append({"module": module, "error": error, "severity": severity})
        
    async def save_conversation(self, *args, **kwargs):
        pass
        
    async def save_evolution_entry(self, *args, **kwargs):
        pass


async def run_attacks_async(args):
    """Async entrypoint for running attacks."""
    request_config = None
    if args.config_file and os.path.exists(args.config_file):
        with open(args.config_file, "r") as f:
            request_config = json.load(f)

    provider = AegisProvider(url=args.url, request_config=request_config)
    profile = ThreatForgeProfile(target_url=args.url)
    session = MockSession()
    
    all_attacks = get_all_attack_modules()
    selected_attacks = []
    
    if args.categories:
        cats = [c.lower() for c in args.categories.split(",")]
        for atk in all_attacks:
            if atk.category.value.lower() in cats or atk.name.split('.')[0].lower() in cats:
                selected_attacks.append(atk)
    else:
        selected_attacks = all_attacks

    logger.info(f"Starting Attack Suite. Loaded {len(selected_attacks)} modules.")
    
    for atk in selected_attacks:
        logger.info(f"[+] Running {atk.name}...")
        try:
            await atk.execute(provider, session, profile)
        except Exception as e:
            logger.error(f"[-] Module {atk.name} failed: {e}")
            await session.add_error(atk.name, str(e))

    logger.info(f"Scan complete. Discovered {len(session.findings)} vulnerabilities.")

    # Convert the dataclass to dict safely
    import dataclasses
    def _asdict_safe(obj):
        if obj is None:
            return None
        if isinstance(obj, (bool, int, float, str)):
            return obj
        if isinstance(obj, list):
            return [_asdict_safe(i) for i in obj]
        if isinstance(obj, dict):
            return {k: _asdict_safe(v) for k, v in obj.items()}
        if dataclasses.is_dataclass(obj):
            return {k: _asdict_safe(v) for k, v in dataclasses.asdict(obj).items()}
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        if hasattr(obj, 'value'): # Handle enums
            return obj.value
        return str(obj)

    report_dict = {
        "total_findings": len(session.findings),
        "total_errors": len(session.errors),
        "findings": [_asdict_safe(f) for f in session.findings],
        "errors": session.errors
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    logger.info(f"Results saved to {args.output}")


def main():
    parser = argparse.ArgumentParser(description="Run ThreatForge Attack Suite")
    parser.add_argument("-u", "--url", required=True, help="Target Aegis API URL")
    parser.add_argument("-o", "--output", required=True, help="Output JSON path")
    parser.add_argument("-c", "--categories", required=False, help="Comma-separated list of categories (e.g. injection,dos,exfil)")
    parser.add_argument("-j", "--config-file", type=str, help="JSON file containing request config")
    
    args = parser.parse_args()
    asyncio.run(run_attacks_async(args))


if __name__ == "__main__":
    main()
