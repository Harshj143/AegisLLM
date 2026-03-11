#!/usr/bin/env python3
"""
AegisLLM Reconnaissance Runner

Bridges AegisLLM's internal API with ThreatForge's recon modules 
to perform fingerprinting, tool discovery, and RAG detection.
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
from threatforge.recon.fingerprint import fingerprint_model
from threatforge.recon.tools import discover_tools
from threatforge.recon.rag import detect_rag
from threatforge.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse
from scripts.prompt_tester import send_chat_message

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("aegis_recon")


class AegisProvider(ProviderAdapter):
    """Wraps AegisLLM's internal API caller."""
    name = "aegis_backend"

    def __init__(self, url: str, request_config: dict | None = None):
        self.url = url
        self.request_config = request_config or {}

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
            None, send_chat_message, self.url, prompt, "recon_scan", "recon-0", self.request_config
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


async def run_recon_async(args):
    """Async entrypoint for recon scan."""
    request_config = None
    if args.config_file and os.path.exists(args.config_file):
        with open(args.config_file, "r") as f:
            request_config = json.load(f)

    provider = AegisProvider(url=args.url, request_config=request_config)
    profile = ThreatForgeProfile(target_url=args.url)
    
    logger.info("Starting Reconnaissance Scan...")
    
    tasks = []
    
    if args.all or args.fingerprint:
        logger.info("[+] Queueing Fingerprint detection...")
        tasks.append(fingerprint_model(provider, profile))
        
    if args.all or args.tools:
        logger.info("[+] Queueing Tool discovery...")
        tasks.append(discover_tools(provider, profile))
        
    if args.all or args.rag:
        logger.info("[+] Queueing RAG detection...")
        tasks.append(detect_rag(provider, profile))

    if not tasks:
        logger.warning("No recon modules selected.")
        return

    # Run the selected recon probes concurrently
    await asyncio.gather(*tasks)

    logger.info("Reconnaissance complete.")

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

    report_dict = {}
    for k, v in dataclasses.asdict(profile).items():
        report_dict[k] = _asdict_safe(v)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    logger.info(f"Results saved to {args.output}")


def main():
    parser = argparse.ArgumentParser(description="Run Reconnaissance Scan")
    parser.add_argument("-u", "--url", required=True, help="Target Aegis API URL")
    parser.add_argument("-o", "--output", required=True, help="Output JSON path")
    parser.add_argument("-j", "--config-file", type=str, help="JSON file containing request config")
    
    parser.add_argument("--all", action="store_true", help="Run all recon modules")
    parser.add_argument("--fingerprint", action="store_true", help="Run model fingerprinting")
    parser.add_argument("--tools", action="store_true", help="Run tool discovery")
    parser.add_argument("--rag", action="store_true", help="Run RAG detection")
    
    args = parser.parse_args()
    
    if not (args.all or args.fingerprint or args.tools or args.rag):
        args.all = True # Default to all if none specified
        
    asyncio.run(run_recon_async(args))


if __name__ == "__main__":
    main()
