#!/usr/bin/env python3
"""
AegisLLM Posture Scan Runner

Bridges AegisLLM's internal API with Basilisk's posture.py to run non-destructive
guardrail assessments.
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

from basilisk.posture import run_posture_scan, save_posture_report
from basilisk.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse
from scripts.prompt_tester import send_chat_message

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("aegis_posture")


class AegisProvider(ProviderAdapter):
    """
    Wraps AegisLLM's `send_chat_message` into the Basilisk ProviderAdapter interface.
    """
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
            None, 
            send_chat_message, 
            self.url, 
            prompt, 
            "posture_scan", 
            "post-0", 
            self.request_config
        )

        response = ProviderResponse(model=model or "unknown")
        
        if success:
            response.content = data.get('extracted_response', data.get('response', ''))
        else:
            response.error = data.get('error', f'HTTP {status_code}')
            
        return response

    async def send_streaming(self, *args, **kwargs) -> AsyncIterator[str]:
        raise NotImplementedError("Streaming not supported by AegisProvider")


async def run_scan_async(args):
    """Async entrypoint for the posture scan."""
    request_config = None
    if args.config_file and os.path.exists(args.config_file):
        with open(args.config_file, "r") as f:
            request_config = json.load(f)

    provider = AegisProvider(url=args.url, request_config=request_config)
    
    logger.info("Starting Guardrail Posture Scan...")
    
    report = await run_posture_scan(
        provider=provider,
        target=args.url,
        provider_name="aegis_backend",
        verbose=True
    )

    logger.info(f"Scan complete. Overall Grade: {report.overall_grade} ({report.overall_score:.0%} coverage)")
    
    report_dict = report.to_dict()
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    logger.info(f"Results saved to {args.output}")


def main():
    parser = argparse.ArgumentParser(description="Run Basilisk Posture Scan")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", required=True, help="Output JSON path")
    parser.add_argument("-j", "--config-file", type=str, help="JSON file containing request config like headers/method")
    
    args = parser.parse_args()
    asyncio.run(run_scan_async(args))


if __name__ == "__main__":
    main()
