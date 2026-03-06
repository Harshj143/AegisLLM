#!/usr/bin/env python3
"""
AegisLLM Differential Scanner Runner

Bridges AegisLLM's internal API and external baselines 
with Basilisk's differential.py to run comparative attacks.
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

from basilisk.differential import run_differential, print_diff_report
from basilisk.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse
from basilisk.providers.litellm_adapter import LiteLLMAdapter
from scripts.prompt_tester import send_chat_message

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("aegis_diff")


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
            None, send_chat_message, self.url, prompt, "diff_scan", "diff-0", self.request_config
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


async def run_diff_async(args):
    """Async entrypoint for differential scan."""
    request_config = None
    if args.config_file and os.path.exists(args.config_file):
        with open(args.config_file, "r") as f:
            request_config = json.load(f)

    adapters = []
    targets_meta = []
    
    # Target 1: Aegis App
    if args.url:
        aegis_adapter = AegisProvider(url=args.url, request_config=request_config)
        adapters.append(("aegis_backend", "target_app", aegis_adapter))
        targets_meta.append({"provider": "aegis_backend", "model": "target_app"})

    # Target 2: Baseline (LiteLLM)
    if args.baseline:
        # e.g., 'openai/gpt-4' or just 'gpt-4'
        parts = args.baseline.split("/", 1)
        provider_name = parts[0] if len(parts) > 1 else "openai"
        model_name = parts[1] if len(parts) > 1 else parts[0]
        
        litellm_adapter = LiteLLMAdapter(
            api_key=os.getenv("OPENAI_API_KEY", ""), # Example assuming env vars are set
            provider=provider_name,
            default_model=args.baseline,
        )
        adapters.append((provider_name, model_name, litellm_adapter))
        targets_meta.append({"provider": provider_name, "model": model_name})

    if len(adapters) < 2:
        logger.warning("Differential scans are best run with at least 2 targets. Proceeding anyway.")
        
    logger.info("Starting Differential Scan...")
    
    report = await run_differential(
        targets=targets_meta,
        verbose=True,
        adapters=adapters
    )

    logger.info(f"Scan complete. Found {report.total_divergences} divergences out of {report.total_probes} probes.")
    
    report_dict = report.to_dict()
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    logger.info(f"Results saved to {args.output}")


def main():
    parser = argparse.ArgumentParser(description="Run Differential Scan")
    parser.add_argument("-u", "--url", required=True, help="Target Aegis API URL")
    parser.add_argument("-b", "--baseline", required=False, help="Baseline model via LiteLLM (e.g., openai/gpt-3.5-turbo)")
    parser.add_argument("-o", "--output", required=True, help="Output JSON path")
    parser.add_argument("-j", "--config-file", type=str, help="JSON file containing request config")
    
    args = parser.parse_args()
    asyncio.run(run_diff_async(args))


if __name__ == "__main__":
    main()
