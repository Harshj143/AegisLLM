# AegisLLM 🛡️

AegisLLM is a powerful, automated security testing suite designed to identify, evaluate, and mitigate vulnerabilities in Large Language Model (LLM) applications. It maps directly to the **OWASP LLM Top 10** to provide actionable security insights.

## 🚀 Features

- **Automated Prompt Testing**: Test thousands of injection and jailbreak prompts against your chat endpoints.
- **Intelligent Injection Judging**: Uses LLM-based evaluation to determine the success rate of complex injection attacks.
- **Determinism Probing**: Analyze LLM behavior for consistency and identify potential data leakage or bypassing of safety filters.
- **Rate-Limit Analysis**: Stress test endpoints to ensure robust rate-limiting and DoS protection.
- **Flexible Configuration**: Support for multiple API providers (OpenAI, Anthropic, etc.) and local models (Ollama).

## 🛠️ Tool Overview (The Scripts)

| Script | Purpose | OWASP Mapping |
|--------|---------|---------------|
| `prompt_tester.py` | Orchestrates batch testing of prompts. | LLM01 (Prompt Injection) |
| `injection_judge.py` | Evaluates if an injection was successful. | LLM01, LLM02 |
| `Probing.py` | Tests for determinism and consistency. | LLM02 (Insecure Output), LLM06 |
| `Rate-limit.py` | Tests API resilience and rate limits. | LLM04 (Model Denial of Service) |

## 📦 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Harshj143/AegisLLM.git
   cd AegisLLM
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment**:
   - Copy `.env.example` to `.env`.
   - Add your API keys and target URLs.
   ```bash
   cp .env.example .env
   ```

## 📖 Usage

### Running a Prompt Test
```bash
python scripts/prompt_tester.py --input prompts/jailbreaks.csv --url http://your-app.com/api
```

### Judging Results
```bash
python scripts/injection_judge.py --input results/test_results.csv --model gpt-4o
```

## 🛡️ Security Disclaimer

This tool is for educational and authorized security testing purposes only. Never use AegisLLM against systems you do not own or have explicit permission to test.

## 📄 License

[MIT](LICENSE)
