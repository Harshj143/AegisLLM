# AegisLLM 🛡️

AegisLLM is a powerful, automated security testing suite designed to identify, evaluate, and mitigate vulnerabilities in Large Language Model (LLM) applications. It maps directly to the **OWASP LLM Top 10** to provide actionable security insights, and features advanced algorithmic modules via the ThreatForge Attack Suite for deep penetration testing.

![AegisLLM Dashboard](output.png)

## 🚀 Key Features

- **Automated Prompt Testing**: Test thousands of injection and jailbreak prompts against your chat endpoints via CSV files.
- **Intelligent Injection Judging**: Uses "LLM-as-a-Judge" evaluation to automatically score the success rate of complex injection attacks.
- **Determinism Probing**: Analyze LLM behavior for consistency and identify potential data leakage or bypassing of safety filters.
- **Rate-Limit Analysis (LLM10)**: Stress test endpoints to ensure robust rate-limiting and DoS protection.
- **Modern Web Dashboard**: A Flask-based local web server (`web_app.py`) providing a visual GUI with real-time logs, progress bars, and formatted HTML results.
- **Flexible Configuration**: Complete support for JSON request templates, authentication cookies, and multiple API providers (OpenAI, Anthropic, local Ollama).

---

## 💥 Advanced Modules (ThreatForge Attack Suite)

AegisLLM goes beyond simple CSV prompt sending by integrating advanced algorithmic test modules:

### 🧬 SPE-NL Genetic Algorithm (LLM-EVO)
Uses "Smart Prompt Evolution" to take a seed set of failed jailbreak prompts and mutate them over multiple generations. 
* **Dynamic Scoring**: Instead of a pass/fail, payloads are scored (0.0 to 1.0) on a weighted scale considering:
  - Refusal Avoidance (30%)
  - Information Leakage (25%)
  - Instruction Compliance (20%)
  - Novelty/Diversity (10%)
  - Target Pattern Matching (10%)
  - Substantive Length (5%)
* Payloads scoring >= 0.85 are flagged as **Breakthroughs** that successfully bypass guardrails.

### �️ Guardrail Posture Scan (LLM-POSTURE)
A rapid, non-destructive assessment that sends a diverse baseline of prompts (hate speech, PII requests, self-harm) to grade your endpoint's inherent safety filters and return an **Overall Grade** and **Coverage Score** before any heavy penetration testing begins.

### ⚖️ Differential Attack Scan (LLM-DIFF)
Identifies unique weaknesses in a fine-tuned or custom-prompted model by sending identical payloads to both your target application and a known baseline model (like an unmodified `gpt-4`). It highlights **divergences** where the baseline model safely refuses, but your target model complies.

### 🕵️ Reconnaissance Scan (LLM-RECON)
An active fingerprinting module that attempts to automatically:
* Fingerprint the underlying backend model (e.g., detecting if a wrapped system is actually Claude).
* Detect if the model relies on RAG (Retrieval-Augmented Generation).
* Enumerate any external tools, APIs, or database connections the model has access to.

---

## 🛠️ Tool Architecture (The Scripts)

| Script / Module | Purpose | OWASP Mapping |
|--------|---------|---------------|
| `prompt_tester.py` | Orchestrates batch testing of CSV prompts. | LLM01, LLM02, LLM05, LLM07, LLM09 |
| `injection_judge.py` | Evaluates if an injection was successful. | LLM01, LLM02 |
| `Rate-limit.py` | Tests API resilience and request throttling. | LLM10 (Unbounded Consumption) |
| `run_evolution.py` | Runs the LLM-EVO genetic algorithm. | Advanced LLM01 |
| `run_posture.py` | Runs the non-destructive guardrail scan. | Baseline Assessment |
| `run_differential.py`| Runs comparative vulnerability testing. | Advanced Recon |
| `run_recon.py` | Fingerprints tools, models, and RAG usage. | Reconnaissance |

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
   - Add your API keys (e.g., `OPENAI_API_KEY` for the Judge and Differential testing) and target URLs.
   ```bash
   cp .env.example .env
   ```

## 📖 Usage

### Running the Web Dashboard (Recommended)
Launch the Flask frontend bridge to use the GUI:
```bash
python web_app.py
```
Then open `http://127.0.0.1:8090` in your browser.

### Running via the Interactive CLI
Launch the terminal-based menu to configure tests interactively:
```bash
python main.py
```

### Running Scripts Manually
You can run any module directly. For example, a basic prompt test:
```bash
python scripts/prompt_tester.py --input prompts/jailbreaks.csv --url http://your-app.com/api
```
Or evaluating results using the automated judge:
```bash
python scripts/injection_judge.py --input results/test_results.csv --model gpt-4o
```

## 🛡️ Security Disclaimer

This tool is for educational and authorized security testing purposes only. Never use AegisLLM against systems you do not own or have explicit permission to test.

## 📄 License

[MIT](LICENSE)
