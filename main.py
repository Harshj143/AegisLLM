#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path

# Configuration
SCRIPTS_DIR = Path(__file__).parent / "scripts"
BASE_DIR = Path(__file__).parent
DEFAULT_URL = "http://localhost:5000/api/chat"

# Mapping OWASP LLM Top 10 (2025) to folders/scripts
OWASP_MAPPING = {
    "1": {
        "id": "LLM01",
        "name": "Prompt Injection",
        "folders": ["prompts", "jailbreaks"],
        "script": "prompt_tester.py"
    },
    "2": {
        "id": "LLM02",
        "name": "Sensitive Information Disclosure",
        "folders": ["Sensitivedata"],
        "script": "prompt_tester.py"
    },
    "3": {
        "id": "LLM05",
        "name": "Improper Output Handling",
        "folders": ["harmful_outputs", "rag"],
        "script": "prompt_tester.py"
    },
    "4": {
        "id": "LLM07",
        "name": "System Prompt Leakage",
        "folders": ["prompts"],
        "script": "prompt_tester.py"
    },
    "5": {
        "id": "LLM09",
        "name": "Misinformation",
        "folders": ["misinformation"],
        "script": "prompt_tester.py"
    },
    "6": {
        "id": "LLM10",
        "name": "Unbounded Consumption",
        "folders": [],
        "script": "Rate-limit.py"
    }
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_input(prompt, default=None):
    if default:
        user_input = input(f"{prompt} [{default}]: ").strip()
        return user_input if user_input else default
    return input(f"{prompt}: ").strip()

def list_csv_files(folders):
    files = []
    for folder in folders:
        folder_path = BASE_DIR / folder
        if folder_path.exists() and folder_path.is_dir():
            for file in folder_path.glob("*.csv"):
                files.append(file)
    return files

def run_rate_limit():
    print("\n--- Model Denial of Service (Rate Limiting) ---")
    print("Examples:")
    print("  - Test with 50 requests at 120 req/min")
    print("  - Test with 200 requests at 150 req/min")
    
    num_requests = get_input("Enter number of requests", "50")
    rate = get_input("Enter request rate (req/min)", "120")
    url = get_input("Enter target URL", DEFAULT_URL)
    
    cmd = [sys.executable, str(SCRIPTS_DIR / "Rate-limit.py"), num_requests, rate, "-u", url]
    print(f"\nRunning: {' '.join(cmd)}")
    subprocess.run(cmd)

def run_prompt_tester(control_config):
    print(f"\n--- {control_config['id']}: {control_config['name']} ---")
    
    csv_files = list_csv_files(control_config['folders'])
    if not csv_files:
        print(f"No CSV files found in folders: {', '.join(control_config['folders'])}")
        input("\nPress Enter to return to menu...")
        return

    print("\nAvailable test data:")
    for i, file in enumerate(csv_files, 1):
        print(f"{i}. {os.path.relpath(file, BASE_DIR)}")
    
    choice = get_input("\nSelect a file to run", "1")
    try:
        selected_file = csv_files[int(choice) - 1]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    rate = get_input("Enter request rate (req/min)", "30")
    url = get_input("Enter target URL", DEFAULT_URL)
    
    # New options
    repeat = get_input("Enter number of repeats per prompt", "1")
    
    cookie_str = None
    use_cookie = get_input("Do you want to test with authentication cookie? (y/n)", "n")
    if use_cookie.lower() == 'y':
        session_id = get_input("Enter session_id")
        auth_token = get_input("Enter auth_token")
        cookie_str = f"session_id={session_id}; auth_token={auth_token}"
    
    check_phrase = get_input("Use 'check for phrase' option? (y/n)", "n")
    
    config_file = None
    use_config = get_input("Use a custom request configuration JSON file? (y/n)", "n")
    if use_config.lower() == 'y':
        config_file = get_input("Enter path to config JSON (e.g., query_config.json)")
        if not os.path.exists(config_file):
            print(f"Warning: Config file {config_file} not found. Proceeding with default.")
            config_file = None
    
    response_path = get_input("Enter dot-notation path to extract response (optional, press enter to skip)")
    
    output_name = f"results_{control_config['id']}_{selected_file.stem}.csv"
    output_path = BASE_DIR / output_name
    
    cmd = [
        sys.executable, 
        str(SCRIPTS_DIR / "prompt_tester.py"), 
        rate, 
        str(selected_file), 
        "-u", url,
        "-o", str(output_path),
        "-r", repeat
    ]
    
    if cookie_str:
        cmd.extend(["-c", cookie_str])
    
    if check_phrase.lower() == 'y':
        cmd.append("--check-for-phrase")
    
    if config_file:
        cmd.extend(["-j", config_file])
    
    if response_path:
        cmd.extend(["-p", response_path])
    
    print(f"\nRunning: {' '.join(cmd)}")
    subprocess.run(cmd)
    
    if output_path.exists():
        print(f"\nResults saved to: {output_name}")
        judge = get_input("Would you like to run injection_judge on these results? (y/n)", "y")
        if judge.lower() == 'y':
            run_judge(output_path)

def run_judge(results_file):
    print("\n--- Injection Judge ---")
    ollama_url = get_input("Enter Ollama API URL", "http://localhost:11434/api/generate")
    model_name = get_input("Enter judge model name", "qwen3:8b")
    
    cmd = [
        sys.executable,
        str(SCRIPTS_DIR / "injection_judge.py"),
        str(results_file),
        "-u", ollama_url,
        "-m", model_name
    ]
    
    print(f"\nRunning: {' '.join(cmd)}")
    subprocess.run(cmd)

def main_menu():
    while True:
        clear_screen()
        print("====================================================")
        print("         LLM Safety Automation Toolkit              ")
        print("====================================================")
        print("Select the OWASP LLM Control to test:")
        for key, config in OWASP_MAPPING.items():
            print(f"{key}. {config['id']}: {config['name']}")
        print("Q. Quit")
        print("----------------------------------------------------")
        
        choice = get_input("Enter your choice").upper()
        
        if choice == 'Q':
            print("\nExiting toolkit. Stay safe!")
            break
        
        if choice in OWASP_MAPPING:
            config = OWASP_MAPPING[choice]
            if config['id'] == "LLM10":
                run_rate_limit()
            else:
                run_prompt_tester(config)
            input("\nPress Enter to return to menu...")
        else:
            print("Invalid choice. Please try again.")
            time.sleep(1)

if __name__ == "__main__":
    import time
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nToolkit interrupted. Exiting...")
