#!/usr/bin/env python3
"""
Prompt Tester - Test multiple prompts and capture their responses
Reads prompts from a file and sends them to the chat endpoint
"""

import argparse
import csv
import json
import requests
import time
import threading
import copy
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union


def get_value_at_path(data: Any, path: str) -> Any:
    """
    Extract value from a nested dictionary/list using a dot-notation path.
    Example: choices.0.message.content
    """
    if not path:
        return data
    
    parts = path.split('.')
    current = data
    
    for part in parts:
        if isinstance(current, dict):
            if part in current:
                current = current[part]
            else:
                return None
        elif isinstance(current, list):
            try:
                index = int(part)
                if 0 <= index < len(current):
                    current = current[index]
                else:
                    return None
            except ValueError:
                return None
        else:
            return None
    return current


def send_chat_message(
    url: str, 
    prompt: str, 
    technique: str = "", 
    prompt_id: str = "",
    config: Optional[dict] = None
) -> tuple[bool, dict, int]:
    """
    Send a message to the chat API endpoint with flexible configuration
    
    Args:
        url: API endpoint URL
        prompt: The prompt to send
        technique: Technique name (for template substitution)
        prompt_id: Prompt ID (for template substitution)
        config: Optional dictionary containing request configuration:
            - method: HTTP method (default: POST)
            - headers: Header dictionary
            - body: JSON body template string or dict
            - response_path: Dot-notation path to extract response
    
    Returns:
        (success, response_data, status_code)
    """
    try:
        # Default configuration
        method = "POST"
        headers = {"Content-Type": "application/json"}
        body_template = {"message": "{{PROMPT}}", "conversation_id": None}
        response_path = "response"
        
        if config:
            method = config.get("method", method).upper()
            if config.get("headers"):
                headers.update(config["headers"])
            if config.get("body"):
                body_template = config["body"]
            if config.get("response_path"):
                response_path = config["response_path"]
        
        # Template substitution helper
        def substitute(item):
            if isinstance(item, str):
                return item.replace("{{PROMPT}}", prompt).replace("{{TECHNIQUE}}", technique).replace("{{ID}}", str(prompt_id))
            elif isinstance(item, dict):
                return {k: substitute(v) for k, v in item.items()}
            elif isinstance(item, list):
                return [substitute(i) for i in item]
            return item

        # Prepare headers and body
        final_headers = substitute(headers)
        
        # If body_template is a string, we might need to parse it as JSON if it's meant to be JSON
        if isinstance(body_template, str):
            final_body_str = substitute(body_template)
            try:
                final_body = json.loads(final_body_str)
            except json.JSONDecodeError:
                final_body = final_body_str  # Use as-is if not JSON
        else:
            final_body = substitute(body_template)

        # Send request
        if method == "GET":
            response = requests.get(url, headers=final_headers, params=final_body if isinstance(final_body, dict) else None, timeout=120)
        elif method == "POST":
            if isinstance(final_body, (dict, list)):
                response = requests.post(url, json=final_body, headers=final_headers, timeout=120)
            else:
                response = requests.post(url, data=final_body, headers=final_headers, timeout=120)
        else:
            # Generic fallback for other methods
            response = requests.request(method, url, json=final_body if isinstance(final_body, (dict, list)) else None, 
                                       data=final_body if not isinstance(final_body, (dict, list)) else None,
                                       headers=final_headers, timeout=120)

        status_code = response.status_code
        
        # Try to parse JSON response
        try:
            data = response.json()
            extracted_response = get_value_at_path(data, response_path)
            if extracted_response is not None:
                # Store the extracted response in a standard field for the rest of the script
                data['extracted_response'] = str(extracted_response)
            else:
                # If path failed, but it's valid JSON, store the whole thing as a fallback or a specific message
                data['extracted_response'] = None
                # Add raw data to help debugging
                data['raw_json'] = json.dumps(data)
        except json.JSONDecodeError:
            data = {"error": "Invalid JSON response", "raw": response.text[:200], "extracted_response": response.text}
        
        return (response.ok, data, status_code)
    
    except requests.exceptions.Timeout:
        return (False, {"error": "Request timeout"}, 0)
    except requests.exceptions.ConnectionError:
        return (False, {"error": "Connection error"}, 0)
    except Exception as e:
        return (False, {"error": str(e)}, 0)


def read_prompts(input_file: str) -> list[dict]:
    """
    Read prompts from CSV file with id, technique, and prompt columns
    
    Args:
        input_file: Path to CSV file containing prompts
        
    Returns:
        List of dictionaries with 'id', 'technique', and 'prompt' keys
    """
    prompts = []
    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('prompt', '').strip():  # Skip rows with empty prompts
                prompts.append({
                    'id': row.get('id', ''),
                    'technique': row.get('technique', ''),
                    'prompt': row['prompt'].strip()
                })
    return prompts


def test_prompts(url: str, prompts: list[dict], requests_per_minute: float, output_file: str, repeat: int = 1, check_for_phrase: bool = False, config: Optional[dict] = None):
    """
    Test multiple prompts and capture responses
    
    Args:
        url: Chat API endpoint URL
        prompts: List of prompt dictionaries with 'id', 'technique', and 'prompt' keys
        requests_per_minute: Maximum rate at which to send requests
        output_file: CSV file to save results
        repeat: Number of times to repeat each prompt
        check_for_phrase: If True, check if the technique phrase appears in the response
        config: Optional request configuration dictionary
    """
    delay = 60.0 / requests_per_minute
    
    total_requests = len(prompts) * repeat
    
    print(f"Prompt Tester - Multiple Prompts Test")
    print(f"=" * 60)
    print(f"Endpoint:       {url}")
    if config and config.get('method'):
        print(f"Method:         {config['method']}")
    print(f"Prompts:        {len(prompts)}")
    print(f"Repeat:         {repeat}x")
    print(f"Total Requests: {total_requests}")
    print(f"Max Rate:       {requests_per_minute} req/min ({delay:.3f}s between requests)")
    print(f"Output:         {output_file}")
    print(f"=" * 60)
    print()
    
    results = []
    results_lock = threading.Lock()
    successful_requests = 0
    
    def send_request_thread(request_num: int, prompt_data: dict, repeat_num: int, scheduled_time: float):
        """Thread function to send a single request"""
        nonlocal successful_requests
        
        # Wait until scheduled time
        wait_time = scheduled_time - time.time()
        if wait_time > 0:
            time.sleep(wait_time)
        
        request_start = time.time()
        actual_delay = request_start - start_time
        
        # Extract prompt information
        prompt_id = prompt_data['id']
        technique = prompt_data['technique']
        prompt = prompt_data['prompt']
        
        # Truncate technique for display
        display_text = f"#{prompt_id} {technique}"
        if repeat > 1:
            display_text += f" (repeat {repeat_num}/{repeat})"
        if len(display_text) > 70:
            display_text = display_text[:67] + "..."
        print(f"Request {request_num}/{total_requests}: {display_text}", flush=True)
        
        # Send request
        success, data, status_code = send_chat_message(url, prompt, technique, prompt_id, config)
        
        # Calculate response time
        response_time = (time.time() - request_start) * 1000  # Convert to ms
        
        # Process response
        phrase_check_result = None
        if success:
            response_text = data.get('extracted_response')
            if response_text is None:
                # Fallback to older response format if extracting fails but request succeeded
                response_text = data.get('response', '')
            
            error_text = None
            print(f"  └─ Request {request_num}: ✅ OK ({response_time:.0f}ms)")
            
            # Check for phrase if requested
            if check_for_phrase and response_text and technique:
                if technique.lower() in response_text.lower():
                    phrase_check_result = "SUCCESS"
                    print(f"     ✅ Phrase check: Found '{technique}' in response")
                else:
                    phrase_check_result = "NO_SUCCESS"
                    print(f"     ❌ Phrase check: '{technique}' not found in response")
            
            with results_lock:
                successful_requests += 1
        else:
            response_text = None
            error_text = data.get('error', 'Unknown error')
            
            # Check if this is a rate limit error
            if status_code == 429 or (error_text and ('rate limit' in error_text.lower() or 'too many requests' in error_text.lower())):
                print(f"  └─ 🚫 RATE LIMITED (status: {status_code})")
            else:
                print(f"  └─ ❌ Error (status: {status_code})")
        
        # Store result
        result = {
            'id': prompt_id,
            'technique': technique,
            'repeat_number': repeat_num,
            'request_number': request_num,
            'response_time_ms': response_time,
            'prompt': prompt,
            'response': response_text if success else f"ERROR: {error_text}",
            'status_code': status_code,
            'timestamp': datetime.now().isoformat()
        }
        
        # Add phrase check result if enabled
        if check_for_phrase:
            result['phrase_check'] = phrase_check_result if phrase_check_result else "N/A"
        
        with results_lock:
            results.append(result)
    
    # Schedule and launch all requests
    start_time = time.time()
    threads = []
    
    request_num = 0
    for prompt_data in prompts:
        for repeat_num in range(1, repeat + 1):
            request_num += 1
            # Calculate scheduled time for this request
            scheduled_time = start_time + (request_num - 1) * delay
            
            # Create and start thread
            thread = threading.Thread(target=send_request_thread, args=(request_num, prompt_data, repeat_num, scheduled_time))
            thread.start()
            threads.append(thread)
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    # Calculate statistics
    total_time = time.time() - start_time
    results.sort(key=lambda x: x['request_number'])  # Sort by request number
    
    print()
    print(f"=" * 60)
    print(f"Test Results Summary")
    print(f"=" * 60)
    print(f"Total requests sent:     {len(results)}")
    print(f"Successful responses:    {successful_requests}")
    print(f"Failed requests:         {len(results) - successful_requests}")
    print(f"Total time:              {total_time:.2f}s")
    print(f"Actual rate achieved:    {(len(results) / total_time) * 60:.2f} req/min")
    
    if successful_requests > 0:
        successful_times = [r['response_time_ms'] for r in results if not r['response'].startswith('ERROR:')]
        if successful_times:
            avg_time = sum(successful_times) / len(successful_times)
            min_time = min(successful_times)
            max_time = max(successful_times)
            print(f"\nResponse Time Statistics:")
            print(f"   Average: {avg_time:.0f}ms")
            print(f"   Min:     {min_time:.0f}ms")
            print(f"   Max:     {max_time:.0f}ms")
    
    # Show phrase check statistics if enabled
    if check_for_phrase:
        phrase_results = [r for r in results if r.get('phrase_check') and r['phrase_check'] != 'N/A']
        if phrase_results:
            success_count = len([r for r in phrase_results if r['phrase_check'] == 'SUCCESS'])
            total_checked = len(phrase_results)
            print(f"\nPhrase Check Statistics:")
            print(f"   Successful matches: {success_count}/{total_checked} ({success_count/total_checked*100:.1f}%)")
            print(f"   Failed matches:     {total_checked - success_count}/{total_checked} ({(total_checked - success_count)/total_checked*100:.1f}%)")
    
    # Save results to CSV
    print(f"\nSaving results to {output_file}...")
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['id', 'technique', 'repeat_number', 'request_number', 'response_time_ms', 'prompt', 'response', 'status_code', 'timestamp']
        if check_for_phrase:
            fieldnames.append('phrase_check')
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Results saved successfully!")
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Prompt Tester - Test multiple prompts and capture responses',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test prompts from CSV file at 10 req/min
  %(prog)s 10 prompts.csv
  
  # Test prompts at 30 req/min with custom output
  %(prog)s 30 test_prompts.csv -o results.csv
  
  # Test each prompt 3 times to check for non-determinism
  %(prog)s 20 prompts.csv --repeat 3
  
  # Test against custom endpoint
  %(prog)s 20 prompts.csv -u http://example.com/api/chat
  
  # Check if technique phrase appears in responses
  %(prog)s 15 prompts.csv --check-for-phrase
  
  # Test with authentication cookie
  %(prog)s 15 prompts.csv -c "session_id=abc123; auth_token=xyz"

Input file format:
  - CSV file with columns: id, technique, prompt
  - Header row required
  - Example: direct_injection.csv
        """
    )
    
    parser.add_argument('rate', type=float, help='Maximum request rate in requests per minute')
    parser.add_argument('input_file', type=str, help='Input CSV file with columns: id, technique, prompt')
    parser.add_argument('-u', '--url', type=str, default='http://localhost:5000/api/chat',
                        help='Chat API endpoint URL (default: http://localhost:5000/api/chat)')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='Output CSV file (default: prompt_results_<timestamp>.csv)')
    parser.add_argument('-r', '--repeat', type=int, default=1,
                        help='Number of times to repeat each prompt (default: 1)')
    parser.add_argument('--check-for-phrase', action='store_true',
                        help='Check if the technique phrase appears in the response and add phrase_check column')
    parser.add_argument('-c', '--cookie', type=str, default=None,
                        help='Cookie string for authentication (shorthand for adding Cookie header)')
    parser.add_argument('-j', '--config', type=str, default=None,
                        help='Path to JSON configuration file for the request')
    parser.add_argument('-X', '--method', type=str, default=None,
                        help='HTTP method (overrides config file)')
    parser.add_argument('-H', '--header', action='append',
                        help='Custom header in "Key: Value" format (can be used multiple times)')
    parser.add_argument('-b', '--body', type=str, default=None,
                        help='JSON body template (overrides config file)')
    parser.add_argument('-p', '--response-path', type=str, default=None,
                        help='Dot-notation path to extract response (e.g., choices.0.message.content)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.rate <= 0:
        parser.error("rate must be positive")
    if args.repeat <= 0:
        parser.error("repeat must be positive")
    
    # Check if input file exists
    if not Path(args.input_file).exists():
        parser.error(f"Input file not found: {args.input_file}")
    
    # Generate default output filename if not provided
    if args.output is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output = f'prompt_results_{timestamp}.csv'
    
    # Load request configuration
    request_config = {
        "method": "POST",
        "headers": {},
        "body": None,
        "response_path": "response"
    }

    if args.config:
        with open(args.config, 'r') as f:
            file_config = json.load(f)
            request_config.update(file_config)
    
    # Overrides from CLI
    if args.method:
        request_config["method"] = args.method
    if args.body:
        request_config["body"] = args.body
    if args.response_path:
        request_config["response_path"] = args.response_path
    if args.cookie:
        request_config["headers"]["Cookie"] = args.cookie
    if args.header:
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                request_config["headers"][k.strip()] = v.strip()

    try:
        # Read prompts from file
        prompts = read_prompts(args.input_file)
        if not prompts:
            print("Error: No prompts found in input file")
            return
        
        print(f"Loaded {len(prompts)} prompts from {args.input_file}\n")
        
        # Run the test
        test_prompts(args.url, prompts, args.rate, args.output, args.repeat, args.check_for_phrase, request_config)
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()