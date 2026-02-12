"""
Temperature Probe - Chat Endpoint Testing Tool
Tests for determinism and rate limiting by sending multiple identical requests
"""

import argparse
import csv
import json
import requests
import time
import re
import statistics
import threading
from datetime import datetime
from typing import List, Dict, Tuple

# ============================================================================
# Basic Statistics Functions
# ============================================================================

def _tokens(s: str) -> List[str]:
    """Tokenize string into words and punctuation"""
    return re.findall(r"\w+|[^\w\s]", s, flags=re.UNICODE)

def basic_stats(batch: List[str]) -> Dict[str, float]:
    """Calculate basic statistics about response lengths"""
    lens = [len(_tokens(s)) for s in batch]
    return {
        "n": len(batch),
        "avg_len_tokens": statistics.mean(lens) if lens else 0.0,
        "median_len_tokens": statistics.median(lens) if lens else 0.0,
        "min_len_tokens": min(lens) if lens else 0,
        "max_len_tokens": max(lens) if lens else 0,
    }

# ============================================================================
# Chat API Testing Functions
# ============================================================================

def send_chat_message(url: str, message: str, conversation_id: str = None) -> Tuple[bool, Dict, int]:
    """
    Send a message to the chat API endpoint
    
    Returns:
        (success, response_data, status_code)
    """
    try:
        payload = {
            "message": message,
            "conversation_id": conversation_id
        }
        
        response = requests.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=60
        )
        
        status_code = response.status_code
        
        # Try to parse JSON response
        try:
            data = response.json()
        except json.JSONDecodeError:
            data = {"error": "Invalid JSON response", "raw": response.text[:200]}
        
        return (response.ok, data, status_code)
    
    except requests.exceptions.Timeout:
        return (False, {"error": "Request timeout"}, 0)
    except requests.exceptions.ConnectionError:
        return (False, {"error": "Connection error"}, 0)
    except Exception as e:
        return (False, {"error": str(e)}, 0)

def calculate_delay(requests_per_minute: float) -> float:
    """Calculate delay in seconds between requests"""
    if requests_per_minute <= 0:
        raise ValueError("Requests per minute must be positive")
    return 60.0 / requests_per_minute

def run_probe(url: str, message: str, num_requests: int, requests_per_minute: float, output_file: str):
    """
    Run the temperature probe test
    
    Args:
        url: Chat API endpoint URL
        message: Message to send repeatedly
        num_requests: Number of times to send the message
        requests_per_minute: Rate at which to send requests
        output_file: CSV file to save results
    """
    delay = calculate_delay(requests_per_minute)
    
    print(f"Temperature Probe - Chat Endpoint Test")
    print(f"=" * 60)
    print(f"Endpoint:       {url}")
    print(f"Message:        {message}")
    print(f"Requests:       {num_requests}")
    print(f"Rate:           {requests_per_minute} req/min ({delay:.3f}s between requests)")
    print(f"Output:         {output_file}")
    print(f"=" * 60)
    print()
    
    results = []
    rate_limited = False
    rate_limit_threshold = None
    successful_requests = 0
    
    # Track timing
    start_time = time.time()
    
    for i in range(1, num_requests + 1):
        request_start = time.time()
        
        print(f"Request {i}/{num_requests}...", end=" ", flush=True)
        
        # Send request
        success, data, status_code = send_chat_message(url, message)
        
        request_end = time.time()
        response_time = (request_end - request_start) * 1000  # Convert to ms
        
        # Extract response text
        if success and data.get('success'):
            response_text = data.get('response', 'No response text')
            error_text = None
            successful_requests += 1
            print(f"OK ({response_time:.0f}ms)")
        else:
            response_text = None
            error_text = data.get('error', 'Unknown error')
            
            # Check if this is a rate limit error
            if status_code == 429 or 'rate limit' in error_text.lower() or 'too many requests' in error_text.lower():
                rate_limited = True
                # Calculate actual rate achieved before throttling
                elapsed_time = time.time() - start_time
                actual_rate = (i / elapsed_time) * 60 if elapsed_time > 0 else 0
                rate_limit_threshold = actual_rate
                print(f"RATE LIMITED (status: {status_code})")
            else:
                print(f"Error (status: {status_code})")
        
        # Store result
        result = {
            'request_number': i,
            'timestamp': datetime.now().isoformat(),
            'status_code': status_code,
            'success': success and data.get('success', False),
            'response_text': response_text,
            'error_text': error_text,
            'response_time_ms': response_time,
            'conversation_id': data.get('conversation_id') if success else None
        }
        results.append(result)
        
        # If rate limited, stop the test
        if rate_limited:
            print()
            print(f"*** RATE LIMITING DETECTED at request {i} ***")
            print(f"   Attempted rate: {requests_per_minute} req/min")
            print(f"   Actual rate achieved: {rate_limit_threshold:.2f} req/min")
            print(f"   Status code: {status_code}")
            print(f"   Error: {error_text}")
            break
        
        # Wait before next request (except for the last one)
        if i < num_requests:
            time.sleep(delay)
    
    # Calculate statistics
    total_time = time.time() - start_time
    actual_rate = (len(results) / total_time) * 60
    
    print()
    print(f"=" * 60)
    print(f"Test Results Summary")
    print(f"=" * 60)
    print(f"Total requests sent:     {len(results)}")
    print(f"Successful responses:    {successful_requests}")
    print(f"Failed requests:         {len(results) - successful_requests}")
    print(f"Total time:              {total_time:.2f}s")
    print(f"Actual rate achieved:    {actual_rate:.2f} req/min")
    
    if rate_limited:
        print(f"Rate limit threshold:  ~{rate_limit_threshold:.2f} req/min")
    
    # Analyze determinism
    if successful_requests > 1:
        unique_responses = len(set(r['response_text'] for r in results if r['response_text']))
        print(f"\nDeterminism Analysis:")
        print(f"   Unique responses:      {unique_responses}/{successful_requests}")
        if unique_responses == 1:
            print(f"Fully deterministic (all responses identical)")
        elif unique_responses == successful_requests:
            print(f"   Non-deterministic (all responses different)")
        else:
            print(f"   Partially deterministic ({unique_responses} variations)")
    
    # Show basic response statistics
    if successful_requests >= 1:
        response_texts = [r['response_text'] for r in results if r['response_text']]
        metrics = basic_stats(response_texts)
        
        print(f"\nResponse Statistics:")
        print(f"   Length (tokens): avg={metrics['avg_len_tokens']:.1f}, "
              f"median={metrics['median_len_tokens']:.1f}, "
              f"min={metrics['min_len_tokens']}, "
              f"max={metrics['max_len_tokens']}")
    
    # Save results to CSV
    print(f"\nSaving results to {output_file}...")
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['request_number', 'timestamp', 'status_code', 'success', 
                      'response_text', 'error_text', 'response_time_ms', 'conversation_id']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Results saved successfully!")
    print()

def run_probe_concurrent(url: str, message: str, num_requests: int, requests_per_minute: float, output_file: str):
    """
    Run the temperature probe test with concurrent requests
    
    Args:
        url: Chat API endpoint URL
        message: Message to send repeatedly
        num_requests: Number of times to send the message
        requests_per_minute: Rate at which to send requests
        output_file: CSV file to save results
    """
    delay = calculate_delay(requests_per_minute)
    
    print(f"Temperature Probe - Chat Endpoint Test (CONCURRENT MODE)")
    print(f"=" * 60)
    print(f"Endpoint:       {url}")
    print(f"Message:        {message}")
    print(f"Requests:       {num_requests}")
    print(f"Rate:           {requests_per_minute} req/min ({delay:.3f}s between requests)")
    print(f"Output:         {output_file}")
    print(f"=" * 60)
    print()
    
    results = []
    results_lock = threading.Lock()
    rate_limited = threading.Event()
    rate_limit_info = {}
    
    def send_request_thread(request_num: int, scheduled_time: float):
        """Thread function to send a single request"""
        nonlocal results, rate_limited, rate_limit_info
        
        # Wait until scheduled time
        wait_time = scheduled_time - time.time()
        if wait_time > 0:
            time.sleep(wait_time)
        
        request_start = time.time()
        actual_delay = request_start - start_time
        
        print(f"Request {request_num}/{num_requests}...", end=" ", flush=True)
        
        # Send request
        success, data, status_code = send_chat_message(url, message)
        
        # Calculate response time
        response_time = (time.time() - request_start) * 1000  # Convert to ms
        
        # Process response
        if success and data.get('success'):
            response_text = data.get('response', '')
            error_text = None
            print(f"OK ({response_time:.0f}ms, delay={actual_delay:.1f}s)")
        else:
            response_text = None
            error_text = data.get('error', 'Unknown error')
            
            # Check if this is a rate limit error
            if status_code == 429 or 'rate limit' in error_text.lower() or 'too many requests' in error_text.lower():
                if not rate_limited.is_set():
                    rate_limited.set()
                    # Calculate actual rate achieved before throttling
                    elapsed_time = time.time() - start_time
                    actual_rate = (request_num / elapsed_time) * 60 if elapsed_time > 0 else 0
                    with results_lock:
                        rate_limit_info.update({
                            'request_num': request_num,
                            'threshold': actual_rate,
                            'status_code': status_code,
                            'error': error_text,
                            'elapsed_time': elapsed_time
                        })
                print(f"RATE LIMITED (status: {status_code})")
            else:
                print(f"Error (status: {status_code})")
        
        # Store result
        result = {
            'request_number': request_num,
            'timestamp': datetime.now().isoformat(),
            'status_code': status_code,
            'success': success and data.get('success', False),
            'response_text': response_text,
            'error_text': error_text,
            'response_time_ms': response_time,
            'conversation_id': data.get('conversation_id') if success else None
        }
        
        with results_lock:
            results.append(result)
    
    # Schedule and launch all requests
    start_time = time.time()
    threads = []
    
    for i in range(1, num_requests + 1):
        # Stop launching new requests if rate limiting detected
        if rate_limited.is_set():
            print(f"\nStopping request launches at request {i} due to rate limiting")
            break
        
        # Calculate scheduled time for this request
        scheduled_time = start_time + (i - 1) * delay
        
        # Create and start thread
        thread = threading.Thread(target=send_request_thread, args=(i, scheduled_time))
        thread.start()
        threads.append(thread)
        
        # Small sleep to allow threads to detect rate limiting
        # This prevents launching too many threads before detection
        if i % 10 == 0:  # Check every 10 requests
            time.sleep(0.01)
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    # Calculate statistics
    total_time = time.time() - start_time
    results.sort(key=lambda x: x['request_number'])  # Sort by request number
    successful_requests = sum(1 for r in results if r['success'])
    
    print()
    print(f"=" * 60)
    print(f"Test Results Summary")
    print(f"=" * 60)
    print(f"Total requests sent:     {len(results)}")
    print(f"Successful responses:    {successful_requests}")
    print(f"Failed requests:         {len(results) - successful_requests}")
    print(f"Total time:              {total_time:.2f}s")
    print(f"Actual rate achieved:    {(len(results) / total_time) * 60:.2f} req/min")
    
    if rate_limited.is_set() and rate_limit_info:
        print(f"\nRATE LIMITING DETECTED:")
        print(f"   First rate limit at request: {rate_limit_info['request_num']}")
        print(f"   Time elapsed: {rate_limit_info['elapsed_time']:.2f}s")
        print(f"   Rate achieved: ~{rate_limit_info['threshold']:.2f} req/min")
        print(f"   Status code: {rate_limit_info['status_code']}")
        print(f"   Error: {rate_limit_info['error']}")
    
    # Analyze determinism
    if successful_requests > 1:
        unique_responses = len(set(r['response_text'] for r in results if r['response_text']))
        print(f"\nDeterminism Analysis:")
        print(f"   Unique responses:      {unique_responses}/{successful_requests}")
        if unique_responses == 1:
            print(f"   Fully deterministic (all responses identical)")
        elif unique_responses == successful_requests:
            print(f"   Non-deterministic (all responses different)")
        else:
            print(f"   Partially deterministic ({unique_responses} variations)")
    
    # Show basic response statistics
    if successful_requests >= 1:
        response_texts = [r['response_text'] for r in results if r['response_text']]
        metrics = basic_stats(response_texts)
        
        print(f"\nResponse Statistics:")
        print(f"   Length (tokens): avg={metrics['avg_len_tokens']:.1f}, "
              f"median={metrics['median_len_tokens']:.1f}, "
              f"min={metrics['min_len_tokens']}, "
              f"max={metrics['max_len_tokens']}")
    
    # Save results to CSV
    print(f"\nSaving results to {output_file}...")
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['request_number', 'timestamp', 'status_code', 'success', 
                      'response_text', 'error_text', 'response_time_ms', 'conversation_id']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Results saved successfully!")
    print()

def main():
    parser = argparse.ArgumentParser(
        description='Temperature Probe - Test chat endpoint for determinism and rate limiting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with 10 requests at 5 req/min
  %(prog)s "What is your return policy?" 10 5
  
  # Test rate limiting with concurrent requests at 120 req/min
  %(prog)s "Hello" 50 120 --concurrent -o rate_limit_test.csv
  
  # Test determinism with same message 20 times at 10 req/min
  %(prog)s "What are USB-C cable specs?" 20 10
        """
    )
    
    parser.add_argument('message', type=str, help='Message to send to the chat endpoint')
    parser.add_argument('num_requests', type=int, help='Number of times to send the message')
    parser.add_argument('rate', type=float, help='Request rate in requests per minute')
    parser.add_argument('-u', '--url', type=str, default='http://localhost:5000/api/chat',
                        help='Chat API endpoint URL (default: http://localhost:5000/api/chat)')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='Output CSV file (default: probe_results_<timestamp>.csv)')
    parser.add_argument('-c', '--concurrent', action='store_true',
                        help='Use concurrent mode (fire requests at specified rate regardless of response time)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.num_requests <= 0:
        parser.error("num_requests must be positive")
    if args.rate <= 0:
        parser.error("rate must be positive")
    
    # Generate default output filename if not provided
    if args.output is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        mode_suffix = '_concurrent' if args.concurrent else '_sequential'
        args.output = f'probe_results{mode_suffix}_{timestamp}.csv'
    
    try:
        if args.concurrent:
            run_probe_concurrent(args.url, args.message, args.num_requests, args.rate, args.output)
        else:
            run_probe(args.url, args.message, args.num_requests, args.rate, args.output)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()