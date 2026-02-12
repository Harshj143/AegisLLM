"""
Rate Limit Tester - Simple tool to find the rate limit threshold
Sends "Hello" messages at a specified rate to detect rate limiting
"""

import argparse
import requests
import time
import threading
from datetime import datetime


def send_chat_message(url: str, message: str) -> tuple[bool, int]:
    """
    Send a message to the chat API endpoint
    
    Returns:
        (is_rate_limited, status_code)
    """
    try:
        payload = {
            "message": message,
            "conversation_id": None
        }
        
        response = requests.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=60
        )
        
        status_code = response.status_code
        
        # Check if rate limited
        is_rate_limited = status_code == 429
        if not is_rate_limited and response.ok:
            try:
                data = response.json()
                error = data.get('error', '').lower()
                if 'rate limit' in error or 'too many requests' in error:
                    is_rate_limited = True
            except:
                pass
        
        return (is_rate_limited, status_code)
    
    except Exception as e:
        return (False, 0)


def test_rate_limit(url: str, num_requests: int, requests_per_minute: float):
    """
    Test rate limiting by sending requests concurrently
    
    Args:
        url: Chat API endpoint URL
        num_requests: Number of requests to send
        requests_per_minute: Rate at which to send requests
    """
    delay = 60.0 / requests_per_minute
    
    print(f"Rate Limit Tester")
    print(f"=" * 60)
    print(f"Endpoint:       {url}")
    print(f"Message:        Hello")
    print(f"Requests:       {num_requests}")
    print(f"Rate:           {requests_per_minute} req/min ({delay:.3f}s between requests)")
    print(f"=" * 60)
    print()
    
    results = []
    results_lock = threading.Lock()
    rate_limited = threading.Event()
    rate_limit_info = {}
    stop_launching = threading.Event()
    
    def send_request_thread(request_num: int, scheduled_time: float):
        """Thread function to send a single request"""
        # Wait until scheduled time
        wait_time = scheduled_time - time.time()
        if wait_time > 0:
            time.sleep(wait_time)
        
        request_start = time.time()
        
        # Send request (don't wait for full response processing)
        is_rate_limited, status_code = send_chat_message(url, "Hello")
        
        # Calculate response time
        response_time = (time.time() - request_start) * 1000  # Convert to ms
        
        # Store result
        with results_lock:
            results.append({
                'request_num': request_num,
                'is_rate_limited': is_rate_limited,
                'status_code': status_code,
                'response_time': response_time,
                'timestamp': time.time()
            })
        
        # Check if this is the first rate limit
        if is_rate_limited and not rate_limited.is_set():
            rate_limited.set()
            stop_launching.set()
            # Calculate actual rate achieved before throttling
            elapsed_time = time.time() - start_time
            actual_rate = (request_num / elapsed_time) * 60 if elapsed_time > 0 else 0
            with results_lock:
                rate_limit_info.update({
                    'request_num': request_num,
                    'threshold': actual_rate,
                    'status_code': status_code,
                    'elapsed_time': elapsed_time
                })
            print(f"\nRATE LIMIT DETECTED at request {request_num} (after {elapsed_time:.2f}s)")
    
    # Schedule and launch all requests
    start_time = time.time()
    threads = []
    
    for i in range(1, num_requests + 1):
        # Stop launching new requests if rate limiting detected
        if stop_launching.is_set():
            break
        
        # Calculate scheduled time for this request
        scheduled_time = start_time + (i - 1) * delay
        
        # Create and start thread
        thread = threading.Thread(target=send_request_thread, args=(i, scheduled_time), daemon=True)
        thread.start()
        threads.append(thread)
        
        # Small sleep to allow threads to detect rate limiting
        if i % 10 == 0:
            time.sleep(0.01)
    
    print(f"Launched {len(threads)} request threads...")
    
    # Wait for all threads to complete (with timeout)
    for thread in threads:
        thread.join(timeout=30)
    
    # Calculate statistics
    total_time = time.time() - start_time
    
    with results_lock:
        total_sent = len(results)
        rate_limited_count = sum(1 for r in results if r['is_rate_limited'])
        successful_count = sum(1 for r in results if not r['is_rate_limited'] and r['status_code'] == 200)
    
    print()
    print(f"=" * 60)
    print(f"Test Results")
    print(f"=" * 60)
    print(f"Total requests sent:     {total_sent}")
    print(f"Successful responses:    {successful_count}")
    print(f"Rate limited responses:  {rate_limited_count}")
    print(f"Total time:              {total_time:.2f}s")
    print(f"Average rate achieved:   {(total_sent / total_time) * 60:.2f} req/min")
    
    if rate_limited.is_set() and rate_limit_info:
        print()
        print(f"RATE LIMIT THRESHOLD DETECTED:")
        print(f"   First rate limit at:  Request #{rate_limit_info['request_num']}")
        print(f"   Time to rate limit:   {rate_limit_info['elapsed_time']:.2f}s")
        print(f"   Calculated threshold: ~{rate_limit_info['threshold']:.2f} req/min")
        print(f"   Status code:          {rate_limit_info['status_code']}")
    else:
        print()
        print(f"NO RATE LIMITING DETECTED")
        print(f"   All {total_sent} requests completed successfully")
        print(f"   Rate limit is above {requests_per_minute} req/min")
    
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Rate Limit Tester - Find the rate limit threshold',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with 50 requests at 120 req/min
  %(prog)s 50 120
  
  # Test with 200 requests at 150 req/min
  %(prog)s 200 150
  
  # Test against custom endpoint
  %(prog)s 100 100 -u http://example.com/api/chat
        """
    )
    
    parser.add_argument('num_requests', type=int, help='Number of requests to send')
    parser.add_argument('rate', type=float, help='Request rate in requests per minute')
    parser.add_argument('-u', '--url', type=str, default='http://localhost:5000/api/chat',
                        help='Chat API endpoint URL (default: http://localhost:5000/api/chat)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.num_requests <= 0:
        parser.error("num_requests must be positive")
    if args.rate <= 0:
        parser.error("rate must be positive")
    
    try:
        test_rate_limit(args.url, args.num_requests, args.rate)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()