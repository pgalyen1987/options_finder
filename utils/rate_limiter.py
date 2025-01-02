import time
from functools import wraps
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, max_requests=5, time_window=1.0):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []

    def wait(self):
        now = time.time()
        self.requests = [req for req in self.requests if now - req < self.time_window]
        
        if len(self.requests) >= self.max_requests:
            sleep_time = self.requests[0] + self.time_window - now
            if sleep_time > 0:
                logger.debug(f"Rate limit reached, waiting {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
        
        self.requests.append(now)

def rate_limited(f):
    limiter = RateLimiter()
    @wraps(f)
    def wrapper(*args, **kwargs):
        limiter.wait()
        return f(*args, **kwargs)
    return wrapper 