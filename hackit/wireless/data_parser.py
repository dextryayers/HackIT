import json

class DataParser:
    @staticmethod
    def parse_telemetry(raw_line: str):
        try:
            return json.loads(raw_line)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def extract_bssid(data: dict):
        if data and data.get("event") == "beacon":
            return data.get("bssid", "UNKNOWN")
        return None
