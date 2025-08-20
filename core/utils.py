import json, os
from datetime import datetime

def ensure_dir(path: str):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

def save_json_report(target: str, module_name: str, data: dict):
    ensure_dir("reports")
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    fn = f"reports/{module_name}_{target.replace('://','_').replace('/','_')}_{ts}.json"
    with open(fn, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return fn
