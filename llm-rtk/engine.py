import os
import json
import requests

from llm_rtk.analyzer import analyze_response
from llm_rtk.reporter import generate_report

# Debug Burp Proxy Configuration
USE_BURP = False

def load_objective_payloads(objective):
    """
    Load objective-specific payload definitions.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, "objectives", f"{objective}.json")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Objective file '{objective}.json' not found.")

    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_template(template_name):
    """
    Load HTTP request template configuration.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(base_dir, "templates", f"{template_name}.json")

    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Template '{template_name}.json' not found.")

    with open(template_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_api_key():
    """
    Load optional API key from secrets directory.
    """
    secrets_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "secrets",
        "api_key.txt"
    )

    if not os.path.exists(secrets_path):
        return None

    with open(secrets_path, "r", encoding="utf-8") as f:
        return f.read().strip()


def inject_placeholders(obj, payload_text, api_key):
    """
    Recursively replace template placeholders:
    - {{payload}}
    - {{api_key}}
    """

    if isinstance(obj, dict):
        return {
            key: inject_placeholders(value, payload_text, api_key)
            for key, value in obj.items()
        }

    elif isinstance(obj, list):
        return [
            inject_placeholders(item, payload_text, api_key)
            for item in obj
        ]

    elif isinstance(obj, str):

        if "{{payload}}" in obj:
            return obj.replace("{{payload}}", payload_text)

        if api_key and "{{api_key}}" in obj:
            return obj.replace("{{api_key}}", api_key)

        if not api_key and "{{api_key}}" in obj:
            return None

        return obj

    else:
        return obj


def clean_headers(headers_dict):
    """
    Remove headers with None values.
    """
    return {
        k: v
        for k, v in headers_dict.items()
        if v is not None
    }


def build_request(template_data, payload_text, api_key):
    """
    Construct request body and headers from template.
    """

    body_template = template_data.get("body", {})
    headers_template = template_data.get("headers", {})

    body = inject_placeholders(body_template, payload_text, api_key)
    headers = inject_placeholders(headers_template, payload_text, api_key)

    headers = clean_headers(headers)

    return body, headers


def run_scan(url, objectives, template_name):
    """
    Execute objective-driven adversarial validation
    against the specified GenAI endpoint.
    """

    findings = []
    total_payloads = 0

    # Load request template and API credentials
    template_data = load_template(template_name)
    api_key = load_api_key()

    # Determine HTTP method and endpoint suffix
    method = template_data.get("method", "POST").upper()
    url_suffix_template = template_data.get("url_suffix", "")

    # Optional Burp proxy support for traffic inspection
    proxies = None
    if USE_BURP:
        proxies = {
                "http": "http://127.0.0.1:8080",
                "https": "http://127.0.0.1:8080",
            }
    
    final_url = url

    # Apply template URL suffix if defined
    if url_suffix_template:
        rl_suffix = url_suffix_template
    
    # Replace API key placeholders if required
    if api_key:
        url_suffix = url_suffix.replace("{{api_key}}", api_key)
        final_url = url + url_suffix

     # Iterate over selected adversarial objectives
    for objective in objectives:
        payloads = load_objective_payloads(objective)
        total_payloads = total_payloads + len(payloads)

        for payload in payloads:
            technique_id = payload["technique"].split(" - ")[0]
        
            body, headers = build_request(
                template_data,
                payload["payload"],
                api_key
            )

            # Send adversarial request to target AI endpoint
            try:
                response = requests.request(
                    method,
                    final_url,
                    json=body,
                    headers=headers,
                    proxies=proxies,
                    verify=False,
                    timeout=60
                )
            except Exception as e:
                print(f"[!] Request failed: {e}")
                continue

            result = analyze_response(
                response.text,
                objective,
                technique_id
            )

            if result.get("vulnerable"):

                findings.append({
                    "payload_id": payload.get("id"),
                    "technique": payload.get("technique"),
                    "objective": objective,
                    "request_body": body,
                    "response_body": response.text,
                    "analysis": result
                })

    generate_report(findings, total_payloads, final_url)