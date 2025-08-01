
"""
Google Threat Intelligence API Tool (Full Version)
=================================================

An interactive command-line tool for interacting with various endpoints of the
Google Threat Intelligence API. This version includes the full suite of
functions from the original script, rebuilt on a scalable and maintainable framework.

**Setup:**
1.  Install dependencies:
    pip install requests

2.  Set your API Key (Recommended):
    Export your key as an environment variable for security.
    -   For Linux/macOS:
        export GTI_API_KEY='your_api_key_here'
    -   For Windows (PowerShell):
        $env:GTI_API_KEY="your_api_key_here"

    If the environment variable is not set, the script will prompt you to
    enter the key securely.
"""

import datetime
import getpass
import json
import logging
import os
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# --- Configuration ---
BASE_URL = "https://www.virustotal.com/api/v3"
OUTPUT_DIR = Path("outputs")
API_KEY_ENV_VAR = "GTI_API_KEY"
DEFAULT_RETRY_COUNT = 3
DEFAULT_TIMEOUT = 30  # seconds

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# --- Custom Exceptions ---
class InvalidApiKeyError(Exception):
    """Custom exception for 401 Unauthorized errors."""
    pass


# ==============================================================================
# 1. API Client for Low-Level Communication
# ==============================================================================

class ApiClient:
    """Handles low-level communication with the Google Threat Intelligence API."""

    def __init__(self, api_key: str):
        if not api_key:
            raise ValueError("API key cannot be empty.")
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "GTI-Python-Tool/2.0",
        })

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        data: Optional[Any] = None,
        files: Optional[Dict] = None,
    ) -> Optional[Dict[str, Any]]:
        """Core request method with retry logic."""
        full_url = f"{BASE_URL}{endpoint}"
        for attempt in range(DEFAULT_RETRY_COUNT):
            try:
                response = self.session.request(
                    method=method,
                    url=full_url,
                    params=params,
                    json=data if not files else None,
                    files=files,
                    timeout=DEFAULT_TIMEOUT,
                )
                if response.status_code == 204:
                    return {"status": "Success", "code": 204, "message": "Request successful with no content."}
                
                response.raise_for_status()
                return response.json()

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    logging.error("HTTP Error: 401 - Invalid API key provided.")
                    raise InvalidApiKeyError("Invalid API key.")
                
                logging.error(f"HTTP Error: {e.response.status_code} - {e.response.text}")
                return None
            
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                logging.warning(f"{type(e).__name__} on attempt {attempt + 1}. Retrying...")
                time.sleep(2 ** attempt)
            except requests.exceptions.RequestException as e:
                logging.error(f"An unexpected request error occurred: {e}")
                return None
        logging.error("Max retries exceeded. Request failed.")
        return None

    def get(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        return self._request("GET", endpoint, params=params)

    def post(self, endpoint: str, data: Optional[Any] = None, files: Optional[Dict] = None) -> Optional[Dict]:
        return self._request("POST", endpoint, data=data, files=files)

    def patch(self, endpoint: str, data: Optional[Any] = None) -> Optional[Dict]:
        return self._request("PATCH", endpoint, data=data)

    def delete(self, endpoint: str) -> Optional[Dict]:
        return self._request("DELETE", endpoint)


# ==============================================================================
# 2. CLI Helper Functions
# ==============================================================================

def get_api_key() -> str:
    """Retrieves API key from environment or prompts user securely."""
    api_key = os.getenv(API_KEY_ENV_VAR)
    if api_key:
        logging.info(f"Using API key from environment variable '{API_KEY_ENV_VAR}'.")
        return api_key
    try:
        logging.warning(f"Environment variable '{API_KEY_ENV_VAR}' not set.")
        return getpass.getpass("Please enter your Google Threat Intelligence API Key: ")
    except (EOFError, KeyboardInterrupt):
        logging.critical("\nOperation cancelled by user.")
        return ""

def sanitize_filename(text: str) -> str:
    s = str(text)
    s = re.sub(r'[<>:"/\\|?*]', '_', s)
    s = s.strip().strip('.')
    return s[:100]

def handle_output(data: Any, operation: str, identifier: str = "") -> None:
    """Saves API response data to a file and waits for user."""
    if data is None:
        logging.warning("No data returned from API call.")
        input("\nPress Enter to return to the menu...")
        return
        
    output_str = json.dumps(data, indent=2)

    # Console output for JSON is suppressed as per user request.
    # print("\n--- API Response ---")
    # print(output_str)

    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_id = f"_{sanitize_filename(identifier)}" if identifier else ""
    filename = f"{operation}{sanitized_id}_{timestamp}.json"
    full_path = OUTPUT_DIR / filename
    
    try:
        full_path.write_text(output_str, encoding="utf-8")
        logging.info(f"Output successfully saved to {full_path}")
    except IOError as e:
        logging.error(f"Failed to save output file: {e}")
        
    input("\nPress Enter to return to the menu...")


# ==============================================================================
# 3. Handler Functions for Menu Actions
# ==============================================================================

# --- IoC Investigation ---
def get_ip_report(client: ApiClient, ip: str): return client.get(f"/ip_addresses/{ip}")
def add_ip_comment(client: ApiClient, ip: str, comment: str): return client.post(f"/ip_addresses/{ip}/comments", data={"data": {"type": "comment", "attributes": {"text": comment}}})
def get_domain_report(client: ApiClient, domain: str): return client.get(f"/domains/{domain}")
def add_domain_comment(client: ApiClient, domain: str, comment: str): return client.post(f"/domains/{domain}/comments", data={"data": {"type": "comment", "attributes": {"text": comment}}})
def get_url_report(client: ApiClient, url: str): url_id = urllib.parse.urlsafe_b64encode(url.encode()).decode().strip("="); return client.get(f"/urls/{url_id}")
def scan_url(client: ApiClient, url: str): return client.post("/urls", data={"url": url})
def get_dns_resolution(client: ApiClient, res_id: str): return client.get(f"/resolutions/{res_id}")

# --- File Operations ---
def get_file_report(client: ApiClient, file_hash: str): return client.get(f"/files/{file_hash}")
def upload_file(client: ApiClient, file_path_str: str):
    path = Path(file_path_str)
    if not path.is_file():
        logging.error(f"File not found: {file_path_str}"); return None
    if path.stat().st_size > 32 * 1024 * 1024:
        logging.error("File > 32MB. Use 'Get URL for uploading large files' option."); return None
    with open(path, "rb") as f:
        files = {"file": (path.name, f)}
        return client.post("/files", files=files)
def get_large_file_upload_url(client: ApiClient): return client.get("/files/upload_url")
def request_file_rescan(client: ApiClient, file_hash: str): return client.post(f"/files/{file_hash}/analyse")
def download_from_url_handler(client: ApiClient, url_endpoint: str, output_filename: str):
    url_response = client.get(url_endpoint)
    if not url_response or "data" not in url_response:
        logging.error("Could not get download URL."); return False
    download_url = url_response["data"]
    logging.info(f"Attempting to download from temporary URL...")
    try:
        with requests.get(download_url, stream=True, timeout=300) as r:
            r.raise_for_status()
            OUTPUT_DIR.mkdir(exist_ok=True)
            full_path = OUTPUT_DIR / sanitize_filename(output_filename)
            with open(full_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
            logging.info(f"File successfully downloaded to {full_path}"); return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during file download: {e}"); return False
def download_file_handler(client: ApiClient, file_hash: str, filename: str): return download_from_url_handler(client, f"/files/{file_hash}/download_url", filename)

# --- Threat Landscape & IoC Collections ---
def list_collections(client: ApiClient, filters: str): return client.get("/collections", params={"filter": filters} if filters else {})
def get_collection(client: ApiClient, threat_id: str): return client.get(f"/collections/{threat_id}")
def create_collection(client: ApiClient, name: str, description: str, is_private: str, raw_items: str):
    payload = {"data": {"type": "collection", "attributes": {"name": name, "description": description, "private": is_private.lower() == 'yes'}}}
    if raw_items: payload["data"]["raw_items"] = raw_items
    return client.post("/collections", data=payload)
def update_collection(client: ApiClient, collection_id: str, name: str, description: str, is_private_str: str, raw_items: str):
    attrs = {k: v for k, v in [("name", name), ("description", description)] if v}
    if is_private_str.lower() == 'yes': attrs["private"] = True
    elif is_private_str.lower() == 'no': attrs["private"] = False
    payload = {"data": {"type": "collection", "id": collection_id, "attributes": attrs}}
    if raw_items: payload["data"]["raw_items"] = raw_items
    return client.patch(f"/collections/{collection_id}", data=payload)
def delete_collection(client: ApiClient, collection_id: str): return client.delete(f"/collections/{collection_id}")

# --- Threat Profiles ---
def list_threat_profiles(client: ApiClient): return client.get("/threat_profiles")
def get_threat_profile(client: ApiClient, profile_id: str): return client.get(f"/threat_profiles/{profile_id}")
def create_threat_profile(client: ApiClient, name: str, targeted_industries: List[str], targeted_regions: List[str]):
    interests = {}
    if targeted_industries and targeted_industries[0]: interests["INTEREST_TYPE_TARGETED_INDUSTRY"] = targeted_industries
    if targeted_regions and targeted_regions[0]: interests["INTEREST_TYPE_TARGETED_REGION"] = targeted_regions
    payload = {"data": {"type": "threat_profile", "attributes": {"name": name, "interests": interests}}}
    return client.post("/threat_profiles", data=payload)
def delete_threat_profile(client: ApiClient, profile_id: str): return client.delete(f"/threat_profiles/{profile_id}")
def get_threat_profile_recs(client: ApiClient, profile_id: str, filter_str: str): return client.get(f"/threat_profiles/{profile_id}/recommendations", params={"filter": filter_str} if filter_str else {})

# --- Zipping Files ---
def create_zip_file(client: ApiClient, hashes: List[str], password: str):
    payload = {"data": {"type": "zip_file", "hashes": hashes}}
    if password: payload["data"]["password"] = password
    return client.post("/intelligence/zip_files", data=payload)
def get_zip_status(client: ApiClient, zip_id: str): return client.get(f"/intelligence/zip_files/{zip_id}")
def download_zip_handler(client: ApiClient, zip_id: str, filename: str): return download_from_url_handler(client, f"/intelligence/zip_files/{zip_id}/download_url", filename)

# --- Search & Metadata ---
def advanced_search(client: ApiClient, query: str): return client.get("/intelligence/search", params={"query": query})
def get_gti_metadata(client: ApiClient): return client.get("/intelligence/metadata")

# --- Categorised Threat Lists ---
def list_threat_lists(client: ApiClient): return client.get("/threat_lists")
def get_hourly_threat_list(client: ApiClient, list_id: str, time_str: str, ioc_type: str, query: str):
    params = {k: v for k, v in [("type", ioc_type), ("query", query)] if v}
    return client.get(f"/threat_lists/{list_id}/{time_str}", params=params)


# ==============================================================================
# 4. Menu Configuration
# ==============================================================================

MENU_CONFIG = {
    "IoC Investigation": [
        {"name": "Get IP Address Report", "handler": get_ip_report, "op_name": "ip_report", "prompts": [{"text": "Enter IP address"}]},
        {"name": "Add Comment to IP Address", "handler": add_ip_comment, "op_name": "ip_comment_add", "prompts": [{"text": "Enter IP address"}, {"text": "Enter your comment"}]},
        {"name": "Get Domain Report", "handler": get_domain_report, "op_name": "domain_report", "prompts": [{"text": "Enter domain name"}]},
        {"name": "Add Comment to Domain", "handler": add_domain_comment, "op_name": "domain_comment_add", "prompts": [{"text": "Enter domain name"}, {"text": "Enter your comment"}]},
        {"name": "Get URL Report", "handler": get_url_report, "op_name": "url_report", "prompts": [{"text": "Enter URL to get report for"}]},
        {"name": "Scan URL", "handler": scan_url, "op_name": "url_scan", "prompts": [{"text": "Enter URL to scan"}]},
        {"name": "Get DNS Resolution Object", "handler": get_dns_resolution, "op_name": "dns_resolution", "prompts": [{"text": "Enter resolution ID (e.g., 8.8.8.8-google.com)"}]},
    ],
    "File Operations": [
        {"name": "Get File Report", "handler": get_file_report, "op_name": "file_report", "prompts": [{"text": "Enter file hash (MD5, SHA1, or SHA256)"}]},
        {"name": "Upload Small File (<= 32MB)", "handler": upload_file, "op_name": "file_upload", "prompts": [{"text": "Enter path to the file to upload"}]},
        {"name": "Get URL for Uploading Large Files (> 32MB)", "handler": get_large_file_upload_url, "op_name": "large_file_upload_url"},
        {"name": "Request File Rescan", "handler": request_file_rescan, "op_name": "file_rescan", "prompts": [{"text": "Enter file hash to rescan"}]},
        {"name": "Download File", "handler": download_file_handler, "op_name": "file_download", "raw_handler": True, "prompts": [{"text": "Enter file hash (SHA256)"}, {"text": "Enter desired output filename"}]},
    ],
    "Threat Landscape & IoC Collections": [
        {"name": "List Threat Collections", "handler": list_collections, "op_name": "list_collections", "prompts": [{"text": "Enter filters (optional)"}]},
        {"name": "Get Specific Threat Collection", "handler": get_collection, "op_name": "get_collection", "prompts": [{"text": "Enter threat ID"}]},
        {"name": "Create IoC Collection", "handler": create_collection, "op_name": "create_collection", "prompts": [{"text": "Enter collection name"}, {"text": "Enter description"}, {"text": "Is this a private collection? (yes/no)"}, {"text": "Enter raw items (optional)"}]},
        {"name": "Update IoC Collection", "handler": update_collection, "op_name": "update_collection", "prompts": [{"text": "Enter collection ID"}, {"text": "Enter new name (blank to keep)"}, {"text": "Enter new description (blank to keep)"}, {"text": "Change privacy? (yes/no/blank)"}, {"text": "Add new raw items (optional)"}]},
        {"name": "Delete IoC Collection", "handler": delete_collection, "op_name": "delete_collection", "raw_handler": True, "prompts": [{"text": "Enter collection ID to delete"}]},
    ],
    "Threat Profiles": [
        {"name": "List Threat Profiles", "handler": list_threat_profiles, "op_name": "list_threat_profiles"},
        {"name": "Get Specific Threat Profile", "handler": get_threat_profile, "op_name": "get_threat_profile", "prompts": [{"text": "Enter Threat Profile ID"}]},
        {"name": "Create Threat Profile", "handler": create_threat_profile, "op_name": "create_threat_profile", "prompts": [{"text": "Enter Threat Profile name"}, {"text": "Enter targeted industries (comma-separated, optional)", "type": "list"}, {"text": "Enter targeted regions (comma-separated, optional)", "type": "list"}]},
        {"name": "Delete Threat Profile", "handler": delete_threat_profile, "op_name": "delete_threat_profile", "raw_handler": True, "prompts": [{"text": "Enter Threat Profile ID to delete"}]},
        {"name": "Get Threat Profile Recommendations", "handler": get_threat_profile_recs, "op_name": "threat_profile_recs", "prompts": [{"text": "Enter Threat Profile ID"}, {"text": "Enter filter (optional)"}]},
    ],
    "Zipping Files": [
        {"name": "Create ZIP File from Hashes", "handler": create_zip_file, "op_name": "create_zip_file", "prompts": [{"text": "Enter file SHA256 hashes (comma-separated)", "type": "list"}, {"text": "Enter optional password"}]},
        {"name": "Get ZIP File Status", "handler": get_zip_status, "op_name": "zip_file_status", "prompts": [{"text": "Enter ZIP file ID"}]},
        {"name": "Download ZIP File", "handler": download_zip_handler, "op_name": "zip_download", "raw_handler": True, "prompts": [{"text": "Enter ZIP file ID"}, {"text": "Enter desired output filename"}]},
    ],
    "Search & Metadata": [
        {"name": "Advanced Corpus Search", "handler": advanced_search, "op_name": "advanced_search", "prompts": [{"text": "Enter search query"}]},
        {"name": "Get Google Threat Intelligence Metadata", "handler": get_gti_metadata, "op_name": "gti_metadata"},
    ],
    "Categorised Threat Lists": [
        {"name": "List Categorised Threat Lists", "handler": list_threat_lists, "op_name": "list_threat_lists"},
        {"name": "Get Hourly Threat List", "handler": get_hourly_threat_list, "op_name": "hourly_threat_list", "prompts": [{"text": "Enter Threat List ID"}, {"text": "Enter time (YYYYMMDDhh)"}, {"text": "Enter IoC type (optional)"}, {"text": "Enter query filter (optional)"}]},
    ],
}


# ==============================================================================
# 5. Main Application Loop
# ==============================================================================

def run_menu_action(client: ApiClient, action: Dict[str, Any]):
    """Prompts for input, runs a function, and handles the output."""
    args = []
    for prompt in action.get("prompts", []):
        user_input = input(f"{prompt['text']}: ").strip()
        args.append([item.strip() for item in user_input.split(',')] if prompt.get("type") == "list" else user_input)
    logging.info(f"Executing: {action['name']}...")
    result = action["handler"](client, *args)
    if action.get("raw_handler"):
        input("\nPress Enter to return to the menu...")
        return
    identifier = str(args[0]) if args else ""
    handle_output(result, action["op_name"], identifier)

def main():
    """Main function to run the interactive tool."""
    print("\n--- Google Threat Intelligence API Tool ---")
    api_key = get_api_key()
    if not api_key: return

    client = ApiClient(api_key)
    choice_map = {}
    idx = 1
    for category, actions in MENU_CONFIG.items():
        for action in actions:
            choice_map[str(idx)] = action
            idx +=1

    while True:
        try:
            print("\n" + "="*15 + " Main Menu " + "="*15)
            current_idx = 1
            for category, actions in MENU_CONFIG.items():
                print(f"--- {category} ---")
                for action in actions:
                    print(f"  {current_idx}. {action['name']}")
                    current_idx += 1
            print("--- Other ---")
            print("  0. Exit")
            choice = input("Enter your choice: ").strip()
            if choice == '0':
                print("Exiting. Goodbye!"); break
            
            action_to_run = choice_map.get(choice)
            if action_to_run:
                run_menu_action(client, action_to_run)
            else:
                print("Invalid choice. Please try again.")

        except InvalidApiKeyError:
            logging.warning("Your API key appears to be invalid or has expired.")
            api_key = get_api_key()
            if not api_key:
                print("No API key provided. Exiting.")
                break
            client = ApiClient(api_key)
            logging.info("API client updated with new key. Please try your selection again.")
            continue

        except Exception as e:
            logging.error(f"An unexpected error occurred in the main loop: {e}", exc_info=True)
            input("\nPress Enter to return to the menu...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("\nOperation cancelled by user. Exiting.")