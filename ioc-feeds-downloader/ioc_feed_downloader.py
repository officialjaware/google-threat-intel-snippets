# -*- coding: utf-8 -*-
"""
GTI Feed Downloader
===================

A command-line tool to download and process minutely threat intelligence feeds
from the Google Threat Intelligence (GTI) API.

This script allows users to:
  - Fetch compressed feed batches for various intelligence types (files, domains, etc.).
  - Parse feeds to download associated artifacts like malware samples, PCAPs, and memory dumps.

**Setup:**
1. Install dependencies:
   pip install requests

2. Set your API Key (recommended):
   Export your key as an environment variable.
   - For Linux/macOS:
     export GTI_API_KEY='your_api_key_here'
   - For Windows (Command Prompt):
     set GTI_API_KEY="your_api_key_here"
   - For Windows (PowerShell):
     $env:GTI_API_KEY="your_api_key_here"

   If the environment variable is not set, the script will prompt you to enter the key.
"""

import bz2
import datetime
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

import requests

# --- Constants ---
API_BASE_URL = "https://www.virustotal.com/api/v3"
API_KEY_ENV_VAR = "GTI_API_KEY"
DEFAULT_OUTPUT_DIR = Path("feeds_output")
# GTI feeds have a ~60 minute lag time from the present.
FEED_LAG_MINUTES = 60
DOWNLOAD_SAMPLE_SIZE = 2
CHUNK_SIZE = 8192

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class ApiClient:
    """A client to interact with the Google Threat Intelligence API."""

    def __init__(self, api_key: str):
        """
        Initializes the API client.

        Args:
            api_key: The Google Threat Intelligence API key.
        """
        if not api_key:
            raise ValueError("API key cannot be empty.")
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "GTI Feed Downloader Script",
        })

    def get_feed_batch(self, feed_endpoint: str) -> Optional[Path]:
        """
        Fetches and decompresses a single minute's feed batch.

        Args:
            feed_endpoint: The API endpoint for the feed (e.g., 'files').

        Returns:
            The path to the saved file if successful, otherwise None.
        """
        target_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=FEED_LAG_MINUTES)
        time_str = target_time.strftime("%Y%m%d%H%M")
        url = f"{API_BASE_URL}/feeds/{feed_endpoint}/{time_str}"
        output_path = DEFAULT_OUTPUT_DIR / f"{feed_endpoint}_{time_str}.jsonl"

        logging.info(f"Requesting {feed_endpoint} feed for {time_str} UTC...")

        try:
            with self.session.get(url, allow_redirects=True, stream=True) as response:
                if response.status_code == 404:
                    logging.warning(f"No batch found for {feed_endpoint} at {time_str}. This is expected for missing batches.")
                    return None
                response.raise_for_status()

                DEFAULT_OUTPUT_DIR.mkdir(exist_ok=True)
                decompressor = bz2.BZ2Decompressor()
                logging.info(f"Decompressing feed to {output_path}...")
                with open(output_path, "wb") as f_out:
                    for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                        f_out.write(decompressor.decompress(chunk))
                logging.info(f"Successfully saved feed to {output_path}")
                return output_path

        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP Error fetching {feed_endpoint}: {e.response.status_code} - {e.response.text}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error fetching {feed_endpoint}: {e}")
        except bz2.BZ2Error as e:
            logging.error(f"Decompression error for {feed_endpoint}: {e}")
            output_path.unlink(missing_ok=True) # Clean up partial file
        return None

    def download_artifact(self, download_url: str, file_type: str, file_id: str) -> bool:
        """
        Downloads a specific file artifact (e.g., sample, PCAP, memdump).

        Args:
            download_url: The pre-signed URL for the download.
            file_type: The type of file ('sample', 'pcap', 'memdump', etc.).
            file_id: The SHA256 or identifier for the artifact.

        Returns:
            True if download was successful, otherwise False.
        """
        filename = f"{file_id}.download" if file_type == "sample" else f"{file_id}_{file_type}.bin"
        output_path = DEFAULT_OUTPUT_DIR / filename
        logging.info(f"Downloading {file_type} for ID {file_id}...")

        try:
            # Note: GTI artifact download URLs are pre-signed and don't need the API key header.
            with requests.get(download_url, stream=True) as response:
                response.raise_for_status()
                DEFAULT_OUTPUT_DIR.mkdir(exist_ok=True)
                with open(output_path, "wb") as f_out:
                    for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                        f_out.write(chunk)
                logging.info(f"Successfully saved {file_type} to {output_path}")
                return True

        except requests.exceptions.RequestException as e:
            logging.error(f"Error downloading {file_type} for {file_id}: {e}")
            return False


def get_api_key() -> str:
    """
    Retrieves the API key from an environment variable or prompts the user.
    """
    api_key = os.getenv(API_KEY_ENV_VAR)
    if api_key:
        logging.info(f"Using API key from environment variable '{API_KEY_ENV_VAR}'.")
        return api_key
    
    try:
        api_key = input("\nPlease enter your Google Threat Intelligence API Key: ").strip()
        if not api_key:
            logging.critical("API Key cannot be empty. Exiting.")
            sys.exit(1)
        return api_key
    except EOFError: # Handles non-interactive script execution
        logging.critical(f"API key not found in environment variable '{API_KEY_ENV_VAR}' and no user input available. Exiting.")
        sys.exit(1)


def get_download_limit() -> Optional[int]:
    """
    Asks the user if they want to download all items or just a sample.

    Returns:
        The number of items to download, or None for no limit.
    """
    while True:
        mode = input(f"Download a (s)ample of {DOWNLOAD_SAMPLE_SIZE} files or (a)ll? [s/a]: ").strip().lower()
        if mode == 's':
            return DOWNLOAD_SAMPLE_SIZE
        if mode == 'a':
            return None
        print("Invalid choice. Please enter 's' or 'a'.")


def process_feed_for_downloads(
    client: ApiClient,
    feed_endpoint: str,
    artifact_type: str,
    extractor: Callable[[Dict], Optional[Tuple[str, str]]],
):
    """
    Generic function to process a feed file and download its artifacts.

    Args:
        client: The configured ApiClient.
        feed_endpoint: The feed to fetch (e.g., 'files').
        artifact_type: A descriptive name of the artifact (e.g., 'sample', 'pcap').
        extractor: A function that takes a JSON feed line and returns a
                   tuple of (download_url, file_id) or None.
    """
    feed_path = client.get_feed_batch(feed_endpoint)
    if not feed_path:
        logging.warning("Cannot proceed with downloads as feed was not retrieved.")
        return

    limit = get_download_limit()
    download_count = 0

    logging.info(f"Processing '{feed_path}' for {artifact_type} downloads...")
    try:
        with open(feed_path, "r", encoding="utf-8") as f_in:
            for line in f_in:
                if limit is not None and download_count >= limit:
                    logging.info(f"Sample size of {limit} reached. Halting download.")
                    break
                try:
                    data = json.loads(line)
                    extracted = extractor(data)
                    if extracted:
                        url, file_id = extracted
                        if client.download_artifact(url, artifact_type, file_id):
                            download_count += 1
                except json.JSONDecodeError:
                    logging.warning(f"Skipping malformed JSON line in {feed_path}")
                    continue
    except FileNotFoundError:
        logging.error(f"Feed file not found at {feed_path}.")
    except Exception as e:
        logging.error(f"An unexpected error occurred while processing the feed: {e}", exc_info=True)

    logging.info(f"\nFinished processing. Downloaded {download_count} {artifact_type} artifacts.")


def main():
    """Main function to run the interactive script."""
    print("\n--- Google Threat Intelligence Feed Downloader ---")
    print("Note: Access to feeds and files requires a specific GTI license.")
    print("Verify your license if you encounter '403 Forbidden' errors.")

    try:
        api_key = get_api_key()
        client = ApiClient(api_key)
    except (ValueError, SystemExit) as e:
        # Error already logged by the function, so just exit.
        return

    # --- Artifact Extractor Functions ---
    def file_extractor(item: Dict) -> Optional[Tuple[str, str]]:
        url = item.get("download_url")
        sha256 = item.get("sha256")
        if url and sha256:
            return url, sha256
        return None

    def behaviour_extractor(item: Dict, artifact_key: str) -> Optional[Tuple[str, str]]:
        url = item.get("context_attributes", {}).get(artifact_key)
        # ID is usually in the format 'sha256_sandboxid'
        sha256 = item.get("id", "").split("_")[0]
        if url and sha256:
            return url, sha256
        return None

    # --- Menu Definition ---
    menu_actions = {
        "1": {"text": "File Intelligence", "func": client.get_feed_batch, "args": ["files"]},
        "2": {"text": "Sandbox Analyses", "func": client.get_feed_batch, "args": ["file_behaviours"]},
        "3": {"text": "Domain Intelligence", "func": client.get_feed_batch, "args": ["domains"]},
        "4": {"text": "IP Intelligence", "func": client.get_feed_batch, "args": ["ip_addresses"]},
        "5": {"text": "URL Intelligence", "func": client.get_feed_batch, "args": ["urls"]},
        "6": {"text": "ALL intelligence feeds", "func": None},  # Special case
        "7": {"text": "Download files from File feed", "func": process_feed_for_downloads, "args": [client, "files", "sample", file_extractor]},
        "8": {"text": "Download PCAPs from Sandbox feed", "func": process_feed_for_downloads, "args": [client, "file_behaviours", "pcap", lambda item: behaviour_extractor(item, "pcap")]},
        "9": {"text": "Download MemDumps from Sandbox feed", "func": process_feed_for_downloads, "args": [client, "file_behaviours", "memdump", lambda item: behaviour_extractor(item, "memdump")]},
        "10": {"text": "Download EVTX from Sandbox feed", "func": process_feed_for_downloads, "args": [client, "file_behaviours", "evtx", lambda item: behaviour_extractor(item, "evtx")]},
        "11": {"text": "Exit", "func": sys.exit},
    }

    # --- Main Loop ---
    while True:
        print("\n" + "="*15 + " Main Menu " + "="*15)
        print("--- Get Minutely Feed Batch ---")
        for i in range(1, 7):
            print(f"{i}. Get a batch for {menu_actions[str(i)]['text']}")
        print("\n--- Download Artifacts from Latest Feeds ---")
        for i in range(7, 11):
            print(f"{i}. {menu_actions[str(i)]['text']}")
        print("\n11. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "11":
            break

        if choice == "6":
            logging.info("--- Retrieving all minutely feed batches ---")
            success_count = 0
            for i in range(1, 6): # Feeds 1 through 5
                if client.get_feed_batch(menu_actions[str(i)]["args"][0]):
                    success_count += 1
                time.sleep(1) # Small delay between requests
            logging.info(f"Finished. Successfully retrieved {success_count} of 5 feeds.")
            continue

        action = menu_actions.get(choice)
        if action:
            logging.info(f"--- Running: {action['text']} ---")
            action["func"](*action.get("args", []))
        else:
            print("Invalid choice. Please try again.")

    print("\nExiting script. Goodbye! 👋")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting gracefully...")
        sys.exit(0)
    except Exception as e:
        logging.critical(f"An unexpected critical error occurred: {e}", exc_info=True)
        sys.exit(1)