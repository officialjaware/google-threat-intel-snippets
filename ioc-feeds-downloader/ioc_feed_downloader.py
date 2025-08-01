import requests
import bz2
import datetime
import os
import sys
import time
import json

def get_api_key():
    """Prompts the user for their Google Threat Intelligence API key."""
    api_key = input("\nPlease enter your Google Threat Intelligence API Key: ").strip()
    if not api_key:
        print("API Key cannot be empty. Exiting.")
        sys.exit(1)
    return api_key

def get_feed_batch(api_key, feed_endpoint, output_dir="feeds_output"):
    """
    Fetches and decompresses a single minute's batch for a given feed.

    Args:
        api_key (str): The Google Threat Intelligence API key.
        feed_endpoint (str): The API endpoint for the feed (e.g., 'files', 'file_behaviours').
        output_dir (str): Directory to save the output files.

    Returns:
        tuple: (bool, str) - a boolean indicating success and the path to the saved file if successful.
    """
    # Calculate the time for the most recent available batch (60 minutes lag)
    target_time_dt = datetime.datetime.utcnow() - datetime.timedelta(minutes=60)
    target_time_str = target_time_dt.strftime("%Y%m%d%H%M")

    url = f"https://www.virustotal.com/api/v3/feeds/{feed_endpoint}/{target_time_str}"
    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }

    print(f"\nAttempting to retrieve {feed_endpoint} feed for time: {target_time_str} UTC...")

    try:
        response = requests.get(url, headers=headers, allow_redirects=True, stream=True)
        response.raise_for_status()

        if response.status_code == 200:
            print(f"Successfully retrieved redirect for {feed_endpoint}. Decompressing...")

            os.makedirs(output_dir, exist_ok=True)
            output_filepath = os.path.join(output_dir, f"{feed_endpoint}_{target_time_str}.jsonl")

            decompressor = bz2.BZ2Decompressor()
            with open(output_filepath, 'wb') as f_out:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        try:
                            f_out.write(decompressor.decompress(chunk))
                        except bz2.BZ2Error as e:
                            print(f"Error decompressing {feed_endpoint} feed: {e}")
                            os.remove(output_filepath)
                            return False, None
            print(f"Successfully saved {feed_endpoint} feed to {output_filepath}")
            return True, output_filepath
        elif response.status_code == 404:
            print(f"No batch found for {feed_endpoint} at {target_time_str}. This is expected for missing batches.")
            return False, None
        else:
            print(f"Error retrieving {feed_endpoint} feed: HTTP {response.status_code} - {response.text}")
            return False, None

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while retrieving {feed_endpoint} feed: {e}")
        return False, None

def download_file_from_url(api_key, download_url, file_type, file_id, output_dir="feeds_output"):
    """
    Downloads a specific file (e.g., PCAP, memdump, or a malware sample) from a URL.
    """
    headers = {
        "x-apikey": api_key,
    }
    
    print(f"Attempting to download {file_type} for file with ID: {file_id}...")
    
    try:
        response = requests.get(download_url, headers=headers, stream=True)
        response.raise_for_status()
        
        if response.status_code == 200:
            os.makedirs(output_dir, exist_ok=True)
            
            # Use SHA256 for filename if available, or the generic ID
            sha256 = file_id.split('_')[0] if '_' in file_id else file_id
            
            if file_type == "file":
                output_filename = f"{sha256}.download"
            else:
                output_filename = f"{sha256}_{file_type}.bin"
            
            output_filepath = os.path.join(output_dir, output_filename)
            
            with open(output_filepath, 'wb') as f_out:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f_out.write(chunk)
            print(f"Successfully saved {file_type} to {output_filepath}")
            return True
        else:
            print(f"Error downloading {file_type}: HTTP {response.status_code} - {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while downloading {file_type}: {e}")
        return False

def process_file_feed_for_downloads(api_key):
    """
    Fetches the latest file feed and downloads file samples.
    """
    success, filepath = get_feed_batch(api_key, "files")
    if not success:
        return

    while True:
        mode = input(f"Do you want to download a (s)ample of 2 files or (a)ll? (s/a): ").strip().lower()
        if mode in ['s', 'a']:
            break
        else:
            print("Invalid choice. Please enter 's' for sample or 'a' for all.")

    output_dir = "feeds_output"
    download_count = 0
    sample_size = 2

    try:
        with open(filepath, 'r') as f_in:
            for line in f_in:
                if mode == 's' and download_count >= sample_size:
                    print(f"Sample size of {sample_size} reached. Stopping download.")
                    break
                    
                data = json.loads(line)

                if "download_url" in data and "sha256" in data:
                    download_url = data["download_url"]
                    sha256 = data["sha256"]
                    
                    if download_url:
                        if download_file_from_url(api_key, download_url, "file", sha256, output_dir):
                            download_count += 1
                    else:
                        print(f"No download URL found for file with SHA256: {sha256}.")
                        
    except FileNotFoundError:
        print(f"Error: File feed file not found at {filepath}.")
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {filepath}.")
    except Exception as e:
        print(f"An unexpected error occurred while processing the feed: {e}")

    print(f"\nFinished processing. Downloaded {download_count} files.")


def process_behaviour_feed_for_downloads(api_key, file_type):
    """
    Fetches the latest behaviour feed and downloads PCAP/memdump/EVTX files.
    """
    success, filepath = get_feed_batch(api_key, "file_behaviours")
    if not success:
        return

    while True:
        mode = input(f"Do you want to download a (s)ample of 2 {file_type} files or (a)ll? (s/a): ").strip().lower()
        if mode in ['s', 'a']:
            break
        else:
            print("Invalid choice. Please enter 's' for sample or 'a' for all.")

    output_dir = "feeds_output"
    download_count = 0
    sample_size = 2
    
    try:
        with open(filepath, 'r') as f_in:
            for line in f_in:
                if mode == 's' and download_count >= sample_size:
                    print(f"Sample size of {sample_size} reached. Stopping download.")
                    break
                    
                data = json.loads(line)
                
                if "context_attributes" in data and file_type in data["context_attributes"]:
                    download_url = data["context_attributes"][file_type]
                    sha256 = data["id"].split("_")[0]
                    
                    if download_url:
                        if download_file_from_url(api_key, download_url, file_type, sha256, output_dir):
                            download_count += 1
                    else:
                        print(f"No {file_type} download URL found for {sha256}.")
                        
    except FileNotFoundError:
        print(f"Error: Behaviour feed file not found at {filepath}.")
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {filepath}.")
    except Exception as e:
        print(f"An unexpected error occurred while processing the feed: {e}")

    print(f"\nFinished processing. Downloaded {download_count} {file_type} files.")

def main():
    api_key = get_api_key()

    feeds = {
        "1": {"name": "File Intelligence", "endpoint": "files"},
        "2": {"name": "Sandbox Analyses", "endpoint": "file_behaviours"},
        "3": {"name": "Domain Intelligence", "endpoint": "domains"},
        "4": {"name": "IP Intelligence", "endpoint": "ip_addresses"},
        "5": {"name": "URL Intelligence", "endpoint": "urls"}
    }

    while True:
        print("\n--- Google Threat Intelligence Feed Menu ---")
        for key, value in feeds.items():
            print(f"{key}. Get a minutely batch for {value['name']}")
        print("6. Get a minutely batch for ALL feeds")
        print("\n--- File Artifacts ---")
        print("7. Download files from the latest File Intelligence feed")
        print("\n--- Sandbox Artifacts ---")
        print("8. Download available PCAP files from the latest Sandbox Analyses feed")
        print("9. Download available Memory Dump files from the latest Sandbox Analyses feed")
        print("10. Download available EVTX files from the latest Sandbox Analyses feed")
        print("\n11. Exit")
        
        choice = input("\nEnter your choice: ").strip()

        if choice == '11':
            print("\nExiting script. Goodbye!")
            break
        elif choice == '6':
            print("\n--- Retrieving all minutely feed batches ---")
            success_count = 0
            for key, feed_info in feeds.items():
                if get_feed_batch(api_key, feed_info['endpoint'])[0]:
                    success_count += 1
                time.sleep(1)
            print(f"\nFinished retrieving all feeds. {success_count} feeds successfully processed.")
        elif choice in feeds:
            selected_feed = feeds[choice]
            print(f"\n--- Retrieving {selected_feed['name']} minutely batch ---")
            get_feed_batch(api_key, selected_feed['endpoint'])
        elif choice == '7':
            print("\n--- Downloading files from latest File Intelligence feed ---")
            process_file_feed_for_downloads(api_key)
        elif choice == '8':
            print("\n--- Downloading PCAP files from latest behaviour feed ---")
            process_behaviour_feed_for_downloads(api_key, 'pcap')
        elif choice == '9':
            print("\n--- Downloading Memory Dump files from latest behaviour feed ---")
            process_behaviour_feed_for_downloads(api_key, 'memdump')
        elif choice == '10':
            print("\n--- Downloading EVTX files from latest behaviour feed ---")
            process_behaviour_feed_for_downloads(api_key, 'evtx')
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    print("\nNote: Access to these feeds and files requires specific Google Threat Intelligence licenses.")
    print("If you encounter '403 Forbidden' errors, please verify your license status.")
    main()