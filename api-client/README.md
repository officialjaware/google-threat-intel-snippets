# Google Threat Intelligence API Client
A comprehensive, interactive command-line tool for interacting with the most common endpoints of the Google Threat Intelligence API. This script provides a user-friendly menu to access a wide range of threat intelligence data, from IoC reports to advanced corpus searches, without needing to write code for each request.

The tool is built on a scalable and maintainable framework, making it easy to extend with new functionality.

# Features
**Interactive Menu:** A simple, numbered menu to navigate through all major API functionalities.

**Comprehensive API Coverage:** Access to over 29 different API operations, including:

**IoC Investigation:** Get reports and add comments for IPs, domains, files, and URLs.

**File Operations:** Upload, rescan, and download files (both small and large).

**Threat Collections:** Create, list, update, and delete custom IoC collections.

**Threat Profiles:** Manage targeted threat profiles and get recommendations.

**Advanced Search:** Perform powerful searches across the Google Threat Intelligence corpus.

**Secure API Key Handling:** Prioritizes using an environment variable (GTI_API_KEY) and falls back to a secure password prompt (getpass) to keep your key safe.

**Robust Error Handling:** Includes automatic retries with exponential backoff for network errors and gracefully handles invalid API keys by re-prompting the user.

**Automatic File Output:** All API responses are automatically saved as well-structured JSON files in an outputs/ directory, timestamped for easy reference.

## Prerequisites
Python 3.7+

```pip``` (Python package installer)

```venv``` (included in standard Python distributions)

## Setup & Installation
Follow these steps to set up the tool in a clean, isolated virtual environment.

1. Get the Script:
Clone the repository or download the Python script (`client.py`) to a local directory on your machine.

1. Create requirements.txt:
In the same directory as the script, create a file named `requirements.txt` and add the following line to it:

    ```
    requests
    ```

3. Set Up the Virtual Environment: Open your terminal or command prompt, navigate to the project directory, and run the following commands:

    On macOS/Linux:

    ```bash
    # Create a virtual environment named 'venv'
    python3 -m venv venv

    # Activate the virtual environment
    source venv/bin/activate

    # You will see (venv) at the beginning of your prompt
    # Now, install the required packages
    pip install -r requirements.txt
    ```

    On Windows:

    ```bash
    # Create a virtual environment named 'venv'
    python -m venv venv

    # Activate the virtual environment
    .\venv\Scripts\activate

    # You will see (venv) at the beginning of your prompt
    # Now, install the required packages
    pip install -r requirements.txt
    ```

4. Configure Your API Key (Recommended):
For the best security, set your Google Threat Intelligence API key as an environment variable. The script will automatically detect and use it.

    On macOS/Linux:

    ```
    export GTI_API_KEY='your_api_key_here'
    ```

    (To make this permanent, add the line to your ~/.bashrc, ~/.zshrc, or other shell profile file.)

    On Windows:

    ```
    # For the current session
    set GTI_API_KEY="your_api_key_here"

    # To set it permanently
    setx GTI_API_KEY "your_api_key_here"
    ```

    If you do not set the environment variable, the script will securely prompt you to enter the key each time it runs.

## Usage
With your virtual environment still active, run the script from the terminal:

```bash
python client.py
```

You will be presented with the main menu. Simply enter the number corresponding to the action you wish to perform and follow the on-screen prompts.

```
=============== Main Menu ===============
--- IoC Investigation ---
  1. Get IP Address Report
  2. Add Comment to IP Address
  ...
--- Other ---
  0. Exit
Enter your choice:
```

To exit the script, choose option `0`.

To deactivate the virtual environment when you are finished, simply run:

```bash
deactivate
```

## Output
All successful API responses are saved as `.json` files inside the `outputs/` directory, which is created automatically.

Filenames are structured for easy identification:

`{operation_name}_{identifier}_{timestamp}.json`

Example:

`ip_report_8.8.8.8_20250731_205146.json`

## Troubleshooting
Here are some common issues you might encounter and how to resolve them.

| Error Message | Cause | Solution|
| ------- | ------ | ------- |
| `HTTP Error: 401 - WrongCredentialsError`     | The API key you provided is incorrect, has been revoked, or is typed incorrectly.   | The script will automatically detect this and re-prompt you for a new key. Carefully copy and paste your valid API key.    |
| `HTTP Error: 403 - Forbidden or UserNotActiveError`  | Your API key is valid, but your account does not have the necessary permissions to access the requested endpoint.   | Verify that your license includes access to the specific feature you are trying to use (e.g., advanced search, file downloads). Contact your Google Account Team or Support for permission issues.   |
| `HTTP Error: 404 - NotFoundError` | The specific resource you requested (e.g., a file hash, IP address, or domain) does not exist in the dataset. | This is not necessarily a script error. Double-check the identifier you entered for typos. If it's correct, the item simply hasn't been seen or analyzed.|
| `ModuleNotFoundError: No module named 'requests'` | The requests library was not installed, or you are running the script outside the activated virtual environment. | Make sure your virtual environment is active (you should see (venv) in your prompt). If it is, run pip install -r requirements.txt again to install the dependency. |
| `FileNotFoundError when trying to upload a file` | The file path you entered is incorrect, or the file does not exist at that location. | Verify the file path is correct. Use an absolute path (e.g., /Users/me/Documents/file.txt or C:\Users\Me\Documents\file.txt) if you are unsure about the relative path.
 |












