import os
import time
from pathlib import Path
from getpass import getpass
from urllib.parse import quote

import requests
import whois
from dotenv import load_dotenv, setkey

# Configuration
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.csv"
OUTPUT_PATH = BASE_DIR / "output.csv"
ENV_PATH = BASE_DIR / ".env"

HIBP_API_KEY = "HIBP_API_KEY"
USER_AGENT = "Houndter/1.0 (Data exposure assessment tool)"

HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount"
REQUEST_TIMEOUT = 15
MAX_RETRIES = 3



def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def get_api_key():
    """Load the HIBP API key or prompt for it and save it locally."""
    load_dotenv(ENV_PATH)
    api_key = os.getenv(HIBP_API_KEY, "").strip()

    if api_key:
        return api_key

    print("No HIBP API key was found.")
    print("Get an API key from https://haveibeenpwned.com/API/Key")

    while True:
        api_key = getpass("Enter your HIBP API key: ").strip()

        if api_key:
            break

        print("The API key cannot be empty.")

    try:
        ENV_PATH.touch(exist_ok=True)
        set_key(str(ENV_PATH), HIBP_API_KEY, api_key)
        print("API key saved to .env.")
    except OSError as exc:
        print(f"Warning: Could not save the API key: {exc}")
        print("The key will only be available for this session.")

    return api_key


def ip_lookup():
    clear_screen()

    while True:
        print("\nIP OSINT")
        ip = input("Target IP (q to quit): ").strip()

        if ip.lower() == "q":
            break

        if not ip:
            continue

        try:
            response = requests.get(
                f"http://ip-api.com/json/{quote(ip, safe='')}",
                params={
                    "fields": (
                        "status,message,country,countryCode,region,"
                        "regionName,city,zip,lat,lon,timezone,isp,org,as"
                    )
                },
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

            if data.get("status") != "success":
                print(f"Lookup failed: {data.get('message', 'Unknown error')}")
                continue

            print("\nResults:")
            print(f"Country:   {data.get('country')} ({data.get('countryCode')})")
            print(f"Region:    {data.get('regionName')} ({data.get('region')})")
            print(f"City:      {data.get('city')}")
            print(f"Zip Code:  {data.get('zip')}")
            print(f"Latitude:  {data.get('lat')}")
            print(f"Longitude: {data.get('lon')}")
            print(f"Timezone:  {data.get('timezone')}")
            print(f"ISP:       {data.get('isp')}")
            print(f"Org:       {data.get('org')}")
            print(f"AS:        {data.get('as')}")

        except (requests.RequestException, ValueError) as exc:
            print(f"Lookup error: {exc}")


def check_email_breach(email: str, api_key: str):
    """Check an email address against the HIBP breach database."""
    url = f"{HIBP_URL}/{quote(email, safe='')}"

    headers = {
        "hibp-api-key": api_key,
        "user-agent": USER_AGENT,
    }
    params = {"includeUnverified": "true"}

    for attempt in range(MAX_RETRIES + 1):
        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code == 200:
                print(f"[+] {email} appears in known breaches!")
                breaches = response.json()

                for breach in breaches:
                    print(
                        f" - Breach: {breach.get('Name', 'Unknown')} "
                        f"(Date: {breach.get('BreachDate', 'Unknown')})"
                    )

                return email

            if response.status_code == 404:
                print(f"[-] No known breaches found for {email}.")
                return None

            if response.status_code == 401:
                print("[X] Invalid HIBP API key.")
                return None

            if response.status_code == 403:
                print("[X] HIBP denied the request. Check API access and permissions.")
                return None

            if response.status_code == 429:
                if attempt == MAX_RETRIES:
                    print("[X] Rate limit persists. Giving up.")
                    return None

                retry_after = response.headers.get("Retry-After", "2")

                try:
                    wait_seconds = max(1, int(retry_after))
                except ValueError:
                    wait_seconds = 2

                print(f"[!] Rate limited. Waiting {wait_seconds} seconds...")
                time.sleep(wait_seconds)
                continue

            print(f"[X] Unexpected HTTP status: {response.status_code}")
            return None

        except (requests.RequestException, ValueError) as exc:
            print(f"[X] Request failed: {exc}")
            return None

    return None


def check_breach_db(valid_emails):
    """Find matching email records in the local CSV database."""
    if not valid_emails:
        return

    if not DB_PATH.is_file():
        print(f"[!] Local database not found: {DB_PATH}")
        return

    email_set = {email.casefold() for email in valid_emails}
    matches = []

    try:
        with DB_PATH.open("r", encoding="utf-8-sig", newline="") as database:
            for line in database:
                if any(email in line.casefold() for email in email_set):
                    print(line.rstrip())
                    matches.append(line)

        if matches:
            with OUTPUT_PATH.open("a", encoding="utf-8", newline="") as output:
                output.writelines(matches)

            print(f"\nSaved {len(matches)} matching record(s) to output.csv.")

    except OSError as exc:
        print(f"[X] Database error: {exc}")


def whoispwned(api_key):
    """Retrieve registration emails for a domain and check for breaches."""
    clear_screen()

    while True:
        print("\nHoundter - WHOIS / Breach Check")
        domain = input("Target domain (q to quit): ").strip()

        if domain.lower() == "q":
            break

        if not domain:
            continue

        try:
            whois_info = whois.whois(domain)
            emails = whois_info.get("emails") or []

            # WHOIS libraries may return one email or a collection.
            if isinstance(emails, str):
                emails = [emails]

            emails = sorted({
                email.strip()
                for email in emails
                if isinstance(email, str) and email.strip()
            })

            if not emails:
                print("No registration emails were found.")
                continue

            print(f"Found {len(emails)} registration email(s).")
            breached_emails = []

            for email in emails:
                result = check_email_breach(email, api_key)

                if result:
                    breached_emails.append(result)

            check_breach_db(breached_emails)

        except Exception as exc:
            print(f"[X] WHOIS lookup failed: {exc}")


def main():
    clear_screen()
    print(r'''
      :::    :::  ::::::::  :::    ::: ::::    ::: ::::::::: ::::::::::: :::::::::: ::::::::: 
     :+:    :+: :+:    :+: :+:    :+: :+:+:   :+: :+:    :+:    :+:     :+:        :+:    :+: 
    +:+    +:+ +:+    +:+ +:+    +:+ :+:+:+  +:+ +:+    +:+    +:+     +:+        +:+    +:+  
   +#++:++#++ +#+    +:+ +#+    +:+ +#+ +:+ +#+ +#+    +:+    +#+     +#++:++#   +#++:++#:    
  +#+    +#+ +#+    +#+ +#+    +#+ +#+  +#+#+# +#+    +#+    +#+     +#+        +#+    +#+    
 #+#    #+# #+#    #+# #+#    #+# #+#   #+#+# #+#    #+#    #+#     #+#        #+#    #+#     
###    ###  ########   ########  ###    #### #########     ###     ########## ###    ###    v1.1   

coded by: zxxn212

1) IP Lookup
2) WHOIS Email Breach Check
3) Exit
''')
    while True:
        choice = input("Select an option: ").strip()

        if choice == "1":
            ip_lookup()

        elif choice == "2":
            api_key = get_api_key()
            whoispwned(api_key)

        elif choice == "3":
            print("Goodbye.")
            break

        else:
            print("Invalid option. Select 1, 2, or 3.")


if __name__ == "__main__":
    main()
