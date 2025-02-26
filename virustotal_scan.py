import requests
import json

def scan_url(api_key, url):
    headers = {"x-apikey": api_key}
    data = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    
    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]
        return scan_id
    else:
        print ("Error submitting URL")
        return None

def get_report(api_key, scan_id):
    headers = {"x-apikey": api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print ("Error fetching report")
        return None

# Replace with your VirusTotal API key
API_KEY = "your_virustotal_api_key"
URL_TO_SCAN = "http://example.com"

scan_id = scan_url(API_KEY, URL_TO_SCAN)
if scan_id:
    report = get_report(API_KEY, scan_id)
    print (json.dumps(report, indent=4))
]

 Note: add “your_virustotal_api_key” in this section
