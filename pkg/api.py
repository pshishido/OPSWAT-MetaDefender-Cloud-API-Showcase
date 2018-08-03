import requests
import json
import time
import sys

# a simple class to abstract the MetaDefender API calls
class API:

    def __init__(self):
        # an API Key is required for using MD Cloud API's (not required for Core)
        self.headers = {"apikey" : "<your_api_key>"}

    # Fetch Scan Result by File Hash via MetaDefender Cloud
    def hashScanResult(self, file_hash):
        api_url = "https://api.metadefender.com/v2/hash/" + file_hash
        response = requests.get(api_url, headers=self.headers)
        if response.status_code != 200:
            print("The server returned a ", response.status_code, file=sys.stderr)
            sys.exit(1)
        data = response.json()
        report = [False, data]
        if file_hash.upper() not in data.keys():
            report[0] = True
        return report

    # Scan a File via MetaDefender Cloud
    def uploadFile(self, file_name):
        api_url = "https://api.metadefender.com/v2/file"
        files = open(file_name, "rb")
        response = requests.post(api_url, headers=self.headers, data=files)
        if response.status_code != 200:
            print("The server returned a ", response.status_code, file=sys.stderr)
            sys.exit(1)
        data = response.json()
        return data["data_id"]

    # Request File Data Sanitization via MetaDefender Cloud (Initial step of CDR)
    def requestDataSanitization(self, file_name):
        api_url = "https://api.metadefender.com/v2/file"
        headers = self.headers
		# user_agent is a required header for the data sanitization request
        headers["user_agent"] = "mcl-metadefender-rest-sanitize-disabled-unarchive"
        files = open(file_name, "rb")
        response = requests.post(api_url, headers=headers, data=files)
        if response.status_code != 200:
            print("The server returned a ", response.status_code, file=sys.stderr)
            sys.exit(1)
        data = response.json()
        file_id = data["data_id"]
        return file_id

    # Download Sanitized File via MetaDefender Cloud (Concluding step of CDR)
    def retrieveSanitizedFile(self, file_id, file_name):
        api_url = "https://api.metadefender.com/v2/file/" + file_id
        headers = self.headers
        # the user_agent header is also required for obtaining the newly sanitized file via a download link
        headers["user_agent"] = "mcl-metadefender-rest-sanitize-disabled-unarchive"
        response = requests.get(api_url, headers=headers)
        if response.status_code != 200:
            print("The server returned a ", response.status_code, file=sys.stderr)
            sys.exit(1)
        data = response.json()
        if "sanitized" not in data.keys() or data["sanitized"]["result"] == "Sanitization failed":
            print(file_name + " did not undergo data sanitization.")
        else:
            print(file_name + " has been sanitized. \nThe sanitized file can be downloaded using the following link: "
                  + data["sanitized"]["file_path"])


    # Fetch Scan Result (by Data ID) via MetaDefender Cloud
    def retrieveScanResult(self, file_data_id):
        api_url = "https://api.metadefender.com/v2/file/" + file_data_id
        response = requests.get(api_url, headers=self.headers)
        if response.status_code != 200:
            print("The server returned a ", response.status_code, file=sys.stderr)
            sys.exit(1)
        data = response.json()

        # Ensure that we have the full scan report, especially useful for scanning large files
        while data['scan_results']['progress_percentage'] < 100:
            response = requests.get(api_url, headers=self.headers)
            data = response.json()
            time.sleep(1)
        return data