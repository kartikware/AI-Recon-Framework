import requests


class NVDLookup:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def search(self, service, version):
        if not service or not version:
            return []

        clean_version = version.split()[0]
        keyword = f"{service} {clean_version}"

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5
        }

        try:
            response = requests.get(self.base_url, params=params, timeout=10)

            if response.status_code != 200:
                return []

            data = response.json()

            vulnerabilities = []

            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})

                cve_id = cve_data.get("id")

                metrics = cve_data.get("metrics", {})
                cvss_score = None

                # Try CVSS v3.1 first
                if "cvssMetricV31" in metrics:
                    cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics:
                    cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                vulnerabilities.append({
                    "id": cve_id,
                    "cvss": cvss_score
                })

            return vulnerabilities

        except Exception as e:
            print("NVD error:", e)
            return []
