import requests
import datetime
import pandas as pd
from io import StringIO

class CveScraper:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key=None):
        self.session = requests.Session()
        self.api_key = api_key

    def get_cve_by_id(self, cve_id):
        """Fetch a specific CVE by its ID."""
        url = f"{self.BASE_URL}?cveId={cve_id}"
        return self._fetch_data(url)

    def get_cves_by_year(self, year, results_per_page=100):
        """Fetch CVEs published in a specific year."""
        all_cves = []
        start_date = datetime.datetime(year, 1, 1)
        end_date = datetime.datetime(year, 12, 31)

        while start_date <= end_date:
            chunk_end_date = min(start_date + datetime.timedelta(days=120), end_date)
            url = f"{self.BASE_URL}?pubStartDate={start_date.isoformat()}Z&pubEndDate={chunk_end_date.isoformat()}Z&resultsPerPage={results_per_page}"
            response = self.session.get(url)

            if response.status_code == 200:
                data = response.json()
                if "vulnerabilities" in data:
                    all_cves.extend(data["vulnerabilities"])
            
            start_date = chunk_end_date + datetime.timedelta(days=1)

        return all_cves

    def _fetch_data(self, url):
        """Fetch data from the API and return JSON or an error message."""
        response = self.session.get(url)
        return response.json() if response.status_code == 200 else {"error": f"Failed to fetch data: {response.status_code}"}

class CisaScraper:
    CISA_CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

    def __init__(self):
        self.session = requests.Session()

    def get_cisa_data(self):
        """Download CISA KEV data and return as a pandas DataFrame."""
        try:
            response = self.session.get(self.CISA_CSV_URL)
            response.raise_for_status()
            csv_data = StringIO(response.text)
            df = pd.read_csv(csv_data)
            
            # Select relevant columns
            df = df[['cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded', 'shortDescription', 'requiredAction']]
            df.columns = ['CVE ID', 'Vendor', 'Product', 'Vulnerability Name', 'Date Added', 'Description', 'Required Action']
            
            return df
        except requests.RequestException as e:
            print(f"Error fetching CISA data: {e}")
            return pd.DataFrame()  # Return empty DataFrame on failure

# Example usage:
if __name__ == "__main__":
    cve_scraper = CveScraper()
    print(f"CVE by ID: {cve_scraper.get_cve_by_id('CVE-2024-1234')}")
    print(f"CVEs by Year: {cve_scraper.get_cves_by_year(2023)}")

    cisa_scraper = CisaScraper()
    cisa_data = cisa_scraper.get_cisa_data()
    print(f"Fetched {len(cisa_data)} CISA vulnerabilities")