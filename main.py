import altair as alt
import pandas as pd
import streamlit as st
from scrape import CveScraper, CisaScraper

# Initialize scrapers
cve_scraper = CveScraper()
cisa_scraper = CisaScraper()

# Set up Streamlit page
st.set_page_config(page_title="Vulnerability Finder", page_icon="👾")
st.title("👾 Vulnerability Finder")
st.write(
    """
    This app visualizes vulnerabilities from MITRE, NIST, and CISA, providing insights into common CVEs
    and known exploited vulnerabilities.
    """
)

# Year selection for CVE scraping
years = st.slider("Select Years for CVEs:", 2021, 2025, (2022, 2025))

def fetch_cve_data(selected_years):
    """Fetch CVEs for the selected years and structure data for display."""
    all_cves = []
    for year in selected_years:
        cves = cve_scraper.get_cves_by_year(year)
        for cve in cves:
            cve_id = cve.get("cve", {}).get("id", "N/A")
            description = cve.get("cve", {}).get("descriptions", [{}])[0].get("value", "No description")
            severity = cve.get("cve", {}).get("metrics", {}).get("cvssMetricV2", [{}])[0].get("baseSeverity", "N/A")
            all_cves.append({"CVE ID": cve_id, "Year": year, "Severity": severity, "Description": description})
    
    return pd.DataFrame(all_cves)

df_cves = fetch_cve_data(years)

# Display CVE data
st.header("📊 NIST CVE Data")
if df_cves.empty:
    st.write("No CVEs found for the selected years.")
else:
    st.dataframe(df_cves, use_container_width=True)

def fetch_cisa_data():
    """Fetch and cache CISA KEV data."""
    return cisa_scraper.get_cisa_data()

df_cisa = fetch_cisa_data()

# Display CISA KEV Data
st.header("🛡️ CISA Known Exploited Vulnerabilities")
if df_cisa.empty:
    st.write("No CISA KEV data available at the moment.")
else:
    st.dataframe(df_cisa, use_container_width=True)