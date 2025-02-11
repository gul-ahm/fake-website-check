from flask import Flask, request, render_template
import requests
import whois
import ssl
import socket
import json
import validators
from bs4 import BeautifulSoup

# Initialize Flask App
app = Flask(__name__)

# Google Safe Browsing API Key (Replace with your own)
API_KEY = "your_google_safe_browsing_api_key"

def check_domain_info(url):
    """Get WHOIS domain information"""
    try:
        domain = url.replace("http://", "").replace("https://", "").split('/')[0]
        domain_info = whois.whois(domain)
        # Handle multiple creation dates (if returned as a list)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]  # Take the first date
        expiration_date = domain_info.expiration_date
        return f"✅ This website was registered on: {creation_date} and will expire on: {expiration_date}.<br>"
    except Exception as e:
        return "⚠️ Warning: We couldn't fetch the domain details. This website may be unofficial, harmful, or unsafe to visit. Be careful!<br>"

def check_ssl_certificate(url):
    """Check if the website has a valid SSL certificate"""
    try:
        domain = url.replace("http://", "").replace("https://", "").split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        return "✅ This website has a valid SSL certificate, which means your connection is secure.<br>"
    except Exception as e:
        return "⚠️ Warning: This website does not have a valid SSL certificate. It may be unsafe or a phishing website. Do not visit this site for your security.<br>"

def check_google_safe_browsing(url):
    """Check URL against Google Safe Browsing API"""
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "your_client_id", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(endpoint, params={"key": API_KEY}, json=payload)
    result = response.json()
    return "⚠️ Warning: This website is flagged as unsafe by Google Safe Browsing. Proceed with caution!<br>" if "matches" in result else "✅ This website is safe according to Google Safe Browsing.<br>"

def check_website_headers(url):
    """Analyze website security headers"""
    try:
        response = requests.get(url)
        headers = response.headers
        missing_headers = []
        security_headers = ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"]
        for header in security_headers:
            if header not in headers:
                missing_headers.append(header)
        return f"⚠️ This website is missing some important security headers: {', '.join(missing_headers)}. This could make it less secure.<br>" if missing_headers else "✅ This website has all the necessary security headers, making it more secure.<br>"
    except Exception as e:
        return f"❌ We couldn't analyze the website's security headers. This might be a temporary issue.<br>"

def analyze_website_code(url):
    """Analyze HTML code for hidden redirects or suspicious scripts"""
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all("script")
        suspicious_scripts = [script for script in scripts if "eval" in str(script) or "document.write" in str(script)]
        return f"⚠️ We found {len(suspicious_scripts)} suspicious scripts on this website. Be cautious!<br>" if suspicious_scripts else "✅ No suspicious scripts were found on this website.<br>"
    except Exception as e:
        return f"❌ We couldn't analyze the website's code. This might be a temporary issue.<br>"

def analyze_external_links(url):
    """Analyze external links and third-party requests"""
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True) if "http" in a['href']]
        external_links = [link for link in links if url not in link]
        return f"🔗 This website contains {len(external_links)} external links. Be cautious when clicking on them.<br>"
    except Exception as e:
        return f"❌ We couldn't analyze the external links. This might be a temporary issue.<br>"

@app.route("/", methods=["GET", "POST"])
def index():
    """Render the homepage and process URL checks"""
    result = {}
    url = ""

    if request.method == "POST":
        url = request.form["url"]
        
        if validators.url(url):
            result["Domain Information"] = check_domain_info(url)
            result["SSL Certificate"] = check_ssl_certificate(url)
            result["Google Safe Browsing"] = check_google_safe_browsing(url)
            result["Security Headers"] = check_website_headers(url)
            result["Code Analysis"] = analyze_website_code(url)
            result["External Links"] = analyze_external_links(url)
        else:
            result["Error"] = "❌ The URL you entered is not valid. Please enter a valid URL.<br>"

    return render_template("index.html", result=result, url=url)

if __name__ == "__main__":
    app.run(debug=True)