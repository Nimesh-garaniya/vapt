import requests

def detect_vulnerabilities(url):
  """
  Detects vulnerabilities in a website.

  Args:
    url: The URL of the website to scan.

  Returns:
    A list of vulnerabilities found in the website.
  """

  vulnerabilities = []

  # Check for HTTP Strict Transport Security (HSTS).
  try:
    response = requests.get(url, verify=True)
  except requests.exceptions.SSLError:
    vulnerabilities.append("HTTP Strict Transport Security (HSTS) is not implemented.")

  # Check for Content Security Policy (CSP).
  try:
    response = requests.get(url)
    headers = response.headers
    if "Content-Security-Policy" not in headers:
      vulnerabilities.append("Content Security Policy (CSP) is not implemented.")
  except requests.exceptions.ConnectionError:
    pass

  # Check for X-Content-Type-Options.
  try:
    response = requests.get(url)
    headers = response.headers
    if "X-Content-Type-Options" not in headers or headers["X-Content-Type-Options"] != "nosniff":
      vulnerabilities.append("X-Content-Type-Options is not set to 'nosniff'.")
  except requests.exceptions.ConnectionError:
    pass

  # Check for Server header.
  try:
    response = requests.get(url)
    headers = response.headers
    if "Server" not in headers:
      vulnerabilities.append("Server header is not set.")
  except requests.exceptions.ConnectionError:
    pass

  # Check for Access-Control-Allow-Origin header.
  try:
    response = requests.get(url)
    headers = response.headers
    if "Access-Control-Allow-Origin" not in headers:
      vulnerabilities.append("Access-Control-Allow-Origin header is not set.")
  except requests.exceptions.ConnectionError:
    pass

  # Check for Access-Control-Allow-Methods header.
  try:
    response = requests.get(url)
    headers = response.headers
    if "Access-Control-Allow-Methods" not in headers:
      vulnerabilities.append("Access-Control-Allow-Methods header is not set.")
  except requests.exceptions.ConnectionError:
    pass

  # Check for X-XSS-Protection header.
  try:
    response = requests.get(url)
    headers = response.headers
    if "X-XSS-Protection" not in headers or headers["X-XSS-Protection"] != "1; mode=block":
      vulnerabilities.append("X-XSS-Protection is not set to '1; mode=block'.")
  except requests.exceptions.ConnectionError:
    pass

  return vulnerabilities


if __name__ == "__main__":
  url = input("Enter the URL of the website to scan: ")
  vulnerabilities = detect_vulnerabilities(url)

  if vulnerabilities:
    print("The following vulnerabilities were found in the website:")
    for vulnerability in vulnerabilities:
      print(vulnerability)
  else:
    print("No vulnerabilities were found in the website.")
