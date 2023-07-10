import webbrowser

# Read the payloads from the file
with open('payloads.txt', 'r') as file:
    payloads = file.read().splitlines()

# Get the target site from the user
target_site = input("Enter the target site: ")

# Generate and open browser links for each payload
for payload in payloads:
    modified_payload = payload.replace("https://malicious-website.com", target_site)
    browser_link = f"data:text/html,<html><body><script>window.open('{modified_payload}', '_blank');</script></body></html>"
    webbrowser.open(browser_link, new=2)
