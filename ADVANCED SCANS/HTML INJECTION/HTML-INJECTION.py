import requests

# Read the payloads from the file
with open('payloads.txt', 'r') as file:
    payloads = file.read().splitlines()

# Specify the target URL
target_url = 'https://www.example.com/'

# Inject and execute each payload
for payload in payloads:
    modified_url = target_url + payload
    response = requests.get(modified_url)
    if payload in response.text:
        print("Vulnerable payload: ", payload)
        print("Injection point: ", modified_url)
        break
