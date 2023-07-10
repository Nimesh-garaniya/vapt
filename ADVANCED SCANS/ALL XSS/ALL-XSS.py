import requests
from bs4 import BeautifulSoup


class XSSScanner:

    def __init__(self, url):
        self.url = url

    def scan(self):
        response = requests.get(self.url)
        html = response.content

        soup = BeautifulSoup(html, "html.parser")

        results = []

        # Find all forms in the HTML content.
        forms = soup.find_all("form")

        # For each form, find all input fields that allow user input.
        for form in forms:
            input_fields = form.find_all("input")

            # For each input field, check if it allows user input.
            for input_field in input_fields:
                if input_field["type"] in ["text", "textarea", "select"]:

                    # Get the value of the input field.
                    value = input_field["value"]

                    # Check if the value contains any malicious code.
                    if value.find("<script>") != -1:
                        # The value contains malicious code.
                        results.append({
                            "type": "Reflected XSS",
                            "location": input_field["id"],
                            "vulnerable_payload": value
                        })

                    # Check if the value contains any cookies.
                    if value.find("Cookie") != -1:
                        # The value contains cookies.
                        results.append({
                            "type": "Steal Cookies with Reflected XSS",
                            "location": input_field["id"],
                            "vulnerable_payload": value
                        })

        # Find all div tags in the HTML content.
        divs = soup.find_all("div")

        # For each div tag, check if it contains any malicious code.
        for div in divs:
            if div.find("<script>") != -1:
                # The div tag contains malicious code.
                results.append({
                    "type": "Stored XSS",
                    "location": div.get("id", "No ID"),
                    "vulnerable_payload": div.text
                })

        # Find all script tags in the HTML content.
        script_tags = soup.find_all("script")

        # For each script tag, check if it contains any malicious code.
        for script_tag in script_tags:
            if script_tag.find("alert(1)") != -1:
                # The script tag contains malicious code.
                results.append({
                    "type": "DOM-based XSS",
                    "location": script_tag["src"],
                    "vulnerable_payload": script_tag.text
                })

        return results


if __name__ == "__main__":
    url = input("Enter the URL of the website to scan: ")

    xss_scanner = XSSScanner(url)

    results = xss_scanner.scan()

    # Print the results of the scan.
    for result in results:
        print(result)
