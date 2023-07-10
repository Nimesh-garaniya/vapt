import requests

def get_server_version(url):
    try:
        response = requests.get(url)
        server_header = response.headers.get('Server')
        if server_header:
            return server_header
        else:
            return "Server version not found"
    except requests.exceptions.RequestException as e:
        return f"An error occurred: {e}"

# Example usage
url = 'https://www.example.in/'
server_version = get_server_version(url)
print(f"Server version: {server_version}")
