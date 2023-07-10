import sqlmap

# Define the target URL
url = "http://testphp.vulnweb.com/login.php"

# Create a SQLMap object
sqlmap = sqlmap.Sqlmap()

# Start a SQLMap scan
sqlmap.scan(url)

# Check for SQL injection vulnerabilities
if sqlmap.is_vulnerable():
    # Print the injection point
    print(sqlmap.get_injection_point())
