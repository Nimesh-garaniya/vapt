import subprocess


def nmap_scan(ip_address):
    """
  Performs an Nmap scan of the specified IP address and returns the results.

  Args:
    ip_address: The IP address of the website to scan.

  Returns:
    A list of dictionaries, where each dictionary contains information about a
    single open port. The information includes the port number, the service
    running on the port, and the state of the port.
  """

    results = []

    # Run the Nmap scan.
    command = "nmap -sV -sC -p- " + ip_address
    output = subprocess.check_output(command, shell=True)

    # Parse the Nmap output.
    for line in output.decode("utf-8").splitlines():
        if line.startswith("Nmap scan report for "):
            # This is the header line for a new host.
            host = line.split()[1]

        # Check if this line contains information about an open port.
        elif line.startswith("(Host is up (0.000000s latency).)"):
            # This line indicates that the host is up and running.

            # Get the port number and service name.
            port_number = line.split(":")[1].split()[0]
            service_name = line.split(":")[1].split()[1]

            # Get the state of the port.
            port_state = line.split("(")[1].split()[0]

            # Add the port information to the results list.
            results.append({
                "port_number": port_number,
                "service_name": service_name,
                "port_state": port_state
            })

    return results


def main():
    # Get the IP address of the website to scan.
    ip_address = input("Enter the IP address of the website to scan: ")

    # Run the Nmap scan and print the results.
    results = nmap_scan(ip_address)
    for result in results:
        print(result)


if __name__ == "__main__":
    main()
