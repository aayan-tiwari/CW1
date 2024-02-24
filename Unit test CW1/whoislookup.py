import subprocess

def whois_lookup(domain_name):
    try:
        result = subprocess.run(['whois', domain_name], capture_output=True, text=True)
        print(result.stdout)
    except FileNotFoundError:
        print("'whois' command not found. Make sure it is installed and available in your system.")

# Example usage:
if __name__ == "__main__":
    domain_name = input("Enter domain name: ")
    whois_lookup(domain_name)
