import dns.resolver

def enumerate_subdomains(domain, wordlist_file):
    try:
        with open(wordlist_file, 'r') as file:
            subdomains = [line.strip() for line in file]

        subdomains_found = False

        for subdomain in subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                for answer in answers:
                    print(f"Found: {full_domain} - {answer}")
                    subdomains_found = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass

        if not subdomains_found:
            print("No subdomains found.")

    except Exception as e:
        print(f"Error: {e}")

def main():
    try:
        domain = input("Enter domain: ")
        wordlist_file = input("Enter wordlist file path: ")

        enumerate_subdomains(domain, wordlist_file)

    except KeyboardInterrupt:
        print("\nProcess interrupted.")

if __name__ == "__main__":
    main()
