import requests

def directory_bruteforce(base_url, wordlist):
    try:
        with open(wordlist, 'r') as file:
            paths = [line.strip() for line in file.readlines()]

        for path in paths:
            full_url = f"{base_url}/{path}"
            response = requests.get(full_url)

            if response.status_code == 200:
                print(f"Found: {full_url}")

    except Exception as e:
        print(f"Error: {e}")

def main():
    base_url = input("Enter the base URL (e.g., http://example.com): ")
    wordlist = input("Enter the path to the wordlist file: ")

    directory_bruteforce(base_url, wordlist)

if __name__ == "__main__":
    main()
