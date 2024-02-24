import requests

def get_source_code(url):
    try:
        response = requests.get(url)

        if response.status_code == 200:
            return response.text
        else:
            return f"Failed to retrieve source code. Status code: {response.status_code}"

    except requests.RequestException as e:
        return f"Error: {e}"

def main():
    url = input("Enter URL: ")
    source_code = get_source_code(url)
    print(source_code)

if __name__ == "__main__":
    main()
