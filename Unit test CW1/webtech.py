import webtech
def analyze_web_tech(url):
    wt = webtech.WebTech()

    try:
        results = wt.start_from_url(url, timeout=1)
        print(results)
    except Exception as e:
        print(f"Error analyzing web tech: {e}")

def main():
    url = input("Enter URL: ")
    analyze_web_tech(url)

if __name__ == "__main__":
    main()
