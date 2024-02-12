import tkinter as tk
from tkinter import filedialog, messagebox
import dns.resolver
import requests
import webtech
import whois

def get_source_code(url):
    try:
        response = requests.get(url)

        if response.status_code == 200:
            source_code_text.config(state=tk.NORMAL)
            source_code_text.delete(1.0, tk.END)
            source_code_text.insert(tk.END, response.text)
            source_code_text.config(state=tk.DISABLED)
        else:
            messagebox.showerror("Error", f"Failed to retrieve source code. Status code: {response.status_code}")

    except requests.RequestException as e:
        messagebox.showerror("Error", f"Error: {e}")

def enumerate_subdomains(domain, wordlist_file):
    subdomains_found = False

    try:
        with open(wordlist_file, 'r') as wordlist:
            subdomains = [line.strip() for line in wordlist.readlines()]

        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)

        for subdomain in subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                for answer in answers:
                    result_text.insert(tk.END, f"Found: {full_domain} - {answer}\n")
                    subdomains_found = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass  # Do nothing if the subdomain is not found

        if not subdomains_found:
            result_text.insert(tk.END, "No subdomains found.\n")

        result_text.config(state=tk.DISABLED)

    except Exception as e:
        messagebox.showerror("Error", f"Error: {e}")

def browse_wordlist(entry_widget):
    wordlist_file_path = filedialog.askopenfilename(title="Select Wordlist File", filetypes=[("Text Files", "*.txt")])
    entry_widget.delete(0, tk.END)
    entry_widget.insert(tk.END, wordlist_file_path)

def analyze_web_tech(url):
    wt = webtech.WebTech()

    try:
        results = wt.start_from_url(url, timeout=1)
        web_tech_result_text.config(state=tk.NORMAL)
        web_tech_result_text.delete(1.0, tk.END)
        web_tech_result_text.insert(tk.END, results)
        web_tech_result_text.config(state=tk.DISABLED)
    except Exception as e:
        messagebox.showerror("Error", f"Error analyzing web tech: {e}")

def directory_bruteforce(base_url, wordlist):
    try:
        with open(wordlist, 'r') as file:
            paths = [line.strip() for line in file.readlines()]

        result_directory.config(state=tk.NORMAL)
        result_directory.delete(1.0, tk.END)

        for path in paths:
            full_url = f"{base_url}/{path}"
            response = requests.get(full_url)

            if response.status_code == 200:
                result_directory.insert(tk.END, f"Found: {full_url}\n")

        result_directory.config(state=tk.DISABLED)

    except Exception as e:
        messagebox.showerror("Error", f"Error: {e}")

def whois_lookup(domain_name):
    try:
        domain_info = whois.whois(domain_name)
        whois_result_text.config(state=tk.NORMAL)
        whois_result_text.delete(1.0, tk.END)
        whois_result_text.insert(tk.END, f"Domain Name: {domain_info.domain_name}\n")
        whois_result_text.insert(tk.END, f"Registrar: {domain_info.registrar}\n")
        whois_result_text.insert(tk.END, f"Creation Date: {domain_info.creation_date}\n")
        whois_result_text.insert(tk.END, f"Expiration Date: {domain_info.expiration_date}\n")
        whois_result_text.insert(tk.END, f"Last Updated: {domain_info.updated_date}\n")
        whois_result_text.insert(tk.END, f"Name Servers: {domain_info.name_servers}\n")
        whois_result_text.config(state=tk.DISABLED)

    except whois.exceptions.FailedParsingWhoisOutput as e:
        messagebox.showerror("Error", f"Error: {e}")

def show_frame(frame):
    frame.pack(side=tk.TOP, pady=100)

def hide_frame(frame):
    frame.pack_forget()

def save_to_file(text_widget, file_extension=".txt"):
    file_path = filedialog.asksaveasfilename(defaultextension=file_extension, filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(text_widget.get(1.0, tk.END))

def exit_application():
    root.destroy()

root = tk.Tk()
root.title("Web Enumeration")

frame_source_code = tk.Frame(root)
label_source_code = tk.Label(frame_source_code, text="Enter the URL of the website:")
label_source_code.pack(pady=5)
entry_source_code = tk.Entry(frame_source_code, width=30)
entry_source_code.pack(pady=5)
extract_button = tk.Button(frame_source_code, text="Extract Source Code", command=lambda: get_source_code(entry_source_code.get()))
extract_button.pack(pady=5)
source_code_text = tk.Text(frame_source_code, wrap=tk.WORD, height=30, width=80, state=tk.DISABLED)
source_code_text.pack(pady=10)

clear_source_code_button = tk.Button(frame_source_code, text="Clear Result", command=lambda: clear_text_area(source_code_text))
clear_source_code_button.pack(pady=5)

frame_subdomains = tk.Frame(root)
label_domain = tk.Label(frame_subdomains, text="Enter the domain name:")
label_domain.pack(pady=5)
entry_domain = tk.Entry(frame_subdomains, width=30)
entry_domain.pack(pady=5)
label_wordlist = tk.Label(frame_subdomains, text="Select Wordlist File:")
label_wordlist.pack(pady=5)
wordlist_entry = tk.Entry(frame_subdomains, width=30)
wordlist_entry.pack(pady=5)
browse_button = tk.Button(frame_subdomains, text="Browse", command=lambda: browse_wordlist(wordlist_entry))
browse_button.pack(pady=5)
enumerate_button = tk.Button(frame_subdomains, text="Enumerate Subdomains", command=lambda: enumerate_subdomains(entry_domain.get(), wordlist_entry.get()))
enumerate_button.pack(pady=5)
result_text = tk.Text(frame_subdomains, wrap=tk.WORD, height=30, width=80, state=tk.DISABLED)
result_text.pack(pady=10)

clear_subdomains_button = tk.Button(frame_subdomains, text="Clear Result", command=lambda: clear_text_area(result_text))
clear_subdomains_button.pack(pady=5)

def clear_text_area(text_widget):
    text_widget.config(state=tk.NORMAL)
    text_widget.delete(1.0, tk.END)
    text_widget.config(state=tk.DISABLED)

frame_whois = tk.Frame(root)
label_whois_domain = tk.Label(frame_whois, text="Enter the domain name for WHOIS lookup:")
label_whois_domain.pack(pady=5)
entry_whois_domain = tk.Entry(frame_whois, width=30)
entry_whois_domain.pack(pady=5)
whois_lookup_button = tk.Button(frame_whois, text="WHOIS Lookup", command=lambda: whois_lookup(entry_whois_domain.get()))
whois_lookup_button.pack(pady=5)
whois_result_text = tk.Text(frame_whois, wrap=tk.WORD, height=30, width=80, state=tk.DISABLED)
whois_result_text.pack(pady=10)

clear_whois_button = tk.Button(frame_whois, text="Clear Result", command=lambda: clear_text_area(whois_result_text))
clear_whois_button.pack(pady=5)

frame_web_tech = tk.Frame(root)
label_web_tech = tk.Label(frame_web_tech, text="Enter the URL for Web Tech analysis:")
label_web_tech.pack(pady=5)
entry_web_tech = tk.Entry(frame_web_tech, width=30)
entry_web_tech.pack(pady=5)
analyze_web_tech_button = tk.Button(frame_web_tech, text="Analyze Web Tech", command=lambda: analyze_web_tech(entry_web_tech.get()))
analyze_web_tech_button.pack(pady=5)
web_tech_result_text = tk.Text(frame_web_tech, wrap=tk.WORD, height=30, width=80, state=tk.DISABLED)
web_tech_result_text.pack(pady=10)

clear_web_tech_button = tk.Button(frame_web_tech, text="Clear Result", command=lambda: clear_text_area(web_tech_result_text))
clear_web_tech_button.pack(pady=5)

frame_directory = tk.Frame(root)
label_base_url = tk.Label(frame_directory, text="Enter the base URL (e.g., http://example.com):")
label_base_url.pack(pady=5)
entry_base_url = tk.Entry(frame_directory, width=30)
entry_base_url.pack(pady=5)
label_wordlist_directory = tk.Label(frame_directory, text="Enter the path to the wordlist file:")
label_wordlist_directory.pack(pady=5)
wordlist_entry_directory = tk.Entry(frame_directory, width=30)
wordlist_entry_directory.pack(pady=5)
browse_button_directory = tk.Button(frame_directory, text="Browse", command=lambda: browse_wordlist(wordlist_entry_directory))
browse_button_directory.pack(pady=5)
directory_bruteforce_button = tk.Button(frame_directory, text="Directory Bruteforce", command=lambda: directory_bruteforce(entry_base_url.get(), wordlist_entry_directory.get()))
directory_bruteforce_button.pack(pady=5)
result_directory = tk.Text(frame_directory, wrap=tk.WORD, height=30, width=80, state=tk.DISABLED)
result_directory.pack(pady=5)

clear_directory_button = tk.Button(frame_directory, text="Clear Result", command=lambda: clear_text_area(result_directory))
clear_directory_button.pack(pady=5)

def show_hide_frames(frame_to_show):
    frames = [frame_subdomains, frame_whois, frame_web_tech, frame_directory, frame_source_code]
    for frame in frames:
        if frame == frame_to_show:
            show_frame(frame)
        else:
            hide_frame(frame)

    submenu_frame.lift()