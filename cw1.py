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