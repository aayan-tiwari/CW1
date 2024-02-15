import tkinter as tk
from tkinter import filedialog, messagebox
import dns.resolver
import requests
import webtech
import subprocess

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
        result = subprocess.run(['whois', domain_name], capture_output=True, text=True)
        whois_result_text.config(state=tk.NORMAL)
        whois_result_text.delete(1.0, tk.END)
        whois_result_text.insert(tk.END, result.stdout)
        whois_result_text.config(state=tk.DISABLED)
    except FileNotFoundError:
        messagebox.showerror("Error", "'whois' command not found. Make sure it is installed and available in your system.")

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

submenu_buttons = [
    ("Source Code", lambda: show_hide_frames(frame_source_code)),
    ("Subdomains", lambda: show_hide_frames(frame_subdomains)),
    ("WHOIS", lambda: show_hide_frames(frame_whois)),
    ("Web Tech", lambda: show_hide_frames(frame_web_tech)),
    ("Directory", lambda: show_hide_frames(frame_directory)),
]

submenu_frame = tk.Frame(root)

for text, command in submenu_buttons:
    button = tk.Button(submenu_frame, text=text, command=command)
    button.pack(side=tk.LEFT, padx=5)
submenu_frame.pack(side=tk.TOP,pady=5)

show_frame(frame_source_code)

def show_help():
    help_text = """
Module Purpose:
This application provides tools for web enumeration, including extracting source code,
enumerating subdomains, performing WHOIS lookup, analyzing web technologies, and
directory brute-forcing.

Functionality:
1. Source Code Extraction: Extracts the source code of a given URL.
2. Subdomain Enumeration: Enumerates subdomains of a given domain using a provided wordlist.
3. WHOIS Lookup: Performs a WHOIS lookup for a given domain.
4. Web Tech Analysis: Analyzes the technologies used by a website.
5. Directory Bruteforce: Attempts to find directories on a website using a provided wordlist.

Usage:
1. Enter the URL/domain in the corresponding entry field.
2. Select options such as wordlist file for subdomain enumeration or directory brute-forcing.
3. Click on the corresponding action button to perform the desired operation.
4. Results will be displayed in the text area, and you can save them using the File menu.
5. Clear buttons are provided to clear the result areas.
"""
    messagebox.showinfo("Project Documentation", help_text)

file_menu = tk.Menu(root)
root.config(menu=file_menu)

save_menu = tk.Menu(file_menu, tearoff=0)
file_menu.add_cascade(label="File", menu=save_menu)
save_menu.add_command(label="Save Subdomains Result", command=lambda: save_to_file(result_text))
save_menu.add_command(label="Save WHOIS Result", command=lambda: save_to_file(whois_result_text))
save_menu.add_command(label="Save Web Tech Result", command=lambda: save_to_file(web_tech_result_text))
save_menu.add_command(label="Save Directory Result", command=lambda: save_to_file(result_directory))
save_menu.add_command(label="Save Source Code", command=lambda: save_to_file(source_code_text))
save_menu.add_separator()
save_menu.add_command(label="Exit", command=exit_application)  # Add an "Exit" option here
help_menu = tk.Menu(file_menu, tearoff=False)
file_menu.add_cascade(label="Help", menu=help_menu)
help_menu.add_command(label="Documentation", command=show_help)

root.mainloop()
