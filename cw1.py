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
