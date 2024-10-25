import requests
import csv
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading

# URL for the VirusTotal API
url = 'https://www.virustotal.com/api/v3/files/'

# Function to check a hash
def check_hash(api_key, hash_value):
    headers = {
        'x-apikey': api_key
    }
    response = requests.get(url + hash_value, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Function to process hashes and write results to CSV
def process_hashes():
    api_key = api_key_entry.get()
    input_file = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    
    if not input_file:
        return
    
    output_file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    
    if not output_file:
        return
    
    with open(input_file, 'r') as csvfile:
        reader = csv.reader(csvfile)
        hashes = [row[0] for row in reader]
    
    progress['maximum'] = len(hashes)
    progress['value'] = 0
    status_label.config(text="Processing...")

    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['hash', 'engine_name', 'method', 'engine_version', 'engine_update', 'category', 'result']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        results_text.delete(1.0, tk.END)  # Clear the text field

        for hash_value in hashes:
            result = check_hash(api_key, hash_value)
            if result:
                last_analysis_results = result['data']['attributes']['last_analysis_results']
                for engine, details in last_analysis_results.items():
                    writer.writerow({
                        'hash': hash_value,
                        'engine_name': details.get('engine_name', 'N/A'),
                        'method': details.get('method', 'N/A'),
                        'engine_version': details.get('engine_version', 'N/A'),
                        'engine_update': details.get('engine_update', 'N/A'),
                        'category': details.get('category', 'N/A'),
                        'result': details.get('result', 'N/A')
                    })
                    results_text.insert(tk.END, f"{hash_value}, {details.get('engine_name', 'N/A')}, {details.get('method', 'N/A')}, {details.get('engine_version', 'N/A')}, {details.get('engine_update', 'N/A')}, {details.get('category', 'N/A')}, {details.get('result', 'N/A')}\n")
                print(f"Results for {hash_value} written to CSV.")
            else:
                print(f"Failed to retrieve results for {hash_value}")
            progress['value'] += 1
            progress_label.config(text=f"{int((progress['value'] / progress['maximum']) * 100)}%")
            root.update_idletasks()
            time.sleep(30)
    
    status_label.config(text="Completed")
    messagebox.showinfo("Completed", "Hash processing completed and results saved to CSV.")

# Function to start the processing in a separate thread
def start_processing():
    threading.Thread(target=process_hashes).start()

# Create the main window
root = tk.Tk()
root.title("VirusTotal Hash Checker")
root.configure(bg='white')

# Create and place the widgets
tk.Label(root, text="Enter VirusTotal API Key:", bg='white').pack(pady=10)
api_key_entry = tk.Entry(root, width=50, show='*')
api_key_entry.pack(pady=5)

tk.Button(root, text="Process Hashes", command=start_processing).pack(pady=20)

style = ttk.Style()
style.configure("red.Horizontal.TProgressbar", troughcolor='white', background='red')
progress = ttk.Progressbar(root, orient='horizontal', length=300, mode='determinate', style="red.Horizontal.TProgressbar")
progress.pack(pady=10)

progress_label = tk.Label(root, text="0%", bg='white')
progress_label.pack(pady=5)

status_label = tk.Label(root, text="", bg='white')
status_label.pack(pady=5)

# Create a text field for results with a scrollbar
results_frame = tk.Frame(root, bg='white')
results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
scrollbar = tk.Scrollbar(results_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
results_text = tk.Text(results_frame, wrap=tk.NONE, yscrollcommand=scrollbar.set)
results_text.pack(fill=tk.BOTH, expand=True)
scrollbar.config(command=results_text.yview)

# Allow the results text field to resize with the window
results_frame.pack_propagate(False)

# Run the application
root.mainloop()
