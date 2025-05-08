import os
import msvcrt
import win32file, win32con, win32api
import threading
import io
import tempfile
import subprocess
import hashlib
from datetime import datetime
import json

from tkinter import messagebox, filedialog
from PIL import Image, ImageTk, ExifTags
import customtkinter as ctk
import tkinter as tk

# Define file signatures and footers for each file type with metadata support
FILE_SIGNATURES = {
    "JPEG": {
        "headers": [b'\xff\xd8\xff\xe0', b'\xff\xd8\xff\xe1', b'\xff\xd8\xff\xe2'],
        "footer": b'\xff\xd9',
        "extension": ".jpg",
        "metadata_func": lambda data: extract_image_metadata(data)
    },
    "PDF": {
        "headers": [b'%PDF-'],
        "footer": b'%%EOF',
        "extension": ".pdf",
        "metadata_func": lambda data: extract_pdf_metadata(data)
    },
    "MKV": {
        "headers": [b'\x1A\x45\xDF\xA3'],
        "footer": None,
        "extension": ".mkv",
        "metadata_func": lambda data: extract_mkv_metadata(data)
    }
}

# Metadata extraction functions
def extract_image_metadata(data):
    try:
        image = Image.open(io.BytesIO(data))
        metadata = {
            "format": image.format,
            "size": image.size,
            "mode": image.mode,
        }
        
        # Try to extract EXIF data
        try:
            exif_data = image._getexif()
            if exif_data:
                exif = {
                    ExifTags.TAGS[k]: v
                    for k, v in exif_data.items()
                    if k in ExifTags.TAGS
                }
                metadata["exif"] = exif
        except Exception:
            pass
            
        return metadata
    except Exception as e:
        return {"error": str(e)}

def extract_pdf_metadata(data):
    try:
        # Simple PDF metadata extraction
        text = data.decode('ascii', errors='ignore')[:1000]
        metadata = {}
        
        # Look for common PDF metadata markers
        if 'Title' in text:
            metadata['title'] = text.split('Title')[1].split(')')[0].strip()
        if 'Author' in text:
            metadata['author'] = text.split('Author')[1].split(')')[0].strip()
            
        return metadata
    except Exception as e:
        return {"error": str(e)}

def extract_mkv_metadata(data):
    try:
        # For MKV, we'd normally use a library like ffmpeg, but for simplicity:
        return {
            "size": len(data),
            "type": "MKV (Matroska)",
            "note": "Use external tools for detailed metadata"
        }
    except Exception as e:
        return {"error": str(e)}

def calculate_hash(data):
    """Calculate SHA-256 hash of data"""
    return hashlib.sha256(data).hexdigest()

def get_available_drives():
    drives = []
    drive_bits = win32api.GetLogicalDrives()
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if drive_bits & 1:
            drives.append(f"{letter}:\\")
        drive_bits >>= 1
    return drives

def get_drive_total_size(drive_letter):
    try:
        _, totalBytes, _ = win32api.GetDiskFreeSpaceEx(drive_letter)
        return totalBytes
    except Exception as e:
        print(f"Error getting size for drive {drive_letter}: {e}")
        return None

def open_raw_drive(drive_path):
    try:
        handle = win32file.CreateFile(
            drive_path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            0,
            None
        )
    except Exception as e:
        raise Exception(f"Failed to open drive using CreateFile: {e}")

    try:
        fd = msvcrt.open_osfhandle(handle.Detach(), os.O_RDONLY)
        fileD = os.fdopen(fd, 'rb')
    except Exception as e:
        raise Exception(f"Failed to convert handle to file: {e}")

    return fileD

def scan_drive(raw_drive_path, total_size, selected_types, progress_callback):
    recovered_files = []
    try:
        fileD = open_raw_drive(raw_drive_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open drive: {e}")
        return []

    # Optimized scanning with larger block size (4 MB) and memoryview
    block_size = 4 * 1024 * 1024  # Increased from 2MB to 4MB for better performance
    max_header_size = max(len(h) for f in selected_types for h in FILE_SIGNATURES[f]["headers"])
    overlap = max_header_size - 1

    offset = 0
    previous_chunk = b""
    scan_start_time = datetime.now()

    while True:
        chunk = fileD.read(block_size)
        if not chunk:
            break

        if previous_chunk:
            chunk = previous_chunk + chunk
        mchunk = memoryview(chunk)

        for ftype in selected_types:
            sig = FILE_SIGNATURES.get(ftype)
            if not sig or not sig["headers"]:
                continue
            for header in sig["headers"]:
                # Use memoryview for faster searching
                pos = mchunk.tobytes().find(header)
                if pos != -1:
                    abs_offset = offset - len(previous_chunk) + pos
                    file_hash = calculate_hash(mchunk[pos:pos+1000].tobytes())  # Hash first 1000 bytes for quick ID
                    file_name = f"{ftype}_{abs_offset:x}_{file_hash[:8]}{sig['extension']}"
                    
                    # Collect file data
                    file_bytes = mchunk[pos:].tobytes()
                    if sig["footer"] is not None:
                        while True:
                            next_block = fileD.read(block_size)
                            if not next_block:
                                break
                            file_bytes += next_block
                            if next_block.find(sig["footer"]) != -1:
                                break
                    else:
                        file_bytes = file_bytes[:block_size * 20]  # Limit to 20 blocks for unknown footer files

                    # Calculate full file hash
                    full_hash = calculate_hash(file_bytes)
                    
                    # Extract metadata if available
                    metadata = {}
                    if "metadata_func" in sig:
                        try:
                            metadata = sig["metadata_func"](file_bytes)
                        except Exception as e:
                            metadata = {"metadata_error": str(e)}
                    
                    recovered_files.append({
                        "offset": abs_offset,
                        "data": file_bytes,
                        "name": file_name,
                        "type": ftype,
                        "hash": full_hash,
                        "metadata": metadata,
                        "size": len(file_bytes),
                        "discovery_time": datetime.now().isoformat()
                    })
                    break

        previous_chunk = chunk[-overlap:] if len(chunk) > overlap else chunk
        offset += (len(chunk) - len(previous_chunk))
        if progress_callback and total_size:
            progress_callback(offset)

    scan_end_time = datetime.now()
    scan_duration = (scan_end_time - scan_start_time).total_seconds()
    print(f"Scan completed in {scan_duration:.2f} seconds")
    
    fileD.close()
    return recovered_files

# Global variable to hold the current preview window
current_preview_window = None

def close_current_preview():
    global current_preview_window
    if current_preview_window is not None:
        try:
            current_preview_window.destroy()
        except Exception as e:
            print("Error closing preview window:", e)
        finally:
            current_preview_window = None

def show_metadata(metadata):
    global current_preview_window
    close_current_preview()
    
    current_preview_window = ctk.CTkToplevel()
    current_preview_window.title("File Metadata")
    
    text_widget = tk.Text(current_preview_window, wrap="word")
    text_widget.pack(expand=True, fill="both", padx=10, pady=10)
    
    if isinstance(metadata, dict):
        formatted_metadata = json.dumps(metadata, indent=2)
    else:
        formatted_metadata = str(metadata)
    
    text_widget.insert("1.0", formatted_metadata)
    current_preview_window.protocol("WM_DELETE_WINDOW", close_current_preview)

def preview_image(data, metadata=None):
    global current_preview_window
    close_current_preview()
    
    try:
        image = Image.open(io.BytesIO(data))
        current_preview_window = ctk.CTkToplevel()
        current_preview_window.title("Image Preview")
        current_preview_window.geometry("800x700")
        
        # Create a tabbed view for image and metadata
        tabview = ctk.CTkTabview(current_preview_window)
        tabview.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Image tab
        tab_image = tabview.add("Image")
        image.thumbnail((600, 600))
        tk_img = ImageTk.PhotoImage(image)
        lbl = ctk.CTkLabel(tab_image, image=tk_img, text="")
        lbl.image = tk_img  # keep a reference
        lbl.pack(padx=10, pady=10)
        
        # Metadata tab
        if metadata:
            tab_meta = tabview.add("Metadata")
            text_widget = tk.Text(tab_meta, wrap="word")
            text_widget.pack(expand=True, fill="both", padx=10, pady=10)
            formatted_metadata = json.dumps(metadata, indent=2)
            text_widget.insert("1.0", formatted_metadata)
        
        current_preview_window.protocol("WM_DELETE_WINDOW", close_current_preview)
    except Exception as e:
        messagebox.showerror("Preview Error", f"Cannot preview image: {e}")

def preview_text(data, metadata=None):
    global current_preview_window
    close_current_preview()
    
    try:
        text = data.decode('utf-8', errors='ignore')[:5000]
        current_preview_window = ctk.CTkToplevel()
        current_preview_window.title("Text Preview")
        current_preview_window.geometry("800x700")
        
        tabview = ctk.CTkTabview(current_preview_window)
        tabview.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Text tab
        tab_text = tabview.add("Text")
        text_widget = tk.Text(tab_text, wrap="word")
        text_widget.insert("1.0", text)
        text_widget.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Metadata tab
        if metadata:
            tab_meta = tabview.add("Metadata")
            meta_widget = tk.Text(tab_meta, wrap="word")
            meta_widget.pack(expand=True, fill="both", padx=10, pady=10)
            formatted_metadata = json.dumps(metadata, indent=2)
            meta_widget.insert("1.0", formatted_metadata)
        
        current_preview_window.protocol("WM_DELETE_WINDOW", close_current_preview)
    except Exception as e:
        messagebox.showerror("Preview Error", f"Cannot preview text: {e}")

def preview_mkv(data, metadata=None):
    global current_preview_window
    close_current_preview()
    
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mkv") as tmp_file:
            tmp_file.write(data)
            tmp_path = tmp_file.name
        
        os.startfile(tmp_path)
        
        current_preview_window = ctk.CTkToplevel()
        current_preview_window.title("MKV Preview Launched")
        
        tabview = ctk.CTkTabview(current_preview_window)
        tabview.pack(expand=True, fill="both", padx=10, pady=10)
        
        tab_info = tabview.add("Info")
        lbl = ctk.CTkLabel(tab_info, text="MKV file launched in external player.")
        lbl.pack(padx=10, pady=10)
        
        if metadata:
            tab_meta = tabview.add("Metadata")
            text_widget = tk.Text(tab_meta, wrap="word")
            text_widget.pack(expand=True, fill="both", padx=10, pady=10)
            formatted_metadata = json.dumps(metadata, indent=2)
            text_widget.insert("1.0", formatted_metadata)
        
        current_preview_window.protocol("WM_DELETE_WINDOW", close_current_preview)
    except Exception as e:
        messagebox.showerror("Preview Error", f"Cannot preview MKV: {e}")

# ----------------------------
# CustomTkinter GUI Setup
# ----------------------------
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.title("Enhanced File Recovery Tool")
root.geometry("1000x800")

# Global variables
recovered_files = []
output_dir = ""

# Create a main frame to hold UI components
main_frame = ctk.CTkFrame(root)
main_frame.pack(padx=20, pady=20, fill="both", expand=True)

# -- Drive Selection --
drive_frame = ctk.CTkFrame(main_frame)
drive_frame.pack(pady=10, fill="x")

ctk.CTkLabel(drive_frame, text="Select Drive:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
drive_list = get_available_drives()
drive_var = ctk.StringVar(value=drive_list[0] if drive_list else "No drives found")
drive_combobox = ctk.CTkComboBox(drive_frame, values=drive_list, variable=drive_var)
drive_combobox.grid(row=0, column=1, padx=5, pady=5)

# -- File Types Selection --
types_frame = ctk.CTkFrame(main_frame)
types_frame.pack(pady=10, fill="x")

ctk.CTkLabel(types_frame, text="Select File Types:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
selected_types_vars = {}
col = 1
for ftype in FILE_SIGNATURES.keys():
    var = tk.IntVar(value=1)
    chk = ctk.CTkCheckBox(types_frame, text=ftype, variable=var)
    chk.grid(row=0, column=col, padx=5, pady=5, sticky="w")
    selected_types_vars[ftype] = var
    col += 1

# -- Output Folder Selection --
output_frame = ctk.CTkFrame(main_frame)
output_frame.pack(pady=10, fill="x")

def select_output_directory():
    global output_dir
    selected_dir = filedialog.askdirectory(title="Select Output Directory")
    if selected_dir:
        output_dir = selected_dir
        output_label.configure(text=f"Output Directory: {output_dir}")

output_btn = ctk.CTkButton(output_frame, text="Select Output Folder", command=select_output_directory)
output_btn.grid(row=0, column=0, padx=5, pady=5)
output_label = ctk.CTkLabel(output_frame, text="Output Directory: Not selected")
output_label.grid(row=0, column=1, padx=5, pady=5)

# -- Scan Button & Progress Bar --
scan_frame = ctk.CTkFrame(main_frame)
scan_frame.pack(pady=10, fill="x")

def start_scan():
    scan_button.configure(state="disabled")
    listbox.delete(0, tk.END)
    recovered_files.clear()
    selected_drive = drive_var.get()
    raw_drive_path = r"\\.\{}:".format(selected_drive[0])
    total_size = get_drive_total_size(selected_drive)
    selected_types = [ftype for ftype, var in selected_types_vars.items() if var.get() == 1]
    if not selected_types:
        messagebox.showwarning("No File Types", "Select at least one file type.")
        scan_button.configure(state="normal")
        return

    def progress_callback(offset):
        progress_bar.set(offset / total_size if total_size else 0)
        progress_label.configure(text=f"Progress: {offset / (1024*1024):.2f} MB / {total_size / (1024*1024):.2f} MB" if total_size else "")

    def scan_thread():
        global recovered_files
        recovered_files = scan_drive(raw_drive_path, total_size, selected_types, progress_callback)
        for rec in recovered_files:
            listbox.insert(tk.END, f"{rec['name']} ({rec['size']/1024:.1f} KB) - {rec['hash'][:8]}...")
        scan_button.configure(state="normal")
        progress_label.configure(text=f"Scan complete. Found {len(recovered_files)} files.")

    threading.Thread(target=scan_thread, daemon=True).start()

scan_button = ctk.CTkButton(scan_frame, text="Scan Drive", command=start_scan)
scan_button.grid(row=0, column=0, padx=5, pady=5)
progress_bar = ctk.CTkProgressBar(scan_frame)
progress_bar.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
progress_label = ctk.CTkLabel(scan_frame, text="")
progress_label.grid(row=1, column=0, columnspan=2, sticky="w")
scan_frame.columnconfigure(1, weight=1)

# -- Listbox for Recovered Files --
listbox_frame = ctk.CTkFrame(main_frame)
listbox_frame.pack(pady=10, fill="both", expand=True)
listbox = tk.Listbox(listbox_frame, selectmode=tk.MULTIPLE, font=("Segoe UI", 11))
listbox.pack(padx=10, pady=10, fill="both", expand=True)

def on_item_double_click(event):
    index = listbox.curselection()
    if index:
        rec = recovered_files[index[0]]
        if rec["type"] == "JPEG":
            preview_image(rec["data"], rec.get("metadata"))
        elif rec["type"] == "MKV":
            preview_mkv(rec["data"], rec.get("metadata"))
        else:
            preview_text(rec["data"], rec.get("metadata"))

listbox.bind("<Double-1>", on_item_double_click)

# -- Right-click context menu for metadata --
context_menu = tk.Menu(root, tearoff=0)
context_menu.add_command(label="Show Metadata", command=lambda: show_selected_metadata())

def show_context_menu(event):
    try:
        context_menu.tk_popup(event.x_root, event.y_root)
    finally:
        context_menu.grab_release()

def show_selected_metadata():
    index = listbox.curselection()
    if index:
        rec = recovered_files[index[0]]
        show_metadata(rec.get("metadata", "No metadata available"))

listbox.bind("<Button-3>", show_context_menu)

# -- Recover Files Button --
button_frame = ctk.CTkFrame(main_frame)
button_frame.pack(pady=10, fill="x")

def recover_selected_files():
    if not output_dir:
        messagebox.showwarning("No Output Folder", "Please select an output folder.")
        return
    selected_indices = listbox.curselection()
    if not selected_indices:
        messagebox.showinfo("No Selection", "Select at least one file to recover.")
        return
    
    success_count = 0
    for idx in selected_indices:
        rec = recovered_files[idx]
        try:
            output_path = os.path.join(output_dir, rec["name"])
            with open(output_path, "wb") as f:
                f.write(rec["data"])
            
            # Save metadata as JSON if available
            if rec.get("metadata"):
                meta_path = output_path + ".meta.json"
                with open(meta_path, "w") as f:
                    json.dump(rec["metadata"], f, indent=2)
            
            success_count += 1
        except Exception as e:
            messagebox.showerror("Write Error", f"Failed to save {rec['name']}: {str(e)}")
    
    messagebox.showinfo("Done", f"Successfully recovered {success_count}/{len(selected_indices)} files.")

recover_button = ctk.CTkButton(button_frame, text="Recover Selected Files", command=recover_selected_files)
recover_button.pack(side="left", padx=5)

def save_scan_report():
    if not recovered_files:
        messagebox.showwarning("No Data", "No scan data to save.")
        return
    
    file_path = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        title="Save Scan Report"
    )
    
    if file_path:
        try:
            report = {
                "scan_date": datetime.now().isoformat(),
                "drive": drive_var.get(),
                "file_types": [ftype for ftype, var in selected_types_vars.items() if var.get() == 1],
                "files": [
                    {
                        "name": f["name"],
                        "type": f["type"],
                        "size": f["size"],
                        "hash": f["hash"],
                        "offset": f["offset"],
                        "discovery_time": f["discovery_time"]
                    } for f in recovered_files
                ]
            }
            
            with open(file_path, "w") as f:
                json.dump(report, f, indent=2)
            
            messagebox.showinfo("Success", "Scan report saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {str(e)}")

report_button = ctk.CTkButton(button_frame, text="Save Scan Report", command=save_scan_report)
report_button.pack(side="left", padx=5)

root.mainloop()
