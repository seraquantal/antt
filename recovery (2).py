import os
import sys
import ctypes
import msvcrt
import win32file, win32con, win32api
import threading
import io
import tempfile
import subprocess
import hashlib
from datetime import datetime
import json
import exifread
import PyPDF2
import concurrent.futures
from collections import deque
import math

from tkinter import messagebox, filedialog
from PIL import Image, ImageTk

import customtkinter as ctk
import tkinter as tk

# === Constants ===
FILE_SIGNATURES = {
    "JPEG": {
        "headers": [b'\xff\xd8\xff\xe0', b'\xff\xd8\xff\xe1', b'\xff\xd8\xff\xe2'],
        "footer": b'\xff\xd9',
        "extension": ".jpg",
        "metadata_extractor": "extract_image_metadata"
    },
    "PDF": {
        "headers": [b'%PDF-'],
        "footer": b'%%EOF',
        "extension": ".pdf",
        "metadata_extractor": "extract_pdf_metadata"
    },
    "MKV": {
        "headers": [b'\x1A\x45\xDF\xA3'],
        "footer": None,
        "extension": ".mkv",
        "metadata_extractor": "extract_video_metadata"
    }
}

DEFAULT_CONFIG = {
    'max_workers': 4,
    'min_chunk_size': 64 * 1024 * 1024,
    'read_block_size': 8 * 1024 * 1024,
    'max_file_size': 100 * 1024 * 1024  # Added to prevent memory issues with large files
}

# === Utility Functions ===
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def check_admin_privileges():
    if not is_admin():
        messagebox.showerror(
            "Insufficient Privileges",
            "This tool must be run as Administrator.\n"
            "Please restart the application with elevated (Admin) privileges."
        )
        sys.exit(1)

def get_available_drives():
    drives = []
    try:
        drive_bits = win32api.GetLogicalDrives()
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if drive_bits & 1:
                drives.append(f"{letter}:\\")
            drive_bits >>= 1
    except Exception as e:
        messagebox.showerror("Drive Error", f"Failed to get available drives: {e}")
    return drives

def get_drive_total_size(drive_letter):
    try:
        _, total_bytes, _ = win32api.GetDiskFreeSpaceEx(drive_letter)
        return total_bytes
    except Exception as e:
        messagebox.showerror("Size Error", f"Error getting size for drive {drive_letter}: {e}")
        return None

def open_raw_drive(drive_path):
    try:
        handle = win32file.CreateFile(
            drive_path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_RANDOM_ACCESS,
            None
        )
        fd = msvcrt.open_osfhandle(handle.Detach(), os.O_RDONLY)
        return os.fdopen(fd, 'rb')
    except Exception as e:
        raise IOError(f"Failed to open drive {drive_path}: {e}")

# === Metadata Extraction Functions ===
def extract_image_metadata(data):
    metadata = {}
    try:
        with io.BytesIO(data) as f:
            tags = exifread.process_file(f)
            metadata["exif"] = {str(tag): str(value) for tag, value in tags.items()}
    except Exception as e:
        metadata["exif_error"] = str(e)
    return metadata

def extract_pdf_metadata(data):
    metadata = {}
    try:
        with io.BytesIO(data) as f:
            reader = PyPDF2.PdfReader(f)
            if reader.metadata:
                metadata["pdf_info"] = dict(reader.metadata)
            metadata["pages"] = len(reader.pages)
    except Exception as e:
        metadata["pdf_error"] = str(e)
    return metadata

def extract_video_metadata(data):
    metadata = {"video_info": "MKV metadata extraction not implemented"}
    return metadata

def generate_file_metadata(file_type, data):
    metadata = {
        "recovery_time": datetime.now().isoformat(),
        "size_bytes": len(data),
        "sha256_hash": hashlib.sha256(data).hexdigest(),
        "file_type": file_type
    }
    extractor = FILE_SIGNATURES.get(file_type, {}).get("metadata_extractor")
    if extractor:
        extractor_func = globals().get(extractor)
        if extractor_func:
            try:
                metadata.update(extractor_func(data))
            except Exception as e:
                metadata[f"{file_type}_extraction_error"] = str(e)
    return metadata

# === Scanning Functions ===
def scan_drive(raw_drive_path, total_size, selected_types, progress_callback):
    recovered_files = []
    try:
        with open_raw_drive(raw_drive_path) as fileD:
            block_size = DEFAULT_CONFIG['read_block_size']
            max_header_size = max(len(h) for f in selected_types for h in FILE_SIGNATURES[f]["headers"])
            overlap = max_header_size - 1
            offset = 0
            previous_chunk = b""

            header_map = {}
            for ftype in selected_types:
                for header in FILE_SIGNATURES[ftype]["headers"]:
                    header_map[header] = ftype

            while True:
                chunk = fileD.read(block_size)
                if not chunk:
                    break
                if previous_chunk:
                    chunk = previous_chunk + chunk
                mchunk = memoryview(chunk)
                
                for header, ftype in header_map.items():
                    pos = 0
                    while True:
                        idx = mchunk[pos:].tobytes().find(header)
                        if idx == -1:
                            break
                        abs_offset = offset - len(previous_chunk) + pos + idx
                        file_name = f"{ftype}_{abs_offset:x}_unknown{FILE_SIGNATURES[ftype]['extension']}"
                        file_bytes = mchunk[pos+idx:].tobytes()
                        
                        sig = FILE_SIGNATURES[ftype]
                        if sig["footer"] is not None:
                            while len(file_bytes) < DEFAULT_CONFIG['max_file_size']:
                                nb = fileD.read(block_size)
                                if not nb:
                                    break
                                file_bytes += nb
                                footer_pos = file_bytes.find(sig["footer"])
                                if footer_pos != -1:
                                    file_bytes = file_bytes[:footer_pos + len(sig["footer"])]
                                    break
                        else:
                            file_bytes = file_bytes[:block_size * 20]  # Limit size for footerless files
                            
                        metadata = generate_file_metadata(ftype, file_bytes)
                        recovered_files.append({
                            "offset": abs_offset,
                            "data": file_bytes,
                            "name": file_name,
                            "type": ftype,
                            "metadata": metadata
                        })
                        pos += idx + len(header)

                previous_chunk = chunk[-overlap:] if len(chunk) > overlap else chunk
                offset += len(chunk) - len(previous_chunk)
                if progress_callback and total_size:
                    progress_callback(offset)

    except Exception as e:
        messagebox.showerror("Scan Error", f"Drive scan failed: {e}")
        return []

    return recovered_files

def parallel_scan_drive(raw_drive_path, total_size, selected_types, progress_callback):
    recovered_files = []
    progress_lock = threading.Lock()
    results_lock = threading.Lock()
    progress = 0

    try:
        with open_raw_drive(raw_drive_path) as fileD:
            fileD.seek(0, os.SEEK_END)
            drive_size = fileD.tell()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open drive: {e}")
        return []

    num_chunks = min(DEFAULT_CONFIG['max_workers'],
                     math.ceil(drive_size / DEFAULT_CONFIG['min_chunk_size']))
    chunk_size = max(DEFAULT_CONFIG['min_chunk_size'], drive_size // num_chunks)
    chunks = [(i * chunk_size, (i + 1) * chunk_size) for i in range(num_chunks)]
    chunks[-1] = (chunks[-1][0], drive_size)

    def scan_chunk(start, end):
        nonlocal progress
        files = []
        try:
            with open_raw_drive(raw_drive_path) as fileD:
                fileD.seek(start)
                remaining = end - start
                max_header = max(len(h) for f in selected_types for h in FILE_SIGNATURES[f]["headers"])
                overlap = max_header - 1
                prev = b""
                
                while remaining > 0:
                    read_size = min(DEFAULT_CONFIG['read_block_size'], remaining)
                    chunk = fileD.read(read_size)
                    if not chunk:
                        break
                    if prev:
                        chunk = prev + chunk
                    mchunk = memoryview(chunk)
                    
                    for ftype in selected_types:
                        sig = FILE_SIGNATURES[ftype]
                        for header in sig["headers"]:
                            idx = mchunk.tobytes().find(header)
                            if idx != -1:
                                abs_offset = start + fileD.tell() - len(chunk) + idx
                                name = f"{ftype}_{abs_offset:x}_parallel{sig['extension']}"
                                data = mchunk[idx:].tobytes()
                                
                                if sig["footer"] is not None:
                                    while len(data) < DEFAULT_CONFIG['max_file_size']:
                                        nb = fileD.read(DEFAULT_CONFIG['read_block_size'])
                                        if not nb:
                                            break
                                        data += nb
                                        footer_pos = data.find(sig["footer"])
                                        if footer_pos != -1:
                                            data = data[:footer_pos + len(sig["footer"])]
                                            break
                                else:
                                    data = data[:DEFAULT_CONFIG['read_block_size'] * 20]
                                    
                                meta = generate_file_metadata(ftype, data)
                                files.append({
                                    "offset": abs_offset, 
                                    "data": data,
                                    "name": name, 
                                    "type": ftype, 
                                    "metadata": meta
                                })
                    
                    prev = chunk[-overlap:] if len(chunk) > overlap else chunk
                    remaining -= len(chunk) - len(prev)
                    with progress_lock:
                        progress += len(chunk) - len(prev)
                        if progress_callback and total_size:
                            progress_callback(progress)
        except Exception as e:
            print(f"Chunk error {start}-{end}: {e}")
        
        with results_lock:
            recovered_files.extend(files)

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=DEFAULT_CONFIG['max_workers']) as executor:
        futures = [executor.submit(scan_chunk, start, end) for start, end in chunks]
        concurrent.futures.wait(futures)

    return recovered_files

# === Preview Functions ===
class PreviewManager:
    def __init__(self):
        self.current_window = None
        self.temp_files = []
        
    def close_current(self):
        if self.current_window:
            try:
                self.current_window.destroy()
            except:
                pass
            self.current_window = None
        self.clean_temp_files()
            
    def clean_temp_files(self):
        for f in self.temp_files:
            try:
                if os.path.exists(f):
                    os.unlink(f)
            except:
                pass
        self.temp_files = []
        
    def preview_image(self, data):
        self.close_current()
        try:
            image = Image.open(io.BytesIO(data))
            self.current_window = ctk.CTkToplevel()
            self.current_window.title("Image Preview")
            self.current_window.geometry("600x600")
            
            # Calculate size to fit window while maintaining aspect ratio
            width, height = image.size
            ratio = min(600/width, 600/height)
            new_size = (int(width * ratio), int(height * ratio))
            
            image = image.resize(new_size, Image.Resampling.LANCZOS)
            tk_img = ImageTk.PhotoImage(image)
            
            lbl = ctk.CTkLabel(self.current_window, image=tk_img, text="")
            lbl.image = tk_img
            lbl.pack(padx=10, pady=10)
            
            self.current_window.protocol("WM_DELETE_WINDOW", self.close_current)
        except Exception as e:
            messagebox.showerror("Preview Error", f"Cannot preview image: {e}")
    
    def preview_text(self, data):
        self.close_current()
        try:
            text = data.decode('utf-8', errors='ignore')[:5000]
            self.current_window = ctk.CTkToplevel()
            self.current_window.title("Text Preview")
            
            frame = ctk.CTkFrame(self.current_window)
            frame.pack(fill="both", expand=True, padx=5, pady=5)
            
            text_widget = tk.Text(frame, wrap="word", font=("Consolas", 10))
            scrollbar = ctk.CTkScrollbar(frame, command=text_widget.yview)
            text_widget.configure(yscrollcommand=scrollbar.set)
            
            scrollbar.pack(side="right", fill="y")
            text_widget.pack(side="left", fill="both", expand=True)
            
            text_widget.insert("1.0", text)
            text_widget.configure(state="disabled")
            
            self.current_window.protocol("WM_DELETE_WINDOW", self.close_current)
        except Exception as e:
            messagebox.showerror("Preview Error", f"Cannot preview text: {e}")
    
    def preview_mkv(self, data):
        self.close_current()
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".mkv") as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            self.temp_files.append(tmp_path)
            
            # Try to open with default player
            try:
                os.startfile(tmp_path)
            except:
                messagebox.showinfo("Info", "No default MKV player associated")
                
            self.current_window = ctk.CTkToplevel()
            self.current_window.title("MKV Preview")
            self.current_window.geometry("400x100")
            
            lbl = ctk.CTkLabel(
                self.current_window, 
                text="MKV file should open in external player.\n"
                     "Temporary file will be deleted when preview is closed."
            )
            lbl.pack(padx=10, pady=10)
            
            btn = ctk.CTkButton(
                self.current_window, 
                text="Close Preview", 
                command=self.close_current
            )
            btn.pack(pady=5)
            
            self.current_window.protocol("WM_DELETE_WINDOW", self.close_current)
        except Exception as e:
            messagebox.showerror("Preview Error", f"Cannot preview MKV: {e}")

# === GUI Application ===
class FileRecoveryApp:
    def __init__(self, root):
        self.root = root
        self.recovered_files = []
        self.output_dir = ""
        self.preview_manager = PreviewManager()
        
        self.setup_ui()
        check_admin_privileges()
        
    def setup_ui(self):
        self.root.title("Advanced File Recovery Tool with Parallel Scanning")
        self.root.geometry("1000x800")
        
        # Configure grid weights
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Main container
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        
        # Notebook (Tabs)
        self.notebook = ctk.CTkTabview(self.main_frame)
        self.notebook.grid(row=0, column=0, sticky="nsew")
        
        # Scan Tab
        self.scan_tab = self.notebook.add("Scan Drive")
        self.setup_scan_tab()
        
        # Metadata Tab
        self.metadata_tab = self.notebook.add("File Metadata")
        self.setup_metadata_tab()
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_scan_tab(self):
        # Drive selection
        drive_frame = ctk.CTkFrame(self.scan_tab)
        drive_frame.pack(pady=10, fill="x")
        
        ctk.CTkLabel(drive_frame, text="Select Drive:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.drive_list = get_available_drives()
        self.drive_var = ctk.StringVar(value=self.drive_list[0] if self.drive_list else "")
        self.drive_combobox = ctk.CTkComboBox(drive_frame, values=self.drive_list, variable=self.drive_var)
        self.drive_combobox.grid(row=0, column=1, padx=5, pady=5)
        
        # Refresh drives button
        refresh_btn = ctk.CTkButton(
            drive_frame, 
            text="Refresh Drives", 
            command=self.refresh_drives,
            width=100
        )
        refresh_btn.grid(row=0, column=2, padx=5)
        
        # File types selection
        types_frame = ctk.CTkFrame(self.scan_tab)
        types_frame.pack(pady=10, fill="x")
        
        ctk.CTkLabel(types_frame, text="Select File Types:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.selected_types_vars = {}
        
        for col, ftype in enumerate(FILE_SIGNATURES.keys(), start=1):
            self.selected_types_vars[ftype] = tk.IntVar(value=1)
            chk = ctk.CTkCheckBox(types_frame, text=ftype, variable=self.selected_types_vars[ftype])
            chk.grid(row=0, column=col, padx=5, pady=5, sticky="w")
        
        # Scan options
        scan_options_frame = ctk.CTkFrame(self.scan_tab)
        scan_options_frame.pack(pady=5, fill="x")
        
        self.parallel_scan_var = tk.IntVar(value=1)
        parallel_check = ctk.CTkCheckBox(
            scan_options_frame, 
            text="Enable Parallel Deep Scan", 
            variable=self.parallel_scan_var
        )
        parallel_check.grid(row=0, column=0, padx=5, sticky="w")
        
        workers_label = ctk.CTkLabel(scan_options_frame, text="Threads:")
        workers_label.grid(row=0, column=1, padx=5, sticky="e")
        
        self.workers_var = tk.StringVar(value=str(DEFAULT_CONFIG['max_workers']))
        self.workers_spin = ctk.CTkEntry(scan_options_frame, textvariable=self.workers_var, width=50)
        self.workers_spin.grid(row=0, column=2, padx=5, sticky="w")
        
        self.workers_var.trace("w", self.update_workers)
        
        # Output directory
        output_frame = ctk.CTkFrame(self.scan_tab)
        output_frame.pack(pady=10, fill="x")
        
        output_btn = ctk.CTkButton(
            output_frame, 
            text="Select Output Folder", 
            command=self.select_output_directory
        )
        output_btn.grid(row=0, column=0, padx=5, pady=5)
        
        self.output_label = ctk.CTkLabel(output_frame, text="Output Directory: Not selected")
        self.output_label.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        # Scan controls
        scan_frame = ctk.CTkFrame(self.scan_tab)
        scan_frame.pack(pady=10, fill="x")
        
        self.scan_button = ctk.CTkButton(
            scan_frame, 
            text="Scan Drive", 
            command=self.start_scan
        )
        self.scan_button.grid(row=0, column=0, padx=5, pady=5)
        
        self.progress_bar = ctk.CTkProgressBar(scan_frame)
        self.progress_bar.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.progress_bar.set(0)
        
        scan_frame.columnconfigure(1, weight=1)
        
        # Results list
        results_frame = ctk.CTkFrame(self.scan_tab)
        results_frame.pack(pady=10, fill="both", expand=True)
        
        self.listbox = tk.Listbox(
            results_frame, 
            selectmode=tk.MULTIPLE, 
            font=("Segoe UI", 11)
        )
        self.listbox.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        scrollbar = ctk.CTkScrollbar(results_frame, command=self.listbox.yview)
        scrollbar.pack(side="right", fill="y")
        
        self.listbox.configure(yscrollcommand=scrollbar.set)
        self.listbox.bind("<Double-1>", self.on_item_double_click)
        self.listbox.bind("<<ListboxSelect>>", self.update_metadata_display)
        
        # File actions
        controls_frame = ctk.CTkFrame(self.scan_tab)
        controls_frame.pack(pady=10, fill="x")
        
        btn_frame = ctk.CTkFrame(controls_frame)
        btn_frame.pack(pady=5)
        
        preview_btn = ctk.CTkButton(
            btn_frame, 
            text="Preview Selected", 
            command=self.preview_selected
        )
        preview_btn.grid(row=0, column=0, padx=5)
        
        info_btn = ctk.CTkButton(
            btn_frame, 
            text="File Info", 
            command=self.show_file_info
        )
        info_btn.grid(row=0, column=1, padx=5)
        
        recover_btn = ctk.CTkButton(
            btn_frame, 
            text="Recover Selected", 
            command=self.recover_selected_files
        )
        recover_btn.grid(row=0, column=2, padx=5)
    
    def setup_metadata_tab(self):
        metadata_frame = ctk.CTkFrame(self.metadata_tab)
        metadata_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.metadata_text = tk.Text(
            metadata_frame, 
            wrap="word", 
            font=("Consolas", 10)
        )
        self.metadata_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        scrollbar = ctk.CTkScrollbar(metadata_frame, command=self.metadata_text.yview)
        scrollbar.pack(side="right", fill="y")
        
        self.metadata_text.configure(yscrollcommand=scrollbar.set)
    
    def refresh_drives(self):
        self.drive_list = get_available_drives()
        self.drive_combobox.configure(values=self.drive_list)
        if self.drive_list:
            self.drive_var.set(self.drive_list[0])
        else:
            self.drive_var.set("")
    
    def update_workers(self, *args):
        try:
            workers = max(1, min(16, int(self.workers_var.get())))
            DEFAULT_CONFIG['max_workers'] = workers
            self.workers_var.set(str(workers))
        except ValueError:
            self.workers_var.set(str(DEFAULT_CONFIG['max_workers']))
    
    def select_output_directory(self):
        directory = filedialog.askdirectory(title="Select Output Directory")
        if directory:
            self.output_dir = directory
            self.output_label.configure(text=f"Output Directory: {self.output_dir}")
    
    def start_scan(self):
        self.scan_button.configure(state="disabled")
        self.listbox.delete(0, tk.END)
        self.recovered_files.clear()
        self.progress_bar.set(0)
        
        drive_path = self.drive_var.get()
        if not drive_path:
            messagebox.showwarning("No Drive", "Please select a drive.")
            self.scan_button.configure(state="normal")
            return
        
        drive_letter = drive_path[0]
        raw_drive_path = rf"\\.\{drive_letter}:"
        total_size = get_drive_total_size(drive_path)
        
        selected_types = [ft for ft, var in self.selected_types_vars.items() if var.get()]
        if not selected_types:
            messagebox.showwarning("No File Types", "Select at least one file type.")
            self.scan_button.configure(state="normal")
            return
        
        def progress_callback(offset):
            if total_size:
                self.progress_bar.set(offset / total_size)
        
        def scan_worker():
            try:
                if self.parallel_scan_var.get():
                    self.recovered_files = parallel_scan_drive(
                        raw_drive_path, total_size, selected_types, progress_callback
                    )
                else:
                    self.recovered_files = scan_drive(
                        raw_drive_path, total_size, selected_types, progress_callback
                    )
                
                # Update UI with results
                self.root.after(0, self.update_results_list)
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
            finally:
                self.root.after(0, lambda: self.scan_button.configure(state="normal"))
        
        threading.Thread(target=scan_worker, daemon=True).start()
    
    def update_results_list(self):
        self.listbox.delete(0, tk.END)
        for rec in self.recovered_files:
            self.listbox.insert(tk.END, f"{rec['name']} at offset {hex(rec['offset'])}")
    
    def update_metadata_display(self, event=None):
        sel = self.listbox.curselection()
        if not sel:
            return
        
        rec = self.recovered_files[sel[0]]
        self.metadata_text.delete("1.0", tk.END)
        self.metadata_text.insert(tk.END, json.dumps(rec["metadata"], indent=2))
        self.metadata_text.configure(state="disabled")
    
    def on_item_double_click(self, event):
        self.preview_selected()
    
    def preview_selected(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        
        rec = self.recovered_files[sel[0]]
        if rec["type"] == "JPEG":
            self.preview_manager.preview_image(rec["data"])
        elif rec["type"] == "MKV":
            self.preview_manager.preview_mkv(rec["data"])
        else:
            self.preview_manager.preview_text(rec["data"])
    
    def show_file_info(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        
        rec = self.recovered_files[sel[0]]
        info = (
            f"File: {rec['name']}\n"
            f"Type: {rec['type']}\n"
            f"Size: {rec['metadata']['size_bytes']:,} bytes\n"
            f"SHA-256: {rec['metadata']['sha256_hash']}\n"
            f"Recovered at: {rec['metadata']['recovery_time']}\n"
        )
        messagebox.showinfo("File Information", info)
    
    def recover_selected_files(self):
        if not self.output_dir:
            messagebox.showwarning("No Output Folder", "Please select an output folder.")
            return
        
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("No Selection", "Select at least one file to recover.")
            return
        
        success = 0
        for i in sel:
            rec = self.recovered_files[i]
            try:
                # Ensure filename is unique
                base_name = os.path.join(self.output_dir, rec["name"])
                counter = 1
                while os.path.exists(base_name):
                    name, ext = os.path.splitext(rec["name"])
                    base_name = os.path.join(self.output_dir, f"{name}_{counter}{ext}")
                    counter += 1
                
                # Save file
                with open(base_name, "wb") as f:
                    f.write(rec["data"])
                
                # Save metadata
                with open(f"{base_name}.meta.json", "w") as mf:
                    json.dump(rec["metadata"], mf, indent=2)
                
                success += 1
            except Exception as e:
                messagebox.showerror("Write Error", f"Failed to save {rec['name']}: {e}")
        
        messagebox.showinfo("Done", f"Successfully recovered {success}/{len(sel)} files.")
    
    def on_close(self):
        self.preview_manager.close_current()
        self.root.destroy()

# === Main Execution ===
if __name__ == "__main__":
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")
    
    root = ctk.CTk()
    app = FileRecoveryApp(root)
    root.mainloop()
