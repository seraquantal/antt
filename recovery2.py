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
import time # Thêm thư viện time

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
        "footer": None, # MKV footers can be complex, relying on size for now
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
                # Convert bytes to string if necessary for JSON serialization
                for key, value in exif.items():
                    if isinstance(value, bytes):
                        try:
                            exif[key] = value.decode('utf-8', errors='replace')
                        except UnicodeDecodeError:
                             exif[key] = str(value) # Fallback to string representation
                metadata["exif"] = exif
        except Exception:
            pass

        return metadata
    except Exception as e:
        return {"error": str(e)}

def extract_pdf_metadata(data):
    try:
        # Simple PDF metadata extraction
        text = data.decode('ascii', errors='ignore')[:2000] # Increased search range
        metadata = {}

        # Look for common PDF metadata markers (more robust parsing might be needed for complex PDFs)
        import re
        title_match = re.search(r"/Title\s*\((.*?)\)", text)
        if title_match:
            metadata['title'] = title_match.group(1)

        author_match = re.search(r"/Author\s*\((.*?)\)", text)
        if author_match:
            metadata['author'] = author_match.group(1)

        return metadata
    except Exception as e:
        return {"error": str(e)}

def extract_mkv_metadata(data):
    try:
        # For MKV, we'd normally use a library like pymkv or ffprobe, but for simplicity:
        metadata = {
            "size": len(data),
            "type": "MKV (Matroska)",
            "note": "Use external tools for detailed metadata. This is a basic extraction."
        }
        # Try to find some common MKV tags if possible (very basic)
        try:
            text_data = data.decode('latin-1', errors='ignore') # MKV often has non-UTF8 strings
            if "title" in text_data.lower():
                 metadata[" संभावित शीर्षक"] = "शीर्षक टैग मौजूद हो सकता है" # "Potential title tag might exist"
            if "encoder" in text_data.lower():
                metadata[" संभावित एन्कोडर"] = "एन्कोडर टैग मौजूद हो सकता है" # "Potential encoder tag might exist"
        except Exception:
            pass
        return metadata
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
            0, #win32con.FILE_FLAG_NO_BUFFERING | win32con.FILE_FLAG_RAW_HANDLE, # Potential flags for raw access
            None
        )
    except Exception as e:
        raise Exception(f"Failed to open drive using CreateFile: {e} (Try running as administrator)")

    try:
        fd = msvcrt.open_osfhandle(handle.Detach(), os.O_RDONLY | os.O_BINARY) # Ensure binary mode
        fileD = os.fdopen(fd, 'rb')
    except Exception as e:
        win32api.CloseHandle(handle) # Close handle if fdopen fails
        raise Exception(f"Failed to convert handle to file: {e}")

    return fileD

def scan_drive_internal(raw_drive_path, total_size, selected_types, progress_callback,
                        stop_event, listbox_update_callback, scan_mode="normal", sector_size=512):
    recovered_files_list = [] # Use a list to append results from threads if needed
    try:
        fileD = open_raw_drive(raw_drive_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open drive: {e}")
        if progress_callback:
            progress_callback(0, True) # Indicate error
        return recovered_files_list

    # Optimized scanning
    block_size = 4 * 1024 * 1024  # 4MB block size
    if scan_mode == "deep":
        block_size = sector_size # For deep scan, read sector by sector initially
    elif scan_mode == "parallel":
        # For parallel scan, we might adjust block_size or how data is fed to threads later
        pass


    max_header_size = 0
    if selected_types: # Ensure selected_types is not empty
        max_header_size = max(len(h) for f_type_key in selected_types for h in FILE_SIGNATURES[f_type_key]["headers"])
    overlap = max_header_size -1 if max_header_size > 0 else 0


    offset = 0
    previous_chunk = b""
    scan_start_time = datetime.now()
    files_found_count = 0

    active_file_streams = {} # For handling fragmented files or overlapping signatures

    while not stop_event.is_set():
        try:
            chunk = fileD.read(block_size)
        except Exception as e:
            print(f"Error reading from drive at offset {offset}: {e}")
            break # Stop if read error occurs

        if not chunk:
            break # End of drive

        current_search_block = previous_chunk + chunk
        m_current_search_block = memoryview(current_search_block)

        for ftype in selected_types:
            sig_info = FILE_SIGNATURES.get(ftype)
            if not sig_info or not sig_info["headers"]:
                continue

            for header in sig_info["headers"]:
                header_len = len(header)
                footer = sig_info.get("footer")
                extension = sig_info["extension"]
                metadata_func = sig_info.get("metadata_func")

                # Search for header
                start_index = 0
                while True:
                    pos = current_search_block.find(header, start_index)
                    if pos == -1:
                        break # No more occurrences of this header in the current search block

                    abs_offset = offset - len(previous_chunk) + pos
                    start_index = pos + header_len # Continue search after this found header

                    # --- Start of file carving logic ---
                    file_data_list = [current_search_block[pos:]] # Start with the current block part
                    current_file_size = len(file_data_list[0])
                    file_complete = False
                    temp_file_offset = fileD.tell() # Save current file descriptor position

                    if footer:
                        # Try to find footer in the already read data
                        footer_pos_in_block = file_data_list[0].find(footer)
                        if footer_pos_in_block != -1:
                            actual_footer_pos = footer_pos_in_block + len(footer)
                            file_data_list = [file_data_list[0][:actual_footer_pos]]
                            file_complete = True
                        else:
                            # Footer not in current block, need to read more
                            # This is a simplified approach. Real carving is more complex.
                            # For deep scan, you might read fixed size or until footer.
                            # For normal scan, this might involve larger subsequent reads.
                            # Limiting read for performance in this example:
                            max_read_ahead = block_size * 20 # Max ~80MB for a file without footer found quickly
                            if scan_mode == "deep":
                                max_read_ahead = block_size * 50 # Allow larger for deep scan

                            while current_file_size < max_read_ahead:
                                if stop_event.is_set(): break
                                next_block_read = fileD.read(block_size)
                                if not next_block_read:
                                    break
                                file_data_list.append(next_block_read)
                                current_file_size += len(next_block_read)
                                if footer in next_block_read:
                                    # Concatenate, find footer, and trim
                                    temp_full_data = b"".join(file_data_list)
                                    footer_final_pos = temp_full_data.find(footer)
                                    if footer_final_pos != -1:
                                        file_data_list = [temp_full_data[:footer_final_pos + len(footer)]]
                                        file_complete = True
                                    break # Found footer or EOF
                            if not file_complete:
                                # If footer still not found, consider it a partial file up to max_read_ahead
                                file_data_list = [b"".join(file_data_list)]


                    else: # No footer defined (e.g., MKV, or rely on max size)
                        # For files without footers, we might limit by a typical max size or smarter logic
                        # For MKV, the structure is more complex (EBML). This is a simplification.
                        # Let's assume a max size for now, or read a few more blocks.
                        max_size_no_footer = block_size * 30 # Approx 120MB for no-footer types
                        if ftype == "MKV":
                             max_size_no_footer = block_size * 100 # Larger for MKVs, still arbitrary

                        # Read a bit more if it's a no-footer type to get a decent chunk
                        if len(file_data_list[0]) < block_size * 2 : # If initial chunk is small
                            for _ in range(5): # Read a few more blocks
                                if stop_event.is_set(): break
                                next_block_read = fileD.read(block_size)
                                if not next_block_read: break
                                file_data_list.append(next_block_read)
                                current_file_size += len(next_block_read)
                                if current_file_size > max_size_no_footer: break
                        file_data_list = [b"".join(file_data_list)]
                        if len(file_data_list[0]) > max_size_no_footer:
                            file_data_list = [file_data_list[0][:max_size_no_footer]]
                        file_complete = True # Mark as complete for processing

                    # --- End of file carving logic ---

                    fileD.seek(temp_file_offset) # IMPORTANT: Reset file descriptor to where it was before carving this file

                    if file_complete:
                        final_file_bytes = b"".join(file_data_list)
                        if not final_file_bytes.startswith(header): # Sanity check
                            continue


                        full_hash = calculate_hash(final_file_bytes)
                        file_name = f"{ftype}_{abs_offset:x}_{full_hash[:8]}{extension}"

                        metadata = {}
                        if metadata_func:
                            try:
                                metadata = metadata_func(final_file_bytes)
                            except Exception as e_meta:
                                metadata = {"metadata_error": str(e_meta)}

                        recovered_info = {
                            "offset": abs_offset,
                            "data": final_file_bytes, # Store bytes for now
                            "name": file_name,
                            "type": ftype,
                            "hash": full_hash,
                            "metadata": metadata,
                            "size": len(final_file_bytes),
                            "discovery_time": datetime.now().isoformat()
                        }
                        recovered_files_list.append(recovered_info)
                        files_found_count +=1
                        if listbox_update_callback:
                            listbox_update_callback(recovered_info) # Update GUI progressively

                        # For deep scan, we might want to skip the carved area if successful.
                        # This needs careful handling of 'offset' and 'previous_chunk'.
                        # For simplicity here, we continue search from 'pos + header_len'.

        # Prepare for next iteration
        previous_chunk = chunk[-overlap:] if overlap > 0 and len(chunk) > overlap else chunk if overlap > 0 else b""
        offset += (len(chunk) - (len(previous_chunk) if previous_chunk is chunk else 0) ) # Adjust offset based on actual advance

        if progress_callback and total_size:
            progress_callback(offset / total_size if total_size else 0, False)

        if scan_mode == "deep" and files_found_count > 0 and files_found_count % 10 == 0: # Slow down deep scan a bit
            time.sleep(0.01)


    scan_end_time = datetime.now()
    scan_duration = (scan_end_time - scan_start_time).total_seconds()
    print(f"Scan ({scan_mode}) completed in {scan_duration:.2f} seconds. Found {files_found_count} potential files.")

    if fileD:
        fileD.close()
    if progress_callback:
            progress_callback(1.0, True if not stop_event.is_set() else False) # Final update, is_complete = True if not stopped

    # Remove data from memory before returning if not saving them directly
    # for f_info in recovered_files_list:
    #    del f_info["data"] # Or handle data saving elsewhere
    return recovered_files_list


# Global variable to hold the current preview window
current_preview_window = None
stop_scan_event = threading.Event() # Event to signal scan threads to stop

def close_current_preview():
    global current_preview_window
    if current_preview_window is not None:
        try:
            current_preview_window.destroy()
        except Exception as e:
            print("Error closing preview window:", e)
        finally:
            current_preview_window = None

def show_metadata(metadata_dict_or_str):
    global current_preview_window
    close_current_preview()

    current_preview_window = ctk.CTkToplevel()
    current_preview_window.title("File Metadata")
    current_preview_window.geometry("600x400")

    text_widget = tk.Text(current_preview_window, wrap="word", relief="sunken", borderwidth=1)
    text_widget.pack(expand=True, fill="both", padx=10, pady=10)

    scrollbar = ctk.CTkScrollbar(text_widget, command=text_widget.yview)
    scrollbar.pack(side="right", fill="y")
    text_widget.configure(yscrollcommand=scrollbar.set)


    if isinstance(metadata_dict_or_str, dict):
        try:
            # Attempt to pretty-print. Handle potential unencodable characters.
            formatted_metadata = json.dumps(metadata_dict_or_str, indent=2, ensure_ascii=False)
        except TypeError: # Handle non-serializable objects if any (e.g. bytes)
             formatted_metadata = json.dumps(str(metadata_dict_or_str), indent=2, ensure_ascii=False) # Fallback
    else:
        formatted_metadata = str(metadata_dict_or_str)

    text_widget.insert("1.0", formatted_metadata)
    text_widget.configure(state="disabled") # Make it read-only
    current_preview_window.protocol("WM_DELETE_WINDOW", close_current_preview)
    current_preview_window.after(100, current_preview_window.lift) # Bring to front

def preview_image(data, metadata=None):
    global current_preview_window
    close_current_preview()

    try:
        image = Image.open(io.BytesIO(data))
        current_preview_window = ctk.CTkToplevel()
        current_preview_window.title("Image Preview")
        current_preview_window.geometry("800x700")

        tabview = ctk.CTkTabview(current_preview_window, width=780, height=680)
        tabview.pack(expand=True, fill="both", padx=10, pady=10)

        tab_image = tabview.add("Image")
        img_frame = ctk.CTkFrame(tab_image, fg_color="transparent")
        img_frame.pack(expand=True, fill="both")


        # Calculate aspect ratio to fit image within a max size (e.g., 700x600)
        max_w, max_h = 750, 550
        img_w, img_h = image.size
        ratio = min(max_w/img_w, max_h/img_h)
        new_w, new_h = int(img_w * ratio), int(img_h * ratio)

        image.thumbnail((new_w, new_h), Image.LANCZOS) # Use LANCZOS for better quality
        tk_img = ImageTk.PhotoImage(image)

        lbl = ctk.CTkLabel(img_frame, image=tk_img, text="")
        lbl.image = tk_img  # keep a reference
        lbl.pack(padx=10, pady=10, anchor="center")


        if metadata:
            tab_meta = tabview.add("Metadata")
            meta_text_widget = tk.Text(tab_meta, wrap="word", relief="sunken", borderwidth=1)
            meta_text_widget.pack(expand=True, fill="both", padx=5, pady=5)
            meta_scrollbar = ctk.CTkScrollbar(meta_text_widget, command=meta_text_widget.yview)
            meta_scrollbar.pack(side="right", fill="y")
            meta_text_widget.configure(yscrollcommand=meta_scrollbar.set)
            try:
                formatted_metadata = json.dumps(metadata, indent=2, ensure_ascii=False)
            except TypeError:
                formatted_metadata = json.dumps(str(metadata), indent=2, ensure_ascii=False)
            meta_text_widget.insert("1.0", formatted_metadata)
            meta_text_widget.configure(state="disabled")


        current_preview_window.protocol("WM_DELETE_WINDOW", close_current_preview)
        current_preview_window.after(100, current_preview_window.lift)
    except Exception as e:
        messagebox.showerror("Preview Error", f"Cannot preview image: {e}")
        if current_preview_window: current_preview_window.destroy()


def preview_text(data, metadata=None):
    global current_preview_window
    close_current_preview()

    try:
        text_content = data.decode('utf-8', errors='replace')[:10000] # Increased preview size
        current_preview_window = ctk.CTkToplevel()
        current_preview_window.title("Text Preview (First 10KB)")
        current_preview_window.geometry("800x700")

        tabview = ctk.CTkTabview(current_preview_window,  width=780, height=680)
        tabview.pack(expand=True, fill="both", padx=10, pady=10)

        tab_text = tabview.add("Text Content")
        text_widget = tk.Text(tab_text, wrap="word", relief="sunken", borderwidth=1)
        text_widget.pack(expand=True, fill="both", padx=5, pady=5)
        text_scrollbar = ctk.CTkScrollbar(text_widget, command=text_widget.yview)
        text_scrollbar.pack(side="right", fill="y")
        text_widget.configure(yscrollcommand=text_scrollbar.set)
        text_widget.insert("1.0", text_content)
        text_widget.configure(state="disabled")


        if metadata:
            tab_meta = tabview.add("Metadata")
            meta_widget = tk.Text(tab_meta, wrap="word", relief="sunken", borderwidth=1)
            meta_widget.pack(expand=True, fill="both", padx=5, pady=5)
            meta_scrollbar = ctk.CTkScrollbar(meta_widget, command=meta_widget.yview)
            meta_scrollbar.pack(side="right", fill="y")
            meta_widget.configure(yscrollcommand=meta_scrollbar.set)
            try:
                formatted_metadata = json.dumps(metadata, indent=2, ensure_ascii=False)
            except TypeError:
                formatted_metadata = json.dumps(str(metadata), indent=2, ensure_ascii=False)
            meta_widget.insert("1.0", formatted_metadata)
            meta_widget.configure(state="disabled")


        current_preview_window.protocol("WM_DELETE_WINDOW", close_current_preview)
        current_preview_window.after(100, current_preview_window.lift)
    except Exception as e:
        messagebox.showerror("Preview Error", f"Cannot preview text: {e}")
        if current_preview_window: current_preview_window.destroy()


def preview_mkv(data, metadata=None):
    global current_preview_window
    close_current_preview()

    tmp_path = ""
    try:
        # Create a temporary file that persists until explicitly deleted
        # This is important for external players that might need time to open the file.
        temp_dir = tempfile.gettempdir()
        tmp_path = os.path.join(temp_dir, f"preview_{hashlib.md5(data[:1024]).hexdigest()}.mkv")

        with open(tmp_path, "wb") as tmp_file:
            tmp_file.write(data)

        # Attempt to open with default OS handler
        os.startfile(tmp_path) # This is Windows specific

        current_preview_window = ctk.CTkToplevel()
        current_preview_window.title("MKV Preview Launched")
        current_preview_window.geometry("500x300") # Smaller window, just for info

        tabview = ctk.CTkTabview(current_preview_window, width=480, height=280)
        tabview.pack(expand=True, fill="both", padx=10, pady=10)

        tab_info = tabview.add("Info")
        info_text = (f"MKV file launched in external player.\n\n"
                     f"Temporary file: {tmp_path}\n"
                     f"This file will be automatically cleaned up by the OS later, "
                     f"or you can delete it manually if needed after viewing.")
        lbl = ctk.CTkLabel(tab_info, text=info_text, wraplength=400, justify="left")
        lbl.pack(padx=10, pady=10)


        if metadata:
            tab_meta = tabview.add("Metadata")
            text_widget = tk.Text(tab_meta, wrap="word", relief="sunken", borderwidth=1)
            text_widget.pack(expand=True, fill="both", padx=5, pady=5)
            meta_scrollbar = ctk.CTkScrollbar(text_widget, command=text_widget.yview)
            meta_scrollbar.pack(side="right", fill="y")
            text_widget.configure(yscrollcommand=meta_scrollbar.set)

            try:
                formatted_metadata = json.dumps(metadata, indent=2, ensure_ascii=False)
            except TypeError:
                formatted_metadata = json.dumps(str(metadata), indent=2, ensure_ascii=False)
            text_widget.insert("1.0", formatted_metadata)
            text_widget.configure(state="disabled")

        def on_mkv_preview_close():
            # Note: We don't delete tmp_path here immediately because the external player might still be using it.
            # Rely on OS temp file cleanup or manual deletion by user if concerned.
            # For more robust cleanup, one might monitor the external process, which is complex.
            print(f"MKV Preview window closed. Temp file at: {tmp_path}")
            close_current_preview()


        current_preview_window.protocol("WM_DELETE_WINDOW", on_mkv_preview_close)
        current_preview_window.after(100, current_preview_window.lift)

    except FileNotFoundError: # os.startfile might fail if no app is associated
         messagebox.showerror("Preview Error", f"Cannot preview MKV: No application associated with .mkv files, or ffplay not found.")
         if tmp_path and os.path.exists(tmp_path): os.remove(tmp_path) # Clean up if launch failed
         if current_preview_window: current_preview_window.destroy()
    except Exception as e:
        messagebox.showerror("Preview Error", f"Cannot preview MKV: {e}")
        if tmp_path and os.path.exists(tmp_path): os.remove(tmp_path) # Clean up
        if current_preview_window: current_preview_window.destroy()


# ----------------------------
# CustomTkinter GUI Setup
# ----------------------------
ctk.set_appearance_mode("System") # System, Dark, Light
ctk.set_default_color_theme("blue") # blue, dark-blue, green

root = ctk.CTk()
root.title("Enhanced File Recovery Tool")
root.geometry("1100x850") # Increased size slightly

# Global variables
recovered_files_data_store = {} # Store full data temporarily, mapping hash to data
# recovered_files will store metadata and references, not the full binary data to save RAM for listbox
recovered_files_display_list = [] # List of dicts for display in listbox
output_dir = ""
current_scan_thread = None # To manage the scan thread


# Create a main frame to hold UI components
main_frame = ctk.CTkFrame(root)
main_frame.pack(padx=10, pady=10, fill="both", expand=True) # Reduced padding slightly

# --- Tabbed interface for different scan modes ---
tab_view = ctk.CTkTabview(main_frame, height=780) # Adjusted height
tab_view.pack(padx=5, pady=5, fill="both", expand=True)

normal_scan_tab = tab_view.add("Normal Scan")
deep_scan_tab = tab_view.add("Deep Scan (Sector by Sector)")
# Parallel scan can be complex to implement correctly without significant overhead or race conditions.
# For now, let's focus on Normal and Deep. Parallel could be a future enhancement.
# parallel_scan_tab = tab_view.add("Parallel Scan (Experimental)")


def create_scan_ui(parent_tab, scan_mode_name):
    """Helper function to create common UI elements for each scan tab."""
    scan_ui_frame = ctk.CTkFrame(parent_tab, fg_color="transparent")
    scan_ui_frame.pack(fill="both", expand=True, padx=5, pady=5)

    # -- Drive Selection --
    drive_frame = ctk.CTkFrame(scan_ui_frame)
    drive_frame.pack(pady=5, fill="x", padx=10)

    ctk.CTkLabel(drive_frame, text="Select Drive:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    drive_list = get_available_drives()
    drive_var = ctk.StringVar(value=drive_list[0] if drive_list else "No drives found")
    drive_combobox = ctk.CTkComboBox(drive_frame, values=drive_list, variable=drive_var, width=150)
    drive_combobox.grid(row=0, column=1, padx=5, pady=5, sticky="w")
    if not drive_list:
        drive_combobox.configure(state="disabled")

    # -- File Types Selection --
    types_frame = ctk.CTkFrame(scan_ui_frame)
    types_frame.pack(pady=5, fill="x", padx=10)
    ctk.CTkLabel(types_frame, text="Select File Types:").pack(side="left", padx=5, pady=5)

    selected_types_vars = {}
    # Use a scrollable frame for file types if there are many
    file_types_canvas = ctk.CTkCanvas(types_frame, height=40) # Adjust height as needed
    file_types_scrollbar = ctk.CTkScrollbar(types_frame, orientation="horizontal", command=file_types_canvas.xview)
    scrollable_types_frame = ctk.CTkFrame(file_types_canvas, fg_color="transparent")

    scrollable_types_frame.bind(
        "<Configure>",
        lambda e: file_types_canvas.configure(scrollregion=file_types_canvas.bbox("all"))
    )
    file_types_canvas.create_window((0, 0), window=scrollable_types_frame, anchor="nw")
    file_types_canvas.configure(xscrollcommand=file_types_scrollbar.set)

    file_types_canvas.pack(side="left", fill="x", expand=True, padx=5)
    if len(FILE_SIGNATURES) > 4: # Only show scrollbar if many types
        file_types_scrollbar.pack(side="bottom", fill="x", padx=5)


    for i, ftype in enumerate(FILE_SIGNATURES.keys()):
        var = tk.IntVar(value=1) # Default to selected
        chk = ctk.CTkCheckBox(scrollable_types_frame, text=ftype, variable=var)
        chk.pack(side="left", padx=5, pady=2)
        selected_types_vars[ftype] = var


    # -- Output Folder Selection --
    output_frame = ctk.CTkFrame(scan_ui_frame)
    output_frame.pack(pady=5, fill="x", padx=10)

    def select_output_directory_tab():
        global output_dir # Use the global output_dir
        selected_dir = filedialog.askdirectory(title="Select Output Directory")
        if selected_dir:
            output_dir = selected_dir
            output_label.configure(text=f"Output: {output_dir}" if len(output_dir) < 60 else f"Output: ...{output_dir[-55:]}")
        elif not output_dir: # If selection cancelled and no prior dir
             output_label.configure(text="Output Directory: Not selected")


    output_btn = ctk.CTkButton(output_frame, text="Select Output Folder", command=select_output_directory_tab, width=180)
    output_btn.grid(row=0, column=0, padx=5, pady=5, sticky="w")
    output_label_text = "Output Directory: Not selected"
    if output_dir: # Persist output_dir across tabs
        output_label_text = f"Output: {output_dir}" if len(output_dir) < 60 else f"Output: ...{output_dir[-55:]}"
    output_label = ctk.CTkLabel(output_frame, text=output_label_text, wraplength=600, justify="left")
    output_label.grid(row=0, column=1, padx=5, pady=5, sticky="w")
    output_frame.columnconfigure(1, weight=1)


    # -- Scan Controls & Progress Bar --
    scan_controls_frame = ctk.CTkFrame(scan_ui_frame)
    scan_controls_frame.pack(pady=5, fill="x", padx=10)

    scan_button = ctk.CTkButton(scan_controls_frame, text=f"Start {scan_mode_name} Scan", width=180)
    scan_button.grid(row=0, column=0, padx=5, pady=5, sticky="w")
    stop_button = ctk.CTkButton(scan_controls_frame, text="Stop Scan", state="disabled", command=lambda: stop_scan_event.set(), width=120)
    stop_button.grid(row=0, column=1, padx=5, pady=5, sticky="w")


    progress_bar = ctk.CTkProgressBar(scan_controls_frame)
    progress_bar.set(0)
    progress_bar.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
    progress_label = ctk.CTkLabel(scan_controls_frame, text="Status: Idle", wraplength=700, justify="left")
    progress_label.grid(row=2, column=0, columnspan=3, padx=5, pady=2, sticky="w")
    scan_controls_frame.columnconfigure(2, weight=1) # Allow progress bar to expand


    # -- Listbox for Recovered Files --
    listbox_frame = ctk.CTkFrame(scan_ui_frame)
    listbox_frame.pack(pady=5, fill="both", expand=True, padx=10)

    listbox = tk.Listbox(listbox_frame, selectmode=tk.EXTENDED, font=("Segoe UI", 10), relief="sunken", borderwidth=1) # EXTENDED for multi-select
    listbox_scrollbar_y = ctk.CTkScrollbar(listbox_frame, command=listbox.yview)
    listbox_scrollbar_x = ctk.CTkScrollbar(listbox_frame, command=listbox.xview, orientation="horizontal")
    listbox.configure(yscrollcommand=listbox_scrollbar_y.set, xscrollcommand=listbox_scrollbar_x.set)

    listbox_scrollbar_y.pack(side="right", fill="y")
    listbox_scrollbar_x.pack(side="bottom", fill="x")
    listbox.pack(padx=0, pady=0, fill="both", expand=True)


    # Assign to a dictionary to access them later
    ui_elements = {
        "drive_var": drive_var, "selected_types_vars": selected_types_vars,
        "output_label": output_label, "scan_button": scan_button, "stop_button": stop_button,
        "progress_bar": progress_bar, "progress_label": progress_label,
        "listbox": listbox
    }

    scan_button.configure(command=lambda: start_scan_wrapper(ui_elements, scan_mode_name.lower().replace(" ", "_"))) # e.g. "deep_scan_sector_by_sector" -> "deep_scan"
    return ui_elements


# Create UI for each tab
normal_scan_ui = create_scan_ui(normal_scan_tab, "Normal")
deep_scan_ui = create_scan_ui(deep_scan_tab, "Deep")
# parallel_scan_ui = create_scan_ui(parallel_scan_tab, "Parallel (Experimental)")

# --- Common controls (Recover, Report) ---
common_controls_frame = ctk.CTkFrame(main_frame)
common_controls_frame.pack(pady=5, fill="x", padx=15) # Place it below tabs

recover_button = ctk.CTkButton(common_controls_frame, text="Recover Selected Files", command=lambda: recover_selected_files_from_active_tab())
recover_button.pack(side="left", padx=10, pady=5)

report_button = ctk.CTkButton(common_controls_frame, text="Save Scan Report", command=lambda: save_scan_report_from_active_tab())
report_button.pack(side="left", padx=10, pady=5)


# --- Event Handlers & Functions ---
def get_active_tab_ui_elements():
    current_tab_name = tab_view.get()
    if current_tab_name == "Normal Scan":
        return normal_scan_ui
    elif current_tab_name == "Deep Scan (Sector by Sector)":
        return deep_scan_ui
    # elif current_tab_name == "Parallel Scan (Experimental)":
    #     return parallel_scan_ui
    return None

def update_listbox_threaded(ui_elems, file_info):
    """Safely updates the listbox from a different thread."""
    if ui_elems and ui_elems.get("listbox"):
        listbox = ui_elems["listbox"]
        # Store the full data separately to avoid bogging down the listbox
        recovered_files_data_store[file_info["hash"]] = file_info["data"]

        display_item = file_info.copy()
        del display_item["data"] # Don't store full binary data in the display list
        recovered_files_display_list.append(display_item) # Add to the global display list

        # Update listbox on the main thread
        listbox.insert(tk.END, f"{file_info['name']} ({file_info['size']/(1024*1024):.2f} MB) - Offset: {file_info['offset']:x} - Hash: {file_info['hash'][:8]}...")
        listbox.see(tk.END) # Scroll to the new item
        ui_elems["progress_label"].configure(text=f"Status: Scanning... Found {len(recovered_files_display_list)} files.")


def start_scan_wrapper(ui_elems, scan_type_str): # scan_type_str: "normal", "deep_scan"
    global current_scan_thread, recovered_files_display_list, recovered_files_data_store
    stop_scan_event.clear() # Reset stop event for new scan

    # Clear previous results
    ui_elems["listbox"].delete(0, tk.END)
    recovered_files_display_list.clear()
    recovered_files_data_store.clear()

    ui_elems["scan_button"].configure(state="disabled")
    ui_elems["stop_button"].configure(state="normal")
    ui_elems["progress_bar"].set(0)
    ui_elems["progress_label"].configure(text="Status: Starting scan...")

    selected_drive = ui_elems["drive_var"].get()
    if not selected_drive or selected_drive == "No drives found":
        messagebox.showerror("Error", "No drive selected or no drives available.")
        ui_elems["scan_button"].configure(state="normal")
        ui_elems["stop_button"].configure(state="disabled")
        return

    raw_drive_path = r"\\.\{}".format(selected_drive[:2]) # Correct path for raw access e.g. \\.\C:

    total_size = get_drive_total_size(selected_drive)
    if total_size is None:
        messagebox.showerror("Error", f"Could not get size for drive {selected_drive}. Ensure it's accessible.")
        ui_elems["scan_button"].configure(state="normal")
        ui_elems["stop_button"].configure(state="disabled")
        return

    selected_file_types_keys = [ftype for ftype, var in ui_elems["selected_types_vars"].items() if var.get() == 1]
    if not selected_file_types_keys:
        messagebox.showwarning("No File Types", "Please select at least one file type to scan for.")
        ui_elems["scan_button"].configure(state="normal")
        ui_elems["stop_button"].configure(state="disabled")
        return

    if not output_dir: # Require output directory to be selected before scan
        messagebox.showwarning("Output Directory", "Please select an output directory before starting the scan.")
        ui_elems["scan_button"].configure(state="normal")
        ui_elems["stop_button"].configure(state="disabled")
        return


    def progress_update(value, is_complete_or_error=False):
        ui_elems["progress_bar"].set(value)
        if total_size:
            processed_mb = value * total_size / (1024*1024)
            total_mb = total_size / (1024*1024)
            status_text = f"Progress: {processed_mb:.2f} MB / {total_mb:.2f} MB ({value*100:.1f}%)"
            if not is_complete_or_error:
                 ui_elems["progress_label"].configure(text=status_text + f" Found: {len(recovered_files_display_list)}")
        else:
            status_text = f"Progress: {value*100:.1f}%"

        if is_complete_or_error:
            final_status = "Scan completed." if value >= 0.99 else "Scan stopped by user or error."
            if stop_scan_event.is_set() and value < 0.99 : final_status = "Scan stopped by user."

            ui_elems["progress_label"].configure(text=f"Status: {final_status} Found {len(recovered_files_display_list)} files.")
            ui_elems["scan_button"].configure(state="normal")
            ui_elems["stop_button"].configure(state="disabled")


    scan_mode_arg = "normal"
    if "deep" in scan_type_str:
        scan_mode_arg = "deep"
    elif "parallel" in scan_type_str:
        scan_mode_arg = "parallel" # Though not fully implemented yet

    # Ensure scan_drive_internal is called in a thread
    def threaded_scan_task():
        global recovered_files_display_list # To store results
        nonlocal total_size # Capture total_size from outer scope

        # Call the actual scanning function
        results = scan_drive_internal(
            raw_drive_path,
            total_size,
            selected_file_types_keys,
            lambda val, complete: root.after(0, progress_update, val, complete), # GUI updates in main thread
            stop_event=stop_scan_event,
            listbox_update_callback=lambda info: root.after(0, update_listbox_threaded, ui_elems, info),
            scan_mode=scan_mode_arg
        )
        # scan_drive_internal now returns the list, but update_listbox_threaded already populated recovered_files_display_list
        # recovered_files_display_list = results # This would overwrite if scan_drive_internal was the sole populator

        # Final completion status update (if not already handled by progress_update's complete flag)
        # This ensures the GUI is updated even if the loop finishes without the progress reaching 1.0 exactly
        if not stop_scan_event.is_set(): # If not stopped by user
            root.after(0, progress_update, 1.0, True)
        else:
            root.after(0, progress_update, ui_elems["progress_bar"].get(), True)


    current_scan_thread = threading.Thread(target=threaded_scan_task, daemon=True)
    current_scan_thread.start()


def on_item_double_click(event):
    active_ui = get_active_tab_ui_elements()
    if not active_ui: return
    listbox = active_ui["listbox"]

    selection = listbox.curselection()
    if not selection:
        return
    selected_index = selection[0]

    if 0 <= selected_index < len(recovered_files_display_list):
        file_info_display = recovered_files_display_list[selected_index]
        file_hash = file_info_display["hash"]

        # Retrieve the actual data from the data store
        file_data = recovered_files_data_store.get(file_hash)

        if not file_data:
            messagebox.showerror("Error", "File data not found in store. Cannot preview.")
            return

        file_type = file_info_display["type"]
        metadata = file_info_display.get("metadata")

        if file_type == "JPEG":
            preview_image(file_data, metadata)
        elif file_type == "MKV":
            preview_mkv(file_data, metadata)
        elif file_type == "PDF": # Assuming PDF is text-previewable for simplicity here
            preview_text(file_data, metadata) # Or a dedicated PDF previewer
        else: # Default to text preview for other types
            preview_text(file_data, metadata)

# Bind double click to the listboxes of each tab
normal_scan_ui["listbox"].bind("<Double-1>", on_item_double_click)
deep_scan_ui["listbox"].bind("<Double-1>", on_item_double_click)
# if parallel_scan_ui: parallel_scan_ui["listbox"].bind("<Double-1>", on_item_double_click)


# -- Right-click context menu for metadata --
context_menu = tk.Menu(root, tearoff=0)

def show_selected_metadata_from_active_tab():
    active_ui = get_active_tab_ui_elements()
    if not active_ui: return
    listbox = active_ui["listbox"]
    selection = listbox.curselection()

    if selection:
        selected_index = selection[0]
        if 0 <= selected_index < len(recovered_files_display_list):
            file_info = recovered_files_display_list[selected_index]
            show_metadata(file_info.get("metadata", "No metadata available or error during extraction."))

context_menu.add_command(label="Show Metadata", command=show_selected_metadata_from_active_tab)

def show_context_menu(event):
    active_ui = get_active_tab_ui_elements()
    if not active_ui: return
    listbox = active_ui["listbox"]

    # Select item under mouse pointer before showing menu
    # listbox.selection_clear(0, tk.END) # Optional: clear previous selections
    # listbox.selection_set(listbox.nearest(event.y)) # Select the item under cursor
    # listbox.activate(listbox.nearest(event.y))

    try:
        # Check if there's any selection. If not, don't show menu or disable items.
        if listbox.curselection():
            context_menu.tk_popup(event.x_root, event.y_root)
        else:
            # Optionally, provide feedback if no item is selected
            # print("No item selected for context menu")
            pass
    finally:
        context_menu.grab_release()

normal_scan_ui["listbox"].bind("<Button-3>", show_context_menu)
deep_scan_ui["listbox"].bind("<Button-3>", show_context_menu)
# if parallel_scan_ui: parallel_scan_ui["listbox"].bind("<Button-3>", show_context_menu)


def recover_selected_files_from_active_tab():
    global output_dir # Ensure we're using the globally set output_dir
    active_ui = get_active_tab_ui_elements()
    if not active_ui:
        messagebox.showerror("Error", "No active scan tab found.")
        return
    listbox = active_ui["listbox"]

    if not output_dir:
        messagebox.showwarning("No Output Folder", "Please select an output folder first using the 'Select Output Folder' button.")
        return

    selected_indices = listbox.curselection()
    if not selected_indices:
        messagebox.showinfo("No Selection", "Please select at least one file from the list to recover.")
        return

    success_count = 0
    failed_files = []

    for idx in selected_indices:
        if 0 <= idx < len(recovered_files_display_list):
            file_info_display = recovered_files_display_list[idx]
            file_hash = file_info_display["hash"]
            file_data = recovered_files_data_store.get(file_hash)
            file_name = file_info_display["name"]
            metadata = file_info_display.get("metadata")


            if not file_data:
                messagebox.showerror("Error", f"Data for {file_name} not found. Cannot recover.")
                failed_files.append(file_name + " (data missing)")
                continue
            try:
                # Ensure directory exists
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(output_dir, file_name)

                # Handle potential filename conflicts by appending a number
                counter = 1
                base_name, ext = os.path.splitext(file_name)
                while os.path.exists(output_path):
                    output_path = os.path.join(output_dir, f"{base_name}_{counter}{ext}")
                    counter += 1


                with open(output_path, "wb") as f:
                    f.write(file_data)

                if metadata and not metadata.get("error") and not metadata.get("metadata_error"): # Only save valid metadata
                    meta_path = output_path + ".meta.json"
                    with open(meta_path, "w", encoding='utf-8') as f_meta: # Ensure utf-8 for metadata
                        json.dump(metadata, f_meta, indent=2, ensure_ascii=False)
                success_count += 1
            except Exception as e:
                failed_files.append(f"{file_name} ({str(e)})")
                print(f"Error saving file {file_name}: {e}") # Log to console as well

    result_message = f"Successfully recovered {success_count} out of {len(selected_indices)} selected files."
    if failed_files:
        result_message += f"\n\nFailed to recover:\n" + "\n".join(failed_files)
        messagebox.showwarning("Recovery Partially Successful", result_message)
    else:
        messagebox.showinfo("Recovery Complete", result_message)


def save_scan_report_from_active_tab():
    active_ui = get_active_tab_ui_elements()
    if not active_ui:
        messagebox.showerror("Error", "No active scan tab found.")
        return

    if not recovered_files_display_list: # Check the global display list
        messagebox.showwarning("No Data", "No scan data available to save. Please perform a scan first.")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")],
        title="Save Scan Report As"
    )

    if file_path:
        try:
            # Get drive and file types from the active UI tab
            drive_scanned = active_ui["drive_var"].get()
            scanned_types_keys = [ftype for ftype, var in active_ui["selected_types_vars"].items() if var.get() == 1]

            report_data = {
                "scan_report_version": "1.1",
                "scan_timestamp": datetime.now().isoformat(),
                "scanned_drive": drive_scanned,
                "selected_file_types_for_scan": scanned_types_keys,
                "total_files_found_in_session": len(recovered_files_display_list),
                "recovered_files_summary": [
                    {
                        "name": f_disp["name"],
                        "type": f_disp["type"],
                        "size_bytes": f_disp["size"],
                        "sha256_hash": f_disp["hash"],
                        "found_at_offset_hex": f"{f_disp['offset']:x}",
                        "discovery_timestamp": f_disp["discovery_time"],
                        "metadata_summary": {k: v for k, v in f_disp.get("metadata", {}).items() if not isinstance(v, (Image.Image, bytes))} # Avoid large/binary data in report metadata
                    } for f_disp in recovered_files_display_list
                ]
            }

            with open(file_path, "w", encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            messagebox.showinfo("Report Saved", f"Scan report successfully saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Save Report Error", f"Failed to save scan report: {str(e)}")


# --- Application Exit ---
def on_closing():
    global current_scan_thread
    if messagebox.askokcancel("Quit", "Do you want to quit the File Recovery Tool?"):
        stop_scan_event.set() # Signal any running scan to stop
        if current_scan_thread and current_scan_thread.is_alive():
            print("Waiting for scan thread to finish...")
            current_scan_thread.join(timeout=2) # Wait for a bit
        close_current_preview() # Close any open preview window
        root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
