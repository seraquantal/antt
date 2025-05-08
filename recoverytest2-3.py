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
import time
import re

from tkinter import messagebox, filedialog
from PIL import Image, ImageTk, ExifTags
import customtkinter as ctk
import tkinter as tk
try:
    from PyPDF2 import PdfReader
    PYPDF2_AVAILABLE = True
except ImportError:
    PYPDF2_AVAILABLE = False
    print("PyPDF2 library not found. PDF metadata extraction will be basic. Install with: pip install PyPDF2")


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

def parse_exif_date(date_str):
    if not date_str or not isinstance(date_str, str):
        return None
    try:
        dt = datetime.strptime(date_str, '%Y:%m:%d %H:%M:%S')
        return dt.isoformat()
    except ValueError:
        return str(date_str)

def extract_image_metadata(data):
    try:
        image = Image.open(io.BytesIO(data))
        metadata = {
            "format": image.format,
            "size_pixels": f"{image.width}x{image.height}",
            "mode": image.mode,
            "embedded_title": None,
            "embedded_creation_date": None,
            "embedded_modified_date": None,
        }
        try:
            exif_data = image._getexif()
            if exif_data:
                exif = {}
                for k, v in exif_data.items():
                    if k in ExifTags.TAGS:
                        tag_name = ExifTags.TAGS[k]
                        if isinstance(v, bytes):
                            try:
                                exif[tag_name] = v.decode('utf-8', errors='replace').strip()
                            except:
                                exif[tag_name] = str(v)
                        else:
                             exif[tag_name] = v if not isinstance(v, str) else v.strip()
                metadata["exif_all"] = {key: str(value)[:200] for key, value in exif.items()}
                metadata["embedded_creation_date"] = parse_exif_date(exif.get("DateTimeOriginal")) or \
                                                  parse_exif_date(exif.get("DateTimeDigitized"))
                metadata["embedded_modified_date"] = parse_exif_date(exif.get("DateTime"))
                metadata["embedded_title"] = exif.get("ImageDescription") or exif.get("XPTitle")
                if metadata["embedded_title"] and isinstance(metadata["embedded_title"], bytes):
                     try:
                         metadata["embedded_title"] = metadata["embedded_title"].decode('utf-16-le', errors='replace').strip()
                     except UnicodeDecodeError:
                         metadata["embedded_title"] = metadata["embedded_title"].decode('latin-1', errors='replace').strip()
        except Exception as exif_e:
            metadata["exif_error"] = str(exif_e)
        return metadata
    except Exception as e:
        return {"error": str(e), "notes": "Could not open image or read basic properties."}

def parse_pdf_date(date_str):
    if not date_str or not isinstance(date_str, str):
        return None
    date_str = date_str.strip()
    if date_str.startswith("D:"):
        date_str = date_str[2:]
    if 'Z' in date_str or '+' in date_str or '-' in date_str:
        match = re.match(r"(\d{14})", date_str)
        if match:
            date_str = match.group(1)
        else:
            return str(date_str)
    elif len(date_str) > 14:
        date_str = date_str[:14]
    try:
        if len(date_str) >= 14: dt = datetime.strptime(date_str[:14], '%Y%m%d%H%M%S')
        elif len(date_str) >= 12: dt = datetime.strptime(date_str[:12], '%Y%m%d%H%M')
        elif len(date_str) >= 8: dt = datetime.strptime(date_str[:8], '%Y%m%d')
        else: return str(date_str)
        return dt.isoformat()
    except ValueError:
        return str(date_str)

def extract_pdf_metadata(data):
    metadata = {
        "embedded_title": None, "embedded_author": None,
        "embedded_creation_date": None, "embedded_modified_date": None,
        "pdf_version": None, "num_pages": None,
    }
    if not PYPDF2_AVAILABLE:
        metadata["error"] = "PyPDF2 library not available for detailed PDF metadata."
        try:
            text_content = data.decode('latin-1', errors='ignore')[:3000]
            title_match = re.search(r"/Title\s*\((.*?)\)", text_content, re.IGNORECASE)
            if title_match: metadata["embedded_title"] = title_match.group(1).strip()
            author_match = re.search(r"/Author\s*\((.*?)\)", text_content, re.IGNORECASE)
            if author_match: metadata["embedded_author"] = author_match.group(1).strip()
            creation_match = re.search(r"/CreationDate\s*\((.*?)\)", text_content, re.IGNORECASE)
            if creation_match: metadata["embedded_creation_date"] = parse_pdf_date(creation_match.group(1))
            mod_match = re.search(r"/ModDate\s*\((.*?)\)", text_content, re.IGNORECASE)
            if mod_match: metadata["embedded_modified_date"] = parse_pdf_date(mod_match.group(1))
        except Exception as e_basic:
            metadata["basic_extraction_error"] = str(e_basic)
        return metadata
    try:
        pdf_file = io.BytesIO(data)
        reader = PdfReader(pdf_file)
        doc_info = reader.metadata
        if doc_info:
            metadata["embedded_title"] = doc_info.title if doc_info.title else None
            metadata["embedded_author"] = doc_info.author if doc_info.author else None
            if doc_info.creation_date: metadata["embedded_creation_date"] = doc_info.creation_date.isoformat()
            if doc_info.modification_date: metadata["embedded_modified_date"] = doc_info.modification_date.isoformat()
        try: metadata["num_pages"] = len(reader.pages)
        except: metadata["num_pages"] = "N/A"
        header_str = data[:10].decode('latin-1', errors='ignore')
        version_match = re.match(r"%PDF-(\d\.\d)", header_str)
        if version_match: metadata["pdf_version"] = version_match.group(1)
        return metadata
    except Exception as e:
        metadata["error"] = f"PyPDF2 processing error: {str(e)}"
        return metadata

def extract_mkv_metadata(data):
    try:
        metadata = {
            "size_bytes": len(data),
            "file_type_suggestion": "MKV (Matroska Video)",
            "note": "MKV metadata is complex. This is a basic check.",
            "embedded_title": None, "embedded_creation_date": None
        }
        try:
            text_data = data.decode('latin-1', errors='ignore')
            title_match = re.search(r"TITLE(?:=|" + chr(0) + r"{1,3})([^\x00-\x1F\x7F-\xFF]{3,100})", text_data, re.IGNORECASE)
            if title_match:
                try: metadata["embedded_title"] = title_match.group(1).strip()
                except: pass
        except: pass
        return metadata
    except Exception as e: return {"error": str(e)}

def calculate_hash(data):
    return hashlib.sha256(data).hexdigest()

def get_available_drives():
    drives = []
    drive_bits = win32api.GetLogicalDrives()
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if drive_bits & 1: drives.append(f"{letter}:\\")
        drive_bits >>= 1
    return drives

def get_drive_total_size(drive_letter):
    try: _, totalBytes, _ = win32api.GetDiskFreeSpaceEx(drive_letter); return totalBytes
    except Exception as e: print(f"Error getting size for drive {drive_letter}: {e}"); return None

def open_raw_drive(drive_path):
    try:
        handle = win32file.CreateFile(drive_path, win32con.GENERIC_READ,
                                      win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
                                      win32con.OPEN_EXISTING, 0, None)
    except Exception as e: raise Exception(f"Failed to open drive using CreateFile: {e} (Try running as administrator)")
    try:
        fd = msvcrt.open_osfhandle(handle.Detach(), os.O_RDONLY | os.O_BINARY)
        fileD = os.fdopen(fd, 'rb')
    except Exception as e: win32api.CloseHandle(handle); raise Exception(f"Failed to convert handle to file: {e}")
    return fileD

def scan_drive_internal(raw_drive_path, total_size, selected_types, progress_callback,
                        stop_event, listbox_update_callback, scan_mode="normal", sector_size=512):
    recovered_files_list_temp = []
    try: fileD = open_raw_drive(raw_drive_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open drive: {e}")
        if progress_callback: progress_callback(0, True)
        return recovered_files_list_temp

    block_size = 4 * 1024 * 1024
    if scan_mode == "deep": block_size = sector_size
    max_header_size = 0
    if selected_types: max_header_size = max(len(h) for f_type_key in selected_types for h in FILE_SIGNATURES[f_type_key]["headers"])
    overlap = max_header_size - 1 if max_header_size > 0 else 0
    offset = 0
    previous_chunk = b""
    scan_start_time = datetime.now()
    files_found_count = 0

    while not stop_event.is_set():
        try: chunk = fileD.read(block_size)
        except Exception as e: print(f"Error reading from drive at offset {offset}: {e}"); break
        if not chunk: break
        current_search_block = previous_chunk + chunk
        for ftype_key in selected_types:
            sig_info = FILE_SIGNATURES.get(ftype_key)
            if not sig_info or not sig_info["headers"]: continue
            for header_bytes in sig_info["headers"]:
                header_len = len(header_bytes); footer_bytes = sig_info.get("footer")
                file_extension = sig_info["extension"]; metadata_extraction_func = sig_info.get("metadata_func")
                current_pos_in_block = 0
                while True:
                    found_at = current_search_block.find(header_bytes, current_pos_in_block)
                    if found_at == -1: break
                    absolute_file_offset = offset - len(previous_chunk) + found_at
                    current_pos_in_block = found_at + header_len
                    carved_data_segments = [current_search_block[found_at:]]
                    current_carved_size = len(carved_data_segments[0]); file_is_complete = False
                    main_fd_pos_before_carve_readahead = fileD.tell()
                    if footer_bytes:
                        footer_pos_in_initial = carved_data_segments[0].find(footer_bytes)
                        if footer_pos_in_initial != -1:
                            carved_data_segments = [carved_data_segments[0][:footer_pos_in_initial + len(footer_bytes)]]
                            file_is_complete = True
                        else:
                            max_read_ahead_bytes = block_size * 20
                            if scan_mode == "deep": max_read_ahead_bytes = block_size * 100
                            while current_carved_size < max_read_ahead_bytes:
                                if stop_event.is_set(): break
                                next_block_for_carving = fileD.read(block_size)
                                if not next_block_for_carving: break
                                carved_data_segments.append(next_block_for_carving)
                                current_carved_size += len(next_block_for_carving)
                                temp_concat_for_footer = b"".join(carved_data_segments)
                                footer_final_pos = temp_concat_for_footer.find(footer_bytes)
                                if footer_final_pos != -1:
                                    carved_data_segments = [temp_concat_for_footer[:footer_final_pos + len(footer_bytes)]]
                                    file_is_complete = True; break
                    else:
                        max_size_for_no_footer = block_size * 30
                        if ftype_key == "MKV": max_size_for_no_footer = block_size * 100
                        if current_carved_size < max_size_for_no_footer and current_carved_size < block_size * 2 :
                             for _ in range(10):
                                if stop_event.is_set() or current_carved_size >= max_size_for_no_footer: break
                                next_block_for_carving = fileD.read(block_size)
                                if not next_block_for_carving: break
                                carved_data_segments.append(next_block_for_carving)
                                current_carved_size += len(next_block_for_carving)
                        final_carved_no_footer = b"".join(carved_data_segments)
                        if len(final_carved_no_footer) > max_size_for_no_footer:
                            carved_data_segments = [final_carved_no_footer[:max_size_for_no_footer]]
                        else: carved_data_segments = [final_carved_no_footer]
                        file_is_complete = True
                    fileD.seek(main_fd_pos_before_carve_readahead)
                    if file_is_complete:
                        final_file_binary_data = b"".join(carved_data_segments)
                        if not final_file_binary_data.startswith(header_bytes): continue
                        file_sha256_hash = calculate_hash(final_file_binary_data)
                        generated_filename = f"{ftype_key}_{absolute_file_offset:x}_{file_sha256_hash[:8]}{file_extension}"
                        extracted_metadata_dict = {}
                        if metadata_extraction_func:
                            try: extracted_metadata_dict = metadata_extraction_func(final_file_binary_data)
                            except Exception as e_meta_extract: extracted_metadata_dict = {"metadata_extraction_error": str(e_meta_extract)}
                        cand_display_name = extracted_metadata_dict.get("embedded_title")
                        if cand_display_name and isinstance(cand_display_name, str) and len(cand_display_name.strip()) > 3:
                            sane_title_part = "".join(c if c.isalnum() or c in (' ', '_', '-') else '_' for c in cand_display_name.strip()[:50])
                            display_filename = f"{sane_title_part.strip()}_{file_sha256_hash[:6]}{file_extension}"
                        else: display_filename = generated_filename
                        file_information_for_list = {"offset": absolute_file_offset, "data_hash": file_sha256_hash,
                            "generated_name": generated_filename, "display_name": display_filename, "type": ftype_key,
                            "size": len(final_file_binary_data), "discovery_time": datetime.now().isoformat(),
                            "embedded_title": extracted_metadata_dict.get("embedded_title"),
                            "embedded_creation_date": extracted_metadata_dict.get("embedded_creation_date"),
                            "embedded_modified_date": extracted_metadata_dict.get("embedded_modified_date"),
                            "other_metadata": extracted_metadata_dict}
                        recovered_files_data_store[file_sha256_hash] = final_file_binary_data
                        recovered_files_list_temp.append(file_information_for_list)
                        files_found_count +=1
                        if listbox_update_callback: listbox_update_callback(file_information_for_list)
        previous_chunk = chunk[-overlap:] if overlap > 0 and len(chunk) > overlap else chunk if overlap > 0 else b""
        offset += len(chunk) - (len(previous_chunk) if previous_chunk is chunk and len(chunk) > overlap else 0)
        if progress_callback and total_size: progress_callback(offset / total_size if total_size else 0, False)
        if scan_mode == "deep" and files_found_count > 0 and files_found_count % 10 == 0: time.sleep(0.01)
    scan_end_time = datetime.now(); scan_duration = (scan_end_time - scan_start_time).total_seconds()
    print(f"Scan ({scan_mode}) completed in {scan_duration:.2f} seconds. Found {files_found_count} potential files.")
    if fileD: fileD.close()
    if progress_callback: progress_callback(1.0, True if not stop_event.is_set() else False)
    return recovered_files_list_temp

current_preview_window = None
stop_scan_event = threading.Event()

def close_current_preview():
    global current_preview_window
    if current_preview_window is not None:
        try: current_preview_window.destroy()
        except Exception as e: print("Error closing preview window:", e)
        finally: current_preview_window = None

def _close_if_exists():
    global current_preview_window
    if current_preview_window:
        try: current_preview_window.destroy()
        except: pass
        current_preview_window = None

def show_metadata(metadata_dict_or_str):
    global current_preview_window; close_current_preview()
    current_preview_window = ctk.CTkToplevel(); current_preview_window.title("File Metadata")
    current_preview_window.geometry("600x400"); text_widget = tk.Text(current_preview_window, wrap="word", relief="sunken", borderwidth=1)
    text_widget.pack(expand=True, fill="both", padx=10, pady=10); scrollbar = ctk.CTkScrollbar(text_widget, command=text_widget.yview)
    scrollbar.pack(side="right", fill="y"); text_widget.configure(yscrollcommand=scrollbar.set)
    if isinstance(metadata_dict_or_str, dict):
        try: formatted_metadata = json.dumps(metadata_dict_or_str, indent=2, ensure_ascii=False)
        except TypeError: formatted_metadata = json.dumps(str(metadata_dict_or_str), indent=2, ensure_ascii=False)
    else: formatted_metadata = str(metadata_dict_or_str)
    text_widget.insert("1.0", formatted_metadata); text_widget.configure(state="disabled")
    current_preview_window.protocol("WM_DELETE_WINDOW", close_current_preview); current_preview_window.after(100, current_preview_window.lift)

def preview_image(data, metadata=None):
    global current_preview_window; close_current_preview()
    try:
        image = Image.open(io.BytesIO(data)); current_preview_window = ctk.CTkToplevel()
        current_preview_window.title("Image Preview"); current_preview_window.geometry("800x700")
        tabview = ctk.CTkTabview(current_preview_window, width=780, height=680); tabview.pack(expand=True, fill="both", padx=10, pady=10)
        tab_image = tabview.add("Image"); img_frame = ctk.CTkFrame(tab_image, fg_color="transparent")
        img_frame.pack(expand=True, fill="both"); max_w, max_h = 750, 550; img_w, img_h = image.size
        ratio = min(max_w/img_w, max_h/img_h) if img_w > 0 and img_h > 0 else 1
        new_w, new_h = int(img_w * ratio), int(img_h * ratio)
        image.thumbnail((new_w, new_h), Image.LANCZOS); tk_img = ImageTk.PhotoImage(image)
        lbl = ctk.CTkLabel(img_frame, image=tk_img, text=""); lbl.image = tk_img; lbl.pack(padx=10, pady=10, anchor="center")
        if metadata:
            tab_meta = tabview.add("Metadata"); meta_text_widget = tk.Text(tab_meta, wrap="word", relief="sunken", borderwidth=1)
            meta_text_widget.pack(expand=True, fill="both", padx=5, pady=5); meta_scrollbar = ctk.CTkScrollbar(meta_text_widget, command=meta_text_widget.yview)
            meta_scrollbar.pack(side="right", fill="y"); meta_text_widget.configure(yscrollcommand=meta_scrollbar.set)
            try: formatted_metadata = json.dumps(metadata, indent=2, ensure_ascii=False)
            except TypeError: formatted_metadata = json.dumps(str(metadata), indent=2, ensure_ascii=False)
            meta_text_widget.insert("1.0", formatted_metadata); meta_text_widget.configure(state="disabled")
        current_preview_window.protocol("WM_DELETE_WINDOW", close_current_preview); current_preview_window.after(100, current_preview_window.lift)
    except Exception as e: messagebox.showerror("Preview Error", f"Cannot preview image: {e}");_close_if_exists()

def preview_text_internal(data, metadata=None, title="Text Preview (First 10KB)"):
    global current_preview_window; close_current_preview()
    try:
        text_content = data.decode('utf-8', errors='replace')[:10000]; current_preview_window = ctk.CTkToplevel()
        current_preview_window.title(title); current_preview_window.geometry("800x700")
        tabview = ctk.CTkTabview(current_preview_window,  width=780, height=680); tabview.pack(expand=True, fill="both", padx=10, pady=10)
        tab_text = tabview.add("Text Content"); text_widget = tk.Text(tab_text, wrap="word", relief="sunken", borderwidth=1)
        text_widget.pack(expand=True, fill="both", padx=5, pady=5); text_scrollbar = ctk.CTkScrollbar(text_widget, command=text_widget.yview)
        text_scrollbar.pack(side="right", fill="y"); text_widget.configure(yscrollcommand=text_scrollbar.set)
        text_widget.insert("1.0", text_content); text_widget.configure(state="disabled")
        if metadata:
            tab_meta = tabview.add("Metadata"); meta_widget = tk.Text(tab_meta, wrap="word", relief="sunken", borderwidth=1)
            meta_widget.pack(expand=True, fill="both", padx=5, pady=5); meta_scrollbar = ctk.CTkScrollbar(meta_widget, command=meta_widget.yview)
            meta_scrollbar.pack(side="right", fill="y"); meta_widget.configure(yscrollcommand=meta_scrollbar.set)
            try: formatted_metadata = json.dumps(metadata, indent=2, ensure_ascii=False)
            except TypeError: formatted_metadata = json.dumps(str(metadata), indent=2, ensure_ascii=False)
            meta_widget.insert("1.0", formatted_metadata); meta_widget.configure(state="disabled")
        current_preview_window.protocol("WM_DELETE_WINDOW", close_current_preview); current_preview_window.after(100, current_preview_window.lift)
    except Exception as e: messagebox.showerror("Preview Error", f"Cannot preview text: {e}"); _close_if_exists()

def preview_external_file(data, metadata, file_extension, file_type_name):
    global current_preview_window; close_current_preview(); tmp_path = ""
    try:
        temp_dir = tempfile.gettempdir()
        tmp_path = os.path.join(temp_dir, f"preview_{file_type_name.lower()}_{hashlib.md5(data[:1024]).hexdigest()}{file_extension}")
        with open(tmp_path, "wb") as tmp_file: tmp_file.write(data)
        os.startfile(tmp_path)
        current_preview_window = ctk.CTkToplevel(); current_preview_window.title(f"{file_type_name} Preview Launched")
        current_preview_window.geometry("500x300")
        tabview = ctk.CTkTabview(current_preview_window, width=480, height=280); tabview.pack(expand=True, fill="both", padx=10, pady=10)
        tab_info = tabview.add("Info")
        info_text = (f"{file_type_name} file launched in external player/viewer.\n\n"
                     f"Temporary file: {tmp_path}\nThis file may be cleaned up by the OS or can be deleted manually after viewing.")
        lbl = ctk.CTkLabel(tab_info, text=info_text, wraplength=400, justify="left"); lbl.pack(padx=10, pady=10)
        if metadata:
            tab_meta = tabview.add("Metadata"); text_widget = tk.Text(tab_meta, wrap="word", relief="sunken", borderwidth=1)
            text_widget.pack(expand=True, fill="both", padx=5, pady=5); meta_scrollbar = ctk.CTkScrollbar(text_widget, command=text_widget.yview)
            meta_scrollbar.pack(side="right", fill="y"); text_widget.configure(yscrollcommand=meta_scrollbar.set)
            try: formatted_metadata = json.dumps(metadata, indent=2, ensure_ascii=False)
            except TypeError: formatted_metadata = json.dumps(str(metadata), indent=2, ensure_ascii=False)
            text_widget.insert("1.0", formatted_metadata); text_widget.configure(state="disabled")
        def on_external_preview_close():
            print(f"{file_type_name} Preview info window closed. Temp file at: {tmp_path}")
            close_current_preview()
        current_preview_window.protocol("WM_DELETE_WINDOW", on_external_preview_close)
        current_preview_window.after(100, current_preview_window.lift)
    except FileNotFoundError:
         messagebox.showerror("Preview Error", f"Cannot preview {file_type_name}: No application associated with {file_extension} files.")
         if tmp_path and os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except Exception as e_del: print(f"Error deleting temp file {tmp_path}: {e_del}")
         _close_if_exists()
    except Exception as e:
        messagebox.showerror("Preview Error", f"Cannot preview {file_type_name}: {e}")
        if tmp_path and os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except Exception as e_del: print(f"Error deleting temp file {tmp_path}: {e_del}")
        _close_if_exists()

def preview_mkv(data, metadata=None): preview_external_file(data, metadata, ".mkv", "MKV")
def preview_pdf_external(data, metadata=None): preview_external_file(data, metadata, ".pdf", "PDF")

ctk.set_appearance_mode("System"); ctk.set_default_color_theme("blue")
root = ctk.CTk(); root.title("Enhanced File Recovery Tool"); root.geometry("1100x850")
recovered_files_data_store = {}; recovered_files_display_list = []
output_dir = ""; current_scan_thread = None
main_frame = ctk.CTkFrame(root); main_frame.pack(padx=10, pady=10, fill="both", expand=True)

# --- SỬA THỨ TỰ PACK: PACK COMMON CONTROLS TRƯỚC ---
common_controls_frame = ctk.CTkFrame(main_frame) # Cha là main_frame
common_controls_frame.pack(pady=10, fill="x", padx=15, side="bottom") # Đặt ở dưới cùng

button_font = ("Segoe UI", 14)
recover_button = ctk.CTkButton(common_controls_frame, text="Recover Selected Files",
    command=lambda: recover_selected_files_from_active_tab(), height=40, width=220, font=button_font)
recover_button.pack(side="left", padx=10, pady=10)
report_button = ctk.CTkButton(common_controls_frame, text="Save Scan Report",
    command=lambda: save_scan_report_from_active_tab(), height=40, width=200, font=button_font)
report_button.pack(side="left", padx=10, pady=10)
# --- KẾT THÚC COMMON CONTROLS ---


# --- PACK TAB VIEW SAU KHI COMMON CONTROLS ĐÃ Ở DƯỚI ---
tab_view = ctk.CTkTabview(main_frame) # Cha là main_frame
tab_view.pack(padx=5, pady=5, fill="both", expand=True) # Mặc định side="top", chiếm phần còn lại

normal_scan_tab = tab_view.add("Normal Scan")
deep_scan_tab = tab_view.add("Deep Scan (Sector by Sector)")

def create_scan_ui(parent_tab, scan_mode_name):
    # ... (Nội dung hàm create_scan_ui giữ nguyên như trước) ...
    scan_ui_frame = ctk.CTkFrame(parent_tab, fg_color="transparent")
    scan_ui_frame.pack(fill="both", expand=True, padx=5, pady=5)
    drive_frame = ctk.CTkFrame(scan_ui_frame); drive_frame.pack(pady=5, fill="x", padx=10)
    ctk.CTkLabel(drive_frame, text="Select Drive:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    drive_list = get_available_drives()
    drive_var = ctk.StringVar(value=drive_list[0] if drive_list else "No drives found")
    drive_combobox = ctk.CTkComboBox(drive_frame, values=drive_list, variable=drive_var, width=150)
    drive_combobox.grid(row=0, column=1, padx=5, pady=5, sticky="w")
    if not drive_list: drive_combobox.configure(state="disabled")
    types_frame = ctk.CTkFrame(scan_ui_frame); types_frame.pack(pady=5, fill="x", padx=10)
    ctk.CTkLabel(types_frame, text="Select File Types:").pack(side="left", padx=5, pady=5)
    selected_types_vars = {}
    file_types_canvas_container = ctk.CTkFrame(types_frame, fg_color="transparent")
    file_types_canvas_container.pack(side="left", fill="x", expand=True, padx=5)
    file_types_canvas = ctk.CTkCanvas(file_types_canvas_container, height=40, highlightthickness=0)
    scrollable_types_frame = ctk.CTkFrame(file_types_canvas, fg_color="transparent")
    file_types_scrollbar = ctk.CTkScrollbar(file_types_canvas_container, orientation="horizontal", command=file_types_canvas.xview)
    scrollable_types_frame.bind("<Configure>", lambda e: file_types_canvas.configure(scrollregion=file_types_canvas.bbox("all")))
    file_types_canvas.create_window((0, 0), window=scrollable_types_frame, anchor="nw")
    file_types_canvas.configure(xscrollcommand=file_types_scrollbar.set)
    file_types_canvas.pack(side="top", fill="x", expand=True)
    if len(FILE_SIGNATURES) > 4: file_types_scrollbar.pack(side="bottom", fill="x")
    for i, ftype in enumerate(FILE_SIGNATURES.keys()):
        var = tk.IntVar(value=1); chk = ctk.CTkCheckBox(scrollable_types_frame, text=ftype, variable=var)
        chk.pack(side="left", padx=5, pady=2); selected_types_vars[ftype] = var
    output_frame = ctk.CTkFrame(scan_ui_frame); output_frame.pack(pady=5, fill="x", padx=10)
    def select_output_directory_tab():
        global output_dir
        selected_dir = filedialog.askdirectory(title="Select Output Directory")
        if selected_dir: output_dir = selected_dir; output_label.configure(text=f"Output: {output_dir}" if len(output_dir) < 60 else f"Output: ...{output_dir[-55:]}")
        elif not output_dir: output_label.configure(text="Output Directory: Not selected")
    output_btn = ctk.CTkButton(output_frame, text="Select Output Folder", command=select_output_directory_tab, width=180)
    output_btn.grid(row=0, column=0, padx=5, pady=5, sticky="w")
    output_label_text = "Output Directory: Not selected"
    if output_dir: output_label_text = f"Output: {output_dir}" if len(output_dir) < 60 else f"Output: ...{output_dir[-55:]}"
    output_label = ctk.CTkLabel(output_frame, text=output_label_text, wraplength=600, justify="left")
    output_label.grid(row=0, column=1, padx=5, pady=5, sticky="w"); output_frame.columnconfigure(1, weight=1)
    scan_controls_frame = ctk.CTkFrame(scan_ui_frame); scan_controls_frame.pack(pady=5, fill="x", padx=10)
    scan_button = ctk.CTkButton(scan_controls_frame, text=f"Start {scan_mode_name} Scan", width=180)
    scan_button.grid(row=0, column=0, padx=5, pady=5, sticky="w")
    stop_button = ctk.CTkButton(scan_controls_frame, text="Stop Scan", state="disabled", command=lambda: stop_scan_event.set(), width=120)
    stop_button.grid(row=0, column=1, padx=5, pady=5, sticky="w")
    progress_bar = ctk.CTkProgressBar(scan_controls_frame); progress_bar.set(0)
    progress_bar.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
    progress_label = ctk.CTkLabel(scan_controls_frame, text="Status: Idle", wraplength=700, justify="left")
    progress_label.grid(row=2, column=0, columnspan=3, padx=5, pady=2, sticky="w"); scan_controls_frame.columnconfigure(1, weight=1)
    listbox_frame = ctk.CTkFrame(scan_ui_frame); listbox_frame.pack(pady=5, fill="both", expand=True, padx=10)
    listbox = tk.Listbox(listbox_frame, selectmode=tk.EXTENDED, font=("Segoe UI", 10), relief="sunken", borderwidth=1)
    listbox_scrollbar_y = ctk.CTkScrollbar(listbox_frame, command=listbox.yview)
    listbox_scrollbar_x = ctk.CTkScrollbar(listbox_frame, command=listbox.xview, orientation="horizontal")
    listbox.configure(yscrollcommand=listbox_scrollbar_y.set, xscrollcommand=listbox_scrollbar_x.set)
    listbox_scrollbar_y.pack(side="right", fill="y"); listbox_scrollbar_x.pack(side="bottom", fill="x")
    listbox.pack(padx=0, pady=0, fill="both", expand=True)
    ui_elements = {"drive_var": drive_var, "selected_types_vars": selected_types_vars,
                   "output_label": output_label, "scan_button": scan_button, "stop_button": stop_button,
                   "progress_bar": progress_bar, "progress_label": progress_label, "listbox": listbox}
    cleaned_scan_mode_name = scan_mode_name.lower().replace(" (sector by sector)", "").replace(" ", "_")
    scan_button.configure(command=lambda: start_scan_wrapper(ui_elements, cleaned_scan_mode_name))
    return ui_elements

normal_scan_ui = create_scan_ui(normal_scan_tab, "Normal")
deep_scan_ui = create_scan_ui(deep_scan_tab, "Deep Scan (Sector by Sector)")


def get_active_tab_ui_elements():
    current_tab_name = tab_view.get()
    if current_tab_name == "Normal Scan": return normal_scan_ui
    elif current_tab_name == "Deep Scan (Sector by Sector)": return deep_scan_ui
    return None

def update_listbox_threaded(ui_elems, file_info_for_display):
    if ui_elems and ui_elems.get("listbox"):
        listbox = ui_elems["listbox"]; recovered_files_display_list.append(file_info_for_display)
        display_str = f"{file_info_for_display['display_name']} ({file_info_for_display['size']/(1024*1024):.2f} MB)"
        if file_info_for_display.get("embedded_creation_date"): display_str += f" [C: {file_info_for_display['embedded_creation_date'][:10]}]"
        elif file_info_for_display.get("embedded_modified_date"): display_str += f" [M: {file_info_for_display['embedded_modified_date'][:10]}]"
        display_str += f" - Off: {file_info_for_display['offset']:x}"
        listbox.insert(tk.END, display_str); listbox.see(tk.END)
        ui_elems["progress_label"].configure(text=f"Status: Scanning... Found {len(recovered_files_display_list)} files.")

def start_scan_wrapper(ui_elems, scan_type_str):
    global current_scan_thread, recovered_files_display_list, recovered_files_data_store
    stop_scan_event.clear(); ui_elems["listbox"].delete(0, tk.END)
    recovered_files_display_list.clear(); recovered_files_data_store.clear()
    ui_elems["scan_button"].configure(state="disabled"); ui_elems["stop_button"].configure(state="normal")
    ui_elems["progress_bar"].set(0); ui_elems["progress_label"].configure(text="Status: Starting scan...")
    selected_drive = ui_elems["drive_var"].get()
    if not selected_drive or selected_drive == "No drives found":
        messagebox.showerror("Error", "No drive selected or no drives available.")
        ui_elems["scan_button"].configure(state="normal"); ui_elems["stop_button"].configure(state="disabled"); return
    raw_drive_path = r"\\.\{}".format(selected_drive[:2])
    total_size = get_drive_total_size(selected_drive)
    if total_size is None:
        messagebox.showerror("Error", f"Could not get size for drive {selected_drive}. Ensure it's accessible.")
        ui_elems["scan_button"].configure(state="normal"); ui_elems["stop_button"].configure(state="disabled"); return
    selected_file_types_keys = [ftype for ftype, var in ui_elems["selected_types_vars"].items() if var.get() == 1]
    if not selected_file_types_keys:
        messagebox.showwarning("No File Types", "Please select at least one file type to scan for.")
        ui_elems["scan_button"].configure(state="normal"); ui_elems["stop_button"].configure(state="disabled"); return
    if not output_dir:
        messagebox.showwarning("Output Directory", "Please select an output directory before starting the scan.")
        ui_elems["scan_button"].configure(state="normal"); ui_elems["stop_button"].configure(state="disabled"); return
    def progress_update(value, is_complete_or_error=False):
        ui_elems["progress_bar"].set(value); current_status_text = ""
        if total_size:
            processed_mb = value * total_size / (1024*1024); total_mb = total_size / (1024*1024)
            current_status_text = f"Progress: {processed_mb:.2f} MB / {total_mb:.2f} MB ({value*100:.1f}%)"
        else: current_status_text = f"Progress: {value*100:.1f}%"
        if not is_complete_or_error: ui_elems["progress_label"].configure(text=current_status_text + f" Found: {len(recovered_files_display_list)}")
        if is_complete_or_error:
            final_status_message = "Scan completed."
            if stop_scan_event.is_set(): final_status_message = "Scan stopped by user."
            elif value < 0.99: final_status_message = "Scan stopped or encountered an error."
            ui_elems["progress_label"].configure(text=f"Status: {final_status_message} Found {len(recovered_files_display_list)} files.")
            ui_elems["scan_button"].configure(state="normal"); ui_elems["stop_button"].configure(state="disabled")
    scan_mode_arg = "deep" if "deep" in scan_type_str else "normal"
    def threaded_scan_task():
        nonlocal total_size
        scan_drive_internal(raw_drive_path, total_size, selected_file_types_keys,
                            lambda val, complete: root.after(0, progress_update, val, complete),
                            stop_event=stop_scan_event,
                            listbox_update_callback=lambda info: root.after(0, update_listbox_threaded, ui_elems, info),
                            scan_mode=scan_mode_arg)
    current_scan_thread = threading.Thread(target=threaded_scan_task, daemon=True); current_scan_thread.start()

def on_item_double_click(event):
    active_ui = get_active_tab_ui_elements();
    if not active_ui: return
    listbox = active_ui["listbox"]; selection = listbox.curselection()
    if not selection: return
    selected_index = selection[0]
    if 0 <= selected_index < len(recovered_files_display_list):
        file_info_display = recovered_files_display_list[selected_index]
        file_hash = file_info_display["data_hash"]
        file_data = recovered_files_data_store.get(file_hash)
        if not file_data: messagebox.showerror("Error", "File data not found in store. Cannot preview."); return
        file_type = file_info_display["type"]; metadata_for_preview = file_info_display.get("other_metadata")
        if file_type == "JPEG": preview_image(file_data, metadata_for_preview)
        elif file_type == "MKV": preview_mkv(file_data, metadata_for_preview)
        elif file_type == "PDF": preview_pdf_external(file_data, metadata_for_preview)
        else: preview_text_internal(file_data, metadata_for_preview, title=f"{file_type} Preview (Text)")

normal_scan_ui["listbox"].bind("<Double-1>", on_item_double_click)
deep_scan_ui["listbox"].bind("<Double-1>", on_item_double_click)
context_menu = tk.Menu(root, tearoff=0)
def show_selected_metadata_from_active_tab():
    active_ui = get_active_tab_ui_elements();
    if not active_ui: return
    listbox = active_ui["listbox"]; selection = listbox.curselection()
    if selection:
        selected_index = selection[0]
        if 0 <= selected_index < len(recovered_files_display_list):
            file_info = recovered_files_display_list[selected_index]
            show_metadata(file_info.get("other_metadata", "No detailed metadata available or error during extraction."))
context_menu.add_command(label="Show Metadata", command=show_selected_metadata_from_active_tab)
def show_context_menu(event):
    active_ui = get_active_tab_ui_elements();
    if not active_ui: return
    listbox = active_ui["listbox"]
    try:
        if listbox.curselection(): context_menu.tk_popup(event.x_root, event.y_root)
    finally: context_menu.grab_release()
normal_scan_ui["listbox"].bind("<Button-3>", show_context_menu)
deep_scan_ui["listbox"].bind("<Button-3>", show_context_menu)

def recover_selected_files_from_active_tab():
    global output_dir; active_ui = get_active_tab_ui_elements();
    if not active_ui: messagebox.showerror("Error", "No active scan tab found."); return
    listbox = active_ui["listbox"]
    if not output_dir: messagebox.showwarning("No Output Folder", "Please select an output folder first."); return
    selected_indices = listbox.curselection()
    if not selected_indices: messagebox.showinfo("No Selection", "Please select at least one file to recover."); return
    success_count = 0; failed_files = []
    for idx in selected_indices:
        if 0 <= idx < len(recovered_files_display_list):
            f_info = recovered_files_display_list[idx]; f_hash = f_info["data_hash"]
            f_data = recovered_files_data_store.get(f_hash)
            f_name_to_save = f_info["display_name"]
            if not f_name_to_save or f_name_to_save == f_info["generated_name"]: f_name_to_save = f_info["generated_name"]
            if not f_data: failed_files.append(f_name_to_save + " (data missing in store)"); continue
            try:
                os.makedirs(output_dir, exist_ok=True)
                sane_fname_chars = "".join(c if c.isalnum() or c in (' ','.','_','-') else '_' for c in f_name_to_save)
                base_name_rec, ext_rec = os.path.splitext(sane_fname_chars)
                if not ext_rec and f_info.get("type"):
                    default_ext = FILE_SIGNATURES.get(f_info["type"], {}).get("extension", ".dat")
                    ext_rec = default_ext
                final_sane_filename = base_name_rec.strip() + ext_rec
                output_path = os.path.join(output_dir, final_sane_filename); counter = 1
                temp_basename, temp_ext = os.path.splitext(final_sane_filename)
                while os.path.exists(output_path):
                    output_path = os.path.join(output_dir, f"{temp_basename}_{counter}{temp_ext}"); counter += 1
                with open(output_path, "wb") as f: f.write(f_data)
                meta_to_save = f_info.get("other_metadata")
                if meta_to_save and not meta_to_save.get("error") and not meta_to_save.get("metadata_extraction_error"):
                    meta_path = output_path + ".meta.json"
                    with open(meta_path, "w", encoding='utf-8') as f_meta: json.dump(meta_to_save, f_meta, indent=2, ensure_ascii=False)
                success_count += 1
            except Exception as e: failed_files.append(f"{f_name_to_save} ({str(e)})"); print(f"Error saving file {f_name_to_save}: {e}")
    result_message = f"Successfully recovered {success_count} out of {len(selected_indices)} selected files."
    if failed_files: result_message += f"\n\nFailed to recover:\n" + "\n".join(failed_files); messagebox.showwarning("Recovery Partially Successful", result_message)
    else: messagebox.showinfo("Recovery Complete", result_message)

def save_scan_report_from_active_tab():
    active_ui = get_active_tab_ui_elements();
    if not active_ui: messagebox.showerror("Error", "No active scan tab found."); return
    if not recovered_files_display_list: messagebox.showwarning("No Data", "No scan data available to save."); return
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")], title="Save Scan Report As")
    if file_path:
        try:
            drive_scanned = active_ui["drive_var"].get()
            scanned_types_keys = [ftype for ftype, var in active_ui["selected_types_vars"].items() if var.get() == 1]
            report_data = {"scan_report_version": "1.2", "scan_timestamp": datetime.now().isoformat(),
                           "scanned_drive": drive_scanned, "selected_file_types_for_scan": scanned_types_keys,
                           "total_files_found_in_session": len(recovered_files_display_list),
                           "recovered_files_summary": [
                               {"generated_name": f["generated_name"], "display_name_suggestion": f["display_name"],
                                "type": f["type"], "size_bytes": f["size"], "sha256_hash": f["data_hash"],
                                "found_at_offset_hex": f"{f['offset']:x}", "discovery_timestamp": f["discovery_time"],
                                "embedded_title": f.get("embedded_title"),
                                "embedded_creation_date": f.get("embedded_creation_date"),
                                "embedded_modified_date": f.get("embedded_modified_date"),
                                "detailed_metadata_preview": {k: str(v)[:200] for k, v in f.get("other_metadata", {}).items() if not isinstance(v, (Image.Image, bytes))}
                               } for f in recovered_files_display_list]}
            with open(file_path, "w", encoding='utf-8') as f: json.dump(report_data, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Report Saved", f"Scan report successfully saved to:\n{file_path}")
        except Exception as e: messagebox.showerror("Save Report Error", f"Failed to save scan report: {str(e)}")

def on_closing():
    global current_scan_thread
    if messagebox.askokcancel("Quit", "Do you want to quit the File Recovery Tool?"):
        stop_scan_event.set()
        if current_scan_thread and current_scan_thread.is_alive():
            print("Waiting for scan thread to finish...")
            current_scan_thread.join(timeout=1)
        close_current_preview(); root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing); root.mainloop()
