import os
import msvcrt
import win32file, win32con, win32api
import threading
import io
import tempfile
import subprocess # Mặc dù được import, nhưng không được sử dụng trong mã hiện tại. Cân nhắc xóa nếu không cần.
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
        "footer": None,  # MKV footers can be complex and variable, often relying on EBML structure.
                         # For simplicity, we might limit scan size or use more advanced parsing.
        "extension": ".mkv",
        "metadata_func": lambda data: extract_mkv_metadata(data)
    }
    # Bạn có thể thêm các loại tệp khác vào đây
    # Ví dụ:
    # "PNG": {
    #     "headers": [b'\x89PNG\r\n\x1a\n'],
    #     "footer": b'IEND\xaeB`\x82',
    #     "extension": ".png",
    #     "metadata_func": lambda data: extract_image_metadata(data) # Giả sử PNG có thể dùng chung hàm metadata hình ảnh
    # },
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
                    if k in ExifTags.TAGS and isinstance(v, (bytes, str, int, float, tuple, list, dict)) # Đảm bảo giá trị có thể serialize JSON
                }
                # Chuyển đổi bytes sang string nếu có thể
                for key, value in exif.items():
                    if isinstance(value, bytes):
                        try:
                            exif[key] = value.decode('utf-8', errors='replace')
                        except:
                             exif[key] = repr(value) # Nếu không decode được thì dùng repr
                metadata["exif"] = exif
        except AttributeError: # Một số định dạng ảnh (vd: PNG) không có _getexif
             pass
        except Exception:
            pass # Bỏ qua lỗi EXIF cụ thể

        return metadata
    except Exception as e:
        return {"error": f"Could not process image data: {str(e)}"}

def extract_pdf_metadata(data):
    try:
        # Simple PDF metadata extraction - cải thiện để tránh lỗi và linh hoạt hơn
        text_content = ""
        try:
            # Thử decode với các encoding phổ biến cho PDF metadata
            encodings_to_try = ['ascii', 'utf-8', 'latin-1']
            for enc in encodings_to_try:
                try:
                    text_content = data[:2048].decode(enc) # Giới hạn vùng đọc để tìm metadata
                    break
                except UnicodeDecodeError:
                    continue
            if not text_content: # Nếu không decode được, dùng errors='ignore'
                 text_content = data[:2048].decode('ascii', errors='ignore')

        except Exception as decode_err:
            return {"error": f"PDF decode error: {str(decode_err)}"}


        metadata = {}
        import re # Sử dụng regex để trích xuất an toàn hơn

        # Tìm Title
        title_match = re.search(r'/Title\s*\(([^)]+)\)', text_content)
        if title_match:
            metadata['title'] = title_match.group(1).strip()

        # Tìm Author
        author_match = re.search(r'/Author\s*\(([^)]+)\)', text_content)
        if author_match:
            metadata['author'] = author_match.group(1).strip()
        
        # Tìm Creator
        creator_match = re.search(r'/Creator\s*\(([^)]+)\)', text_content)
        if creator_match:
            metadata['creator'] = creator_match.group(1).strip()

        # Tìm Producer
        producer_match = re.search(r'/Producer\s*\(([^)]+)\)', text_content)
        if producer_match:
            metadata['producer'] = producer_match.group(1).strip()

        # Tìm CreationDate
        creation_date_match = re.search(r'/CreationDate\s*\(([^)]+)\)', text_content)
        if creation_date_match:
            metadata['creation_date'] = creation_date_match.group(1).strip()
            
        return metadata if metadata else {"info": "No common metadata fields found in the first 2KB"}
    except Exception as e:
        return {"error": str(e)}

def extract_mkv_metadata(data):
    try:
        # For MKV, we'd normally use a library like pymkv or ffprobe (via subprocess) for detailed metadata.
        # This is a placeholder.
        metadata = {
            "size_bytes": len(data),
            "type": "MKV (Matroska)",
            "note": "Basic check. Use external tools like MediaInfo or ffprobe for detailed metadata.",
            "first_bytes_hex": data[:16].hex() # Hiển thị một vài byte đầu tiên dưới dạng hex
        }
        # Attempt to find some common EBML elements (very basic)
        if b'matroska' in data[:1024].lower(): # Tìm chuỗi 'matroska' trong 1KB đầu
            metadata['ebml_matroska_found'] = True
        if b'Segment' in data[:4096]:
             metadata['ebml_segment_likely_present'] = True
        return metadata
    except Exception as e:
        return {"error": str(e)}

def calculate_hash(data):
    """Calculate SHA-256 hash of data"""
    return hashlib.sha256(data).hexdigest()

def get_available_drives():
    drives = []
    drive_bits = win32api.GetLogicalDrives()
    for i in range(26):
        letter = chr(ord('A') + i)
        if drive_bits & 1:
            drive_path = f"{letter}:\\"
            try:
                # SỬA Ở ĐÂY: Sử dụng win32file.GetDriveTypeW
                drive_type = win32file.GetDriveTypeW(drive_path)
                # Chỉ thêm các ổ đĩa cố định, ổ đĩa di động, CD-ROM.
                if drive_type in [win32con.DRIVE_FIXED, win32con.DRIVE_REMOVABLE, win32con.DRIVE_CDROM]:
                    drives.append(drive_path)
            except win32api.error as e:
                # Bỏ qua lỗi nếu không lấy được thông tin ổ đĩa (ví dụ: ổ đĩa trống hoặc không sẵn sàng)
                # print(f"Could not get drive type for {drive_path}: {e}") # Bỏ comment nếu muốn debug
                pass
        drive_bits >>= 1
    return drives

def get_drive_total_size(drive_letter):
    try:
        # Đảm bảo drive_letter là một đường dẫn hợp lệ cho GetDiskFreeSpaceEx
        # Ví dụ: "C:\\" thay vì chỉ "C:"
        path = drive_letter
        if not path.endswith("\\"):
            path += "\\"
        _, totalBytes, _ = win32api.GetDiskFreeSpaceEx(path)
        return totalBytes
    except Exception as e:
        print(f"Error getting size for drive {drive_letter}: {e}")
        return None

def open_raw_drive(drive_letter):
    # Tạo đường dẫn vật lý cho ổ đĩa (ví dụ: \\.\C:)
    raw_drive_path = r"\\.\{}".format(drive_letter.rstrip("\\"))
    try:
        handle = win32file.CreateFile(
            raw_drive_path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_ATTRIBUTE_NORMAL | win32con.FILE_FLAG_SEQUENTIAL_SCAN, # Thêm cờ để tối ưu quét tuần tự
            None
        )
    except win32api.error as e:
        # Cung cấp thông báo lỗi cụ thể hơn
        if e.winerror == 5: # Access Denied
            raise Exception(f"Access Denied. Please run the tool as Administrator to open drive {raw_drive_path}.")
        elif e.winerror == 2: # The system cannot find the file specified (drive not ready/exists)
            raise Exception(f"Drive {raw_drive_path} not found or not ready. Error code: {e.winerror}")
        else:
            raise Exception(f"Failed to open drive {raw_drive_path} using CreateFile. Error code: {e.winerror}, Message: {e.strerror}")


    try:
        # Chuyển đổi handle sang file descriptor của C runtime
        fd = msvcrt.open_osfhandle(handle.Detach(), os.O_RDONLY | os.O_BINARY) # Thêm os.O_BINARY
        # Mở file descriptor như một file object Python ở chế độ binary read
        fileD = os.fdopen(fd, 'rb')
    except Exception as e:
        # Đóng handle nếu chuyển đổi thất bại để tránh rò rỉ tài nguyên
        if 'handle' in locals() and handle != win32file.INVALID_HANDLE_VALUE:
             win32api.CloseHandle(handle)
        raise Exception(f"Failed to convert handle to file object for {raw_drive_path}: {e}")

    return fileD

def scan_drive(raw_drive_path_letter, total_size, selected_types, progress_callback, scan_mode="Chuyên sâu"):
    recovered_files_details = [] # Đổi tên để rõ ràng hơn
    fileD = None # Khởi tạo fileD là None

    try:
        fileD = open_raw_drive(raw_drive_path_letter)
    except Exception as e:
        # Sử dụng root.after để đảm bảo messagebox được hiển thị trong luồng chính của Tkinter
        root.after(0, lambda: messagebox.showerror("Lỗi Mở Ổ Đĩa", f"Không thể mở ổ đĩa: {e}\n"
                                                                "Hãy chắc chắn bạn đã chạy ứng dụng với quyền Administrator."))
        return []

    # Optimized scanning with larger block size (4 MB) and memoryview
    block_size = 4 * 1024 * 1024
    max_header_len = 0
    if selected_types: # Đảm bảo selected_types không rỗng
        max_header_len = max(len(h) for f_type in selected_types for h in FILE_SIGNATURES[f_type]["headers"])

    overlap = max_header_len - 1 if max_header_len > 0 else 0


    offset = 0
    previous_chunk_overlap = b"" # Đổi tên để rõ ràng hơn
    scan_start_time = datetime.now()
    processed_hashes = set() # Set để lưu trữ hash của các tệp đã xử lý, tránh trùng lặp

    # Xác định giới hạn kích thước tệp dựa trên chế độ quét cho các tệp không có footer
    # Chế độ "Nhanh" sẽ giới hạn kích thước đọc ít hơn để tăng tốc
    max_blocks_no_footer = 20 if scan_mode == "Chuyên sâu" else 5 # Ví dụ: 20 blocks cho chuyên sâu, 5 cho nhanh

    current_file_data = None
    current_file_type = None
    current_file_start_offset = -1

    while True:
        try:
            chunk = fileD.read(block_size)
        except io.UnsupportedOperation: # Xử lý nếu ổ đĩa không hỗ trợ seek (hiếm khi xảy ra với raw disk)
            root.after(0, lambda: messagebox.showerror("Lỗi Đọc Ổ Đĩa", "Ổ đĩa không hỗ trợ hoạt động đọc theo khối."))
            break
        except Exception as e:
            root.after(0, lambda: messagebox.showerror("Lỗi Đọc Ổ Đĩa", f"Lỗi khi đọc từ ổ đĩa: {e}"))
            break

        if not chunk:
            break # Kết thúc vòng lặp nếu không còn dữ liệu

        search_buffer = previous_chunk_overlap + chunk
        m_search_buffer = memoryview(search_buffer)


        for f_type in selected_types:
            sig_details = FILE_SIGNATURES.get(f_type)
            if not sig_details or not sig_details["headers"]:
                continue

            for header_bytes in sig_details["headers"]:
                idx = -1
                while True:
                    # Tìm header trong buffer, bắt đầu từ vị trí sau lần tìm thấy trước đó
                    try:
                        idx = search_buffer.find(header_bytes, idx + 1)
                    except Exception: # Bắt lỗi chung nếu find thất bại
                        break

                    if idx == -1:
                        break # Không tìm thấy header nữa trong buffer này

                    # Tính toán offset tuyệt đối của header
                    # offset là vị trí bắt đầu của `chunk` hiện tại trên ổ đĩa
                    # `len(previous_chunk_overlap)` là độ dài của phần dữ liệu từ chunk trước
                    # `idx` là vị trí của header trong `search_buffer`
                    absolute_start_offset = offset - len(previous_chunk_overlap) + idx
                    
                    # Tạo một hash tạm thời từ một phần nhỏ dữ liệu để kiểm tra trùng lặp nhanh
                    # Điều này giúp tránh việc đọc và hash toàn bộ file nếu nó có vẻ giống file đã tìm thấy
                    potential_file_start_data = m_search_buffer[idx : idx + min(len(m_search_buffer) - idx, 1024)].tobytes()
                    quick_hash = calculate_hash(potential_file_start_data)

                    if quick_hash in processed_hashes:
                        continue # Bỏ qua nếu hash này đã được xử lý (có thể là file trùng)

                    file_data_list = [potential_file_start_data] # Bắt đầu thu thập dữ liệu tệp
                    
                    # Đọc thêm dữ liệu cho đến khi tìm thấy footer hoặc đạt giới hạn
                    # Bắt đầu từ cuối phần `search_buffer` đã có header
                    current_read_pos_in_drive = absolute_start_offset + len(potential_file_start_data)
                    fileD.seek(current_read_pos_in_drive) # Di chuyển con trỏ đọc của ổ đĩa

                    file_ended_with_footer = False
                    blocks_read_for_this_file = 0

                    if sig_details["footer"]:
                        # Đọc từng khối nhỏ để tìm footer hiệu quả hơn
                        small_block_size_for_footer_search = 64 * 1024 # 64KB
                        temp_buffer = b""
                        while True:
                            # Kiểm tra xem footer có trong temp_buffer không
                            footer_pos_in_temp = temp_buffer.find(sig_details["footer"])
                            if footer_pos_in_temp != -1:
                                # Footer tìm thấy, cắt dữ liệu đến cuối footer
                                file_data_list.append(temp_buffer[:footer_pos_in_temp + len(sig_details["footer"])])
                                file_ended_with_footer = True
                                break 
                            
                            # Nếu temp_buffer quá lớn mà không thấy footer, có thể là lỗi
                            if len(temp_buffer) > block_size * 2: # Giới hạn kích thước temp_buffer
                                break

                            next_small_block = fileD.read(small_block_size_for_footer_search)
                            if not next_small_block:
                                break # Hết dữ liệu trên ổ đĩa
                            
                            file_data_list.append(temp_buffer) # Thêm buffer cũ (nếu chưa thêm)
                            temp_buffer = next_small_block # buffer mới cho lần tìm kiếm tiếp theo

                            # Cập nhật vị trí đọc hiện tại
                            current_read_pos_in_drive += len(next_small_block)
                            blocks_read_for_this_file +=1 # Đếm theo số lần đọc khối nhỏ

                            # Giới hạn để tránh đọc vô hạn nếu footer không đúng hoặc tệp lớn
                            if blocks_read_for_this_file > (max_blocks_no_footer * (block_size // small_block_size_for_footer_search) * 2) : # Giới hạn lớn hơn cho file có footer
                                break
                        
                        if not file_ended_with_footer and temp_buffer:
                             file_data_list.append(temp_buffer) # Thêm phần còn lại nếu không tìm thấy footer

                    else: # Không có footer được định nghĩa
                        # Đọc một số lượng khối nhất định
                        for _ in range(max_blocks_no_footer -1): # -1 vì đã đọc 1 phần ở potential_file_start_data
                            next_block_data = fileD.read(block_size)
                            if not next_block_data:
                                break
                            file_data_list.append(next_block_data)
                            current_read_pos_in_drive += len(next_block_data)
                            if len(file_data_list) * block_size > 200 * 1024 * 1024 : # Giới hạn kích thước file tối đa 200MB cho file không footer
                                break


                    # Ghép các phần dữ liệu lại
                    complete_file_data = b"".join(file_data_list)
                    if not complete_file_data.startswith(header_bytes): # Kiểm tra lại header sau khi ghép
                        continue


                    full_file_hash = calculate_hash(complete_file_data)
                    if full_file_hash in processed_hashes:
                        continue # Bỏ qua nếu hash đầy đủ đã được xử lý
                    
                    processed_hashes.add(quick_hash) # Thêm hash nhanh để tránh xử lý lại
                    processed_hashes.add(full_file_hash) # Thêm hash đầy đủ


                    # Trích xuất metadata
                    metadata = {}
                    if "metadata_func" in sig_details:
                        try:
                            metadata = sig_details["metadata_func"](complete_file_data)
                        except Exception as e_meta:
                            metadata = {"metadata_extraction_error": str(e_meta)}
                    
                    file_name = f"{f_type}_{absolute_start_offset:x}_{full_file_hash[:8]}{sig_details['extension']}"
                    file_size = len(complete_file_data)

                    recovered_files_details.append({
                        "offset": absolute_start_offset,
                        "data": complete_file_data,
                        "name": file_name,
                        "type": f_type,
                        "hash": full_file_hash,
                        "metadata": metadata,
                        "size": file_size,
                        "discovery_time": datetime.now().isoformat()
                    })
                    
                    # Cập nhật UI trong luồng chính nếu cần (ví dụ: thêm vào listbox ngay lập tức)
                    # root.after(0, lambda item=recovered_files_details[-1]: listbox.insert(tk.END, f"{item['name']} ({item['size']/1024:.1f} KB)"))

                    # Di chuyển con trỏ đọc của ổ đĩa đến cuối tệp vừa tìm thấy
                    # để chunk tiếp theo bắt đầu từ đó
                    # Điều này quan trọng để tránh tìm lại cùng một header trong dữ liệu đã xử lý của tệp này
                    fileD.seek(absolute_start_offset + file_size)
                    offset = absolute_start_offset + file_size - (len(search_buffer) - (idx + file_size - (offset - len(previous_chunk_overlap))))
                    previous_chunk_overlap = b"" # Reset previous_chunk_overlap vì đã xử lý một tệp hoàn chỉnh
                    # Thoát khỏi vòng lặp header_bytes và f_type để đọc chunk mới vì đã tìm thấy một tệp
                    # và di chuyển con trỏ fileD.
                    # Tuy nhiên, cách tiếp cận này có thể bỏ sót các file chồng lấp.
                    # Cân nhắc lại logic này. Hiện tại, để đơn giản, ta sẽ break và đọc chunk mới.
                    # Một cách tiếp cận khác là tiếp tục tìm kiếm từ cuối file vừa tìm thấy trong `search_buffer`.
                    idx = idx + file_size -1 # Cập nhật idx để vòng lặp find tiếp theo bắt đầu sau file này
                    # break # Thoát vòng lặp header
                # if idx != -1: # Nếu một file được tìm thấy và xử lý từ một header
                #     break # Thoát vòng lặp file type
        
        # Cập nhật offset và previous_chunk_overlap cho lần đọc tiếp theo
        if chunk: # Đảm bảo chunk không rỗng
            bytes_processed_in_chunk = len(chunk) - (len(previous_chunk_overlap) if previous_chunk_overlap else 0)
            offset += len(chunk) # Offset là vị trí bắt đầu của chunk tiếp theo sẽ được đọc
            previous_chunk_overlap = chunk[-overlap:] if overlap > 0 else b""
        
        if progress_callback and total_size and total_size > 0:
            # offset ở đây là vị trí bắt đầu của chunk tiếp theo sẽ được đọc
            # nên nó đại diện cho lượng dữ liệu đã được đưa vào xử lý (đã đọc)
            current_progress_offset = min(fileD.tell(), total_size) # Sử dụng fileD.tell() cho vị trí chính xác hơn
            progress_callback(current_progress_offset)


    scan_end_time = datetime.now()
    scan_duration = (scan_end_time - scan_start_time).total_seconds()
    print(f"Scan completed in {scan_duration:.2f} seconds. Found {len(recovered_files_details)} potential files.")
    
    if fileD:
        try:
            fileD.close()
        except Exception as e_close:
            print(f"Error closing drive file: {e_close}")
            
    return recovered_files_details

# Global variable to hold the current preview window
current_preview_window = None

def close_current_preview():
    global current_preview_window
    if current_preview_window is not None:
        try:
            current_preview_window.destroy()
        except tk.TclError: # Có thể cửa sổ đã bị hủy rồi
            pass
        except Exception as e:
            print("Error closing preview window:", e)
        finally:
            current_preview_window = None

def show_metadata_window(metadata_dict, parent_window):
    """Hàm trợ giúp để hiển thị metadata trong một cửa sổ riêng biệt."""
    global current_preview_window
    close_current_preview() # Đóng cửa sổ preview cũ (nếu có)

    current_preview_window = ctk.CTkToplevel(parent_window)
    current_preview_window.title("File Metadata")
    current_preview_window.geometry("600x400")
    current_preview_window.transient(parent_window) # Giữ cửa sổ này ở trên cùng của cửa sổ cha
    current_preview_window.grab_set() # Chặn tương tác với cửa sổ cha

    text_widget = tk.Text(current_preview_window, wrap="word", font=("Segoe UI", 10))
    text_widget.pack(expand=True, fill="both", padx=10, pady=10)
    
    scrollbar = ctk.CTkScrollbar(current_preview_window, command=text_widget.yview)
    scrollbar.pack(side="right", fill="y")
    text_widget.configure(yscrollcommand=scrollbar.set)

    if isinstance(metadata_dict, dict):
        try:
            # Chuyển đổi bytes trong metadata sang string để hiển thị
            def convert_bytes_to_str(obj):
                if isinstance(obj, bytes):
                    try:
                        return obj.decode('utf-8', errors='replace')
                    except:
                        return repr(obj)
                elif isinstance(obj, dict):
                    return {k: convert_bytes_to_str(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_bytes_to_str(i) for i in obj]
                return obj

            cleaned_metadata = convert_bytes_to_str(metadata_dict)
            formatted_metadata = json.dumps(cleaned_metadata, indent=4, ensure_ascii=False)
        except TypeError as te:
            formatted_metadata = f"Error formatting metadata for JSON: {te}\n\nRaw metadata:\n{str(metadata_dict)}"
        except Exception as e:
            formatted_metadata = f"Could not format metadata: {e}\n\nRaw metadata:\n{str(metadata_dict)}"
    else:
        formatted_metadata = str(metadata_dict)
    
    text_widget.insert("1.0", formatted_metadata)
    text_widget.configure(state="disabled") # Ngăn chỉnh sửa
    
    # Đảm bảo current_preview_window được reset khi đóng
    current_preview_window.protocol("WM_DELETE_WINDOW", lambda: (close_current_preview(), current_preview_window.grab_release()))


def preview_image(data, metadata=None):
    global current_preview_window
    close_current_preview()
    
    try:
        image_data = io.BytesIO(data)
        pil_image = Image.open(image_data)
        
        # Tạo cửa sổ preview
        current_preview_window = ctk.CTkToplevel(root) # Gắn vào root
        current_preview_window.title("Image Preview")
        current_preview_window.geometry("800x700")
        current_preview_window.transient(root)
        current_preview_window.grab_set()

        tabview = ctk.CTkTabview(current_preview_window, width=780, height=680)
        tabview.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Image tab
        tab_image = tabview.add("Image")
        
        # Tính toán kích thước để hiển thị ảnh mà không làm méo
        # Giữ tỷ lệ khung hình, khớp với kích thước tab
        img_width, img_height = pil_image.size
        tab_width, tab_height = 750, 600 # Ước lượng kích thước vùng hiển thị ảnh trong tab
        
        ratio = min(tab_width / img_width, tab_height / img_height)
        new_width = int(img_width * ratio)
        new_height = int(img_height * ratio)
        
        # Sử dụng ANTIALIAS cho chất lượng resize tốt hơn
        resized_image = pil_image.resize((new_width, new_height), Image.LANCZOS) #Image.Resampling.LANCZOS for Pillow >= 9.1.0
        tk_img = ImageTk.PhotoImage(resized_image)
        
        image_label = ctk.CTkLabel(tab_image, image=tk_img, text="")
        image_label.image = tk_img  # Giữ tham chiếu quan trọng!
        image_label.pack(padx=10, pady=10, expand=True) # expand=True để căn giữa
        
        # Metadata tab
        if metadata:
            tab_meta = tabview.add("Metadata")
            meta_text_widget = tk.Text(tab_meta, wrap="word", font=("Segoe UI", 10))
            meta_text_widget.pack(expand=True, fill="both", padx=5, pady=5)
            
            meta_scrollbar = ctk.CTkScrollbar(tab_meta, command=meta_text_widget.yview)
            meta_scrollbar.pack(side="right", fill="y")
            meta_text_widget.configure(yscrollcommand=meta_scrollbar.set)

            def convert_bytes_to_str_local(obj): # Hàm local để tránh xung đột
                if isinstance(obj, bytes):
                    try: return obj.decode('utf-8', errors='replace')
                    except: return repr(obj)
                if isinstance(obj, dict): return {k: convert_bytes_to_str_local(v) for k, v in obj.items()}
                if isinstance(obj, list): return [convert_bytes_to_str_local(i) for i in obj]
                return obj
            
            try:
                cleaned_meta = convert_bytes_to_str_local(metadata)
                formatted_meta = json.dumps(cleaned_meta, indent=4, ensure_ascii=False)
            except Exception as e_json:
                formatted_meta = f"Error formatting metadata: {e_json}\n\nRaw:\n{str(metadata)}"

            meta_text_widget.insert("1.0", formatted_meta)
            meta_text_widget.configure(state="disabled")
        
        current_preview_window.protocol("WM_DELETE_WINDOW", lambda: (close_current_preview(), current_preview_window.grab_release()))

    except Exception as e:
        messagebox.showerror("Lỗi Xem Trước Ảnh", f"Không thể xem trước ảnh: {e}", parent=root)
        if current_preview_window: current_preview_window.grab_release() # Nhả grab nếu có lỗi
        close_current_preview()


def preview_text(data, metadata=None, file_type="Text"): # Thêm file_type để tùy chỉnh tiêu đề
    global current_preview_window
    close_current_preview()
    
    try:
        # Cố gắng decode với UTF-8, nếu lỗi thì dùng 'latin-1' hoặc 'ascii' với error replacement
        try:
            text_content = data.decode('utf-8')
        except UnicodeDecodeError:
            try:
                text_content = data.decode('latin-1')
            except UnicodeDecodeError:
                text_content = data.decode('ascii', errors='replace')
        
        text_content_preview = text_content[:10000] # Giới hạn 10000 ký tự cho preview

        current_preview_window = ctk.CTkToplevel(root)
        current_preview_window.title(f"{file_type} Preview")
        current_preview_window.geometry("800x700")
        current_preview_window.transient(root)
        current_preview_window.grab_set()
        
        tabview = ctk.CTkTabview(current_preview_window, width=780, height=680)
        tabview.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Text content tab
        tab_content = tabview.add("Content")
        content_text_widget = tk.Text(tab_content, wrap="word", font=("Segoe UI", 10))
        content_text_widget.pack(expand=True, fill="both", padx=5, pady=5)
        
        content_scrollbar = ctk.CTkScrollbar(tab_content, command=content_text_widget.yview)
        content_scrollbar.pack(side="right", fill="y")
        content_text_widget.configure(yscrollcommand=content_scrollbar.set)
        
        content_text_widget.insert("1.0", text_content_preview)
        if len(text_content) > 10000:
            content_text_widget.insert(tk.END, f"\n\n--- Nội dung đã được cắt bớt, tổng cộng {len(text_content)} ký tự ---")
        content_text_widget.configure(state="disabled")
        
        # Metadata tab
        if metadata:
            tab_meta = tabview.add("Metadata")
            meta_text_widget = tk.Text(tab_meta, wrap="word", font=("Segoe UI", 10))
            meta_text_widget.pack(expand=True, fill="both", padx=5, pady=5)

            meta_scrollbar = ctk.CTkScrollbar(tab_meta, command=meta_text_widget.yview)
            meta_scrollbar.pack(side="right", fill="y")
            meta_text_widget.configure(yscrollcommand=meta_scrollbar.set)

            def convert_bytes_to_str_local(obj): # Hàm local
                if isinstance(obj, bytes):
                    try: return obj.decode('utf-8', errors='replace')
                    except: return repr(obj)
                if isinstance(obj, dict): return {k: convert_bytes_to_str_local(v) for k, v in obj.items()}
                if isinstance(obj, list): return [convert_bytes_to_str_local(i) for i in obj]
                return obj
            try:
                cleaned_meta = convert_bytes_to_str_local(metadata)
                formatted_meta = json.dumps(cleaned_meta, indent=4, ensure_ascii=False)
            except Exception as e_json:
                 formatted_meta = f"Error formatting metadata: {e_json}\n\nRaw:\n{str(metadata)}"

            meta_text_widget.insert("1.0", formatted_meta)
            meta_text_widget.configure(state="disabled")
            
        current_preview_window.protocol("WM_DELETE_WINDOW", lambda: (close_current_preview(), current_preview_window.grab_release()))

    except Exception as e:
        messagebox.showerror(f"Lỗi Xem Trước {file_type}", f"Không thể xem trước {file_type.lower()}: {e}", parent=root)
        if current_preview_window: current_preview_window.grab_release()
        close_current_preview()


def preview_mkv(data, metadata=None):
    global current_preview_window
    close_current_preview()
    
    tmp_path = "" # Khởi tạo để có thể truy cập trong finally
    try:
        # Tạo file tạm với context manager để đảm bảo nó được đóng đúng cách
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mkv") as tmp_file:
            tmp_file.write(data)
            tmp_path = tmp_file.name
        
        # Mở file bằng trình phát mặc định của hệ thống
        os.startfile(tmp_path)
        
        # Cửa sổ thông báo nhỏ (không phải cửa sổ preview chính)
        info_window = ctk.CTkToplevel(root)
        info_window.title("MKV Launched")
        info_window.geometry("350x150")
        info_window.transient(root)
        # info_window.grab_set() # Không grab_set cửa sổ thông báo này để người dùng có thể làm việc khác

        ctk.CTkLabel(info_window, text=f"Tệp MKV đã được mở bằng trình phát mặc định.\nĐường dẫn tạm: {tmp_path}", wraplength=330).pack(padx=10, pady=10)
        
        # Nút để hiển thị metadata nếu có
        if metadata:
            meta_button = ctk.CTkButton(info_window, text="Hiển thị Metadata", 
                                        command=lambda m=metadata: show_metadata_window(m, info_window)) # Truyền info_window làm parent
            meta_button.pack(pady=10)

        # Thiết lập current_preview_window là cửa sổ thông báo này để logic close_current_preview có thể quản lý nó
        # Hoặc tốt hơn là không set, vì nó không phải là "preview" thực sự.
        # Thay vào đó, quản lý việc xóa file tạm khi cửa sổ info đóng.
        def on_info_close():
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                    print(f"Đã xóa tệp tạm: {tmp_path}")
                except OSError as e_unlink:
                    print(f"Lỗi khi xóa tệp tạm {tmp_path}: {e_unlink}")
            info_window.destroy()

        info_window.protocol("WM_DELETE_WINDOW", on_info_close)
        
        # Không set current_preview_window ở đây để tránh nhầm lẫn với các preview có tab.
        # File tạm sẽ được xóa khi cửa sổ thông báo đóng.

    except FileNotFoundError: # os.startfile có thể báo lỗi này nếu không có trình phát mặc định
        messagebox.showerror("Lỗi Xem Trước MKV", "Không tìm thấy trình phát mặc định cho tệp .mkv.", parent=root)
        if tmp_path and os.path.exists(tmp_path): os.unlink(tmp_path) # Dọn dẹp nếu có lỗi
    except Exception as e:
        messagebox.showerror("Lỗi Xem Trước MKV", f"Không thể xem trước MKV: {e}", parent=root)
        if tmp_path and os.path.exists(tmp_path): os.unlink(tmp_path) # Dọn dẹp
    # Không cần finally để xóa file tạm ở đây nữa vì nó được xử lý bởi on_info_close

# ----------------------------
# CustomTkinter GUI Setup
# ----------------------------
ctk.set_appearance_mode("System") # System, Dark, Light
ctk.set_default_color_theme("blue") # blue, dark-blue, green

root = ctk.CTk()
root.title("Công Cụ Phục Hồi Tệp Nâng Cao")
root.geometry("1100x850") # Tăng kích thước cửa sổ một chút

# Global variables
recovered_files_data = [] # Đổi tên để rõ ràng hơn
output_dir = ""

# Create a main frame to hold UI components
main_frame = ctk.CTkFrame(root)
main_frame.pack(padx=15, pady=15, fill="both", expand=True)

# -- Top Configuration Frame (Drive, File Types, Scan Mode) --
config_frame = ctk.CTkFrame(main_frame)
config_frame.pack(pady=10, padx=10, fill="x")

# Drive Selection
drive_frame = ctk.CTkFrame(config_frame)
drive_frame.pack(side="left", padx=(0,10), fill="x", expand=True)
ctk.CTkLabel(drive_frame, text="Chọn Ổ Đĩa:").pack(side="left", padx=5, pady=5)
available_drives = get_available_drives()
drive_var = ctk.StringVar(value=available_drives[0] if available_drives else "Không tìm thấy ổ đĩa")
drive_combobox = ctk.CTkComboBox(drive_frame, values=available_drives, variable=drive_var, width=150)
drive_combobox.pack(side="left", padx=5, pady=5)

# Scan Mode Selection
scan_mode_frame = ctk.CTkFrame(config_frame)
scan_mode_frame.pack(side="left", padx=10, fill="x") # Thay đổi thành side="left"
ctk.CTkLabel(scan_mode_frame, text="Chế Độ Quét:").pack(side="left", padx=5, pady=5)
scan_mode_var = ctk.StringVar(value="Chuyên sâu") # Giá trị mặc định
scan_mode_segmented_button = ctk.CTkSegmentedButton(scan_mode_frame,
                                                     values=["Nhanh", "Chuyên sâu"],
                                                     variable=scan_mode_var)
scan_mode_segmented_button.pack(side="left", padx=5, pady=5)


# File Types Selection
types_frame = ctk.CTkFrame(main_frame)
types_frame.pack(pady=10, padx=10, fill="x")
ctk.CTkLabel(types_frame, text="Chọn Loại Tệp:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
selected_types_vars = {}
# Hiển thị các checkbox thành nhiều hàng nếu cần
max_cols = 6 # Số checkbox tối đa trên một hàng
current_col = 1
current_row = 0
for ftype in FILE_SIGNATURES.keys():
    if current_col > max_cols:
        current_col = 1
        current_row += 1
    var = tk.IntVar(value=1) # Mặc định chọn tất cả
    chk = ctk.CTkCheckBox(types_frame, text=ftype, variable=var)
    chk.grid(row=current_row, column=current_col, padx=5, pady=5, sticky="w")
    selected_types_vars[ftype] = var
    current_col += 1

# -- Output Folder Selection --
output_frame = ctk.CTkFrame(main_frame)
output_frame.pack(pady=10, padx=10, fill="x")

def select_output_directory():
    global output_dir
    # Sử dụng parent=root để filedialog hiển thị đúng cách
    selected_dir = filedialog.askdirectory(title="Chọn Thư Mục Lưu Trữ", parent=root)
    if selected_dir:
        output_dir = selected_dir
        output_label.configure(text=f"Thư Mục Lưu: {output_dir}")

output_btn = ctk.CTkButton(output_frame, text="Chọn Thư Mục Lưu", command=select_output_directory)
output_btn.pack(side="left", padx=5, pady=5) #Sử dụng pack thay vì grid
output_label = ctk.CTkLabel(output_frame, text="Thư Mục Lưu: Chưa chọn", wraplength=700) # wraplength để xuống dòng
output_label.pack(side="left", padx=5, pady=5, fill="x", expand=True)


# -- Scan Button & Progress Bar --
scan_controls_frame = ctk.CTkFrame(main_frame) # Đổi tên frame để rõ ràng hơn
scan_controls_frame.pack(pady=10, padx=10, fill="x")

# Biến cờ để dừng quét
stop_scan_event = threading.Event()


def update_ui_after_scan():
    scan_button.configure(state="normal")
    stop_scan_button.configure(state="disabled")
    if not stop_scan_event.is_set(): # Chỉ hiển thị nếu không phải do người dùng dừng
        progress_label.configure(text=f"Hoàn tất quét. Tìm thấy {len(recovered_files_data)} tệp.")
    else:
        progress_label.configure(text=f"Quét đã dừng bởi người dùng. Tìm thấy {len(recovered_files_data)} tệp.")
    
    # Cập nhật listbox
    listbox.delete(0, tk.END)
    for rec_file in recovered_files_data:
        listbox.insert(tk.END, f"{rec_file['name']} ({rec_file['size']/(1024*1024):.2f} MB) - Hash: {rec_file['hash'][:8]}...")


def start_scan_thread(): # Đổi tên hàm
    global recovered_files_data # Đảm bảo sử dụng biến global
    
    stop_scan_event.clear() # Reset cờ dừng trước mỗi lần quét
    scan_button.configure(state="disabled")
    stop_scan_button.configure(state="normal") # Kích hoạt nút dừng
    listbox.delete(0, tk.END)
    recovered_files_data.clear() # Xóa kết quả cũ
    
    selected_drive_letter = drive_var.get()
    if not selected_drive_letter or selected_drive_letter == "Không tìm thấy ổ đĩa":
        messagebox.showwarning("Chưa Chọn Ổ Đĩa", "Vui lòng chọn một ổ đĩa để quét.", parent=root)
        scan_button.configure(state="normal")
        stop_scan_button.configure(state="disabled")
        return

    # raw_drive_path = r"\\.\{}".format(selected_drive_letter[0]) # Lấy ký tự đầu tiên của ổ đĩa
    # Chúng ta sẽ truyền selected_drive_letter (vd: "C:\") vào scan_drive, hàm open_raw_drive sẽ xử lý
    
    drive_size_bytes = get_drive_total_size(selected_drive_letter)
    if drive_size_bytes is None:
        messagebox.showerror("Lỗi Kích Thước Ổ Đĩa", f"Không thể xác định kích thước ổ đĩa {selected_drive_letter}.", parent=root)
        scan_button.configure(state="normal")
        stop_scan_button.configure(state="disabled")
        return

    current_selected_types = [ftype for ftype, var_obj in selected_types_vars.items() if var_obj.get() == 1]
    if not current_selected_types:
        messagebox.showwarning("Chưa Chọn Loại Tệp", "Vui lòng chọn ít nhất một loại tệp để quét.", parent=root)
        scan_button.configure(state="normal")
        stop_scan_button.configure(state="disabled")
        return

    current_scan_mode = scan_mode_var.get()
    progress_bar.set(0) # Reset progress bar
    progress_label.configure(text="Đang quét...")

    def progress_update_callback(current_offset):
        if stop_scan_event.is_set(): # Kiểm tra cờ dừng
            return # Ngừng cập nhật nếu yêu cầu dừng

        if drive_size_bytes > 0:
            progress_percentage = current_offset / drive_size_bytes
            progress_bar.set(progress_percentage)
            progress_label.configure(text=f"Đang quét: {current_offset / (1024*1024):.2f} MB / {drive_size_bytes / (1024*1024):.2f} MB ({progress_percentage*100:.1f}%)")
        else:
            progress_label.configure(text=f"Đang quét: {current_offset / (1024*1024):.2f} MB")
        root.update_idletasks() # Cập nhật UI


    def actual_scan_execution(): # Hàm thực thi quét trong thread
        global recovered_files_data
        try:
            # Truyền selected_drive_letter trực tiếp
            temp_recovered_files = scan_drive(selected_drive_letter, drive_size_bytes, current_selected_types, progress_update_callback, current_scan_mode)
            if not stop_scan_event.is_set(): # Chỉ cập nhật nếu không bị dừng
                 recovered_files_data = temp_recovered_files

        except Exception as e_scan:
            root.after(0, lambda: messagebox.showerror("Lỗi Quét", f"Đã xảy ra lỗi trong quá trình quét: {e_scan}", parent=root))
            recovered_files_data = [] # Reset nếu có lỗi
        finally:
            # Cập nhật UI từ luồng chính, bất kể quét thành công, thất bại hay bị dừng
            root.after(0, update_ui_after_scan)


    # Chạy hàm quét trong một luồng riêng để không làm đông cứng UI
    scan_worker_thread = threading.Thread(target=actual_scan_execution, daemon=True)
    scan_worker_thread.start()

def stop_current_scan():
    stop_scan_event.set() # Đặt cờ báo dừng
    progress_label.configure(text="Đang dừng quét...")
    scan_button.configure(state="disabled") # Giữ nút scan bị vô hiệu hóa cho đến khi thread dừng hẳn
    stop_scan_button.configure(state="disabled") # Vô hiệu hóa nút dừng ngay


scan_button = ctk.CTkButton(scan_controls_frame, text="Bắt Đầu Quét", command=start_scan_thread, width=120)
scan_button.pack(side="left", padx=5, pady=10)

stop_scan_button = ctk.CTkButton(scan_controls_frame, text="Dừng Quét", command=stop_current_scan, width=120, state="disabled")
stop_scan_button.pack(side="left", padx=5, pady=10)

progress_bar = ctk.CTkProgressBar(scan_controls_frame, height=20) # Tăng chiều cao progress bar
progress_bar.pack(side="left", padx=10, pady=10, fill="x", expand=True)
progress_bar.set(0) # Giá trị khởi tạo

progress_label = ctk.CTkLabel(main_frame, text="Chưa bắt đầu quét.", font=("Segoe UI", 10)) # Font nhỏ hơn
progress_label.pack(pady=(0,5), padx=10, fill="x")


# -- Listbox for Recovered Files --
listbox_frame = ctk.CTkFrame(main_frame)
listbox_frame.pack(pady=10, padx=10, fill="both", expand=True)

listbox_label = ctk.CTkLabel(listbox_frame, text="Các Tệp Tìm Thấy:")
listbox_label.pack(anchor="w", padx=5, pady=(0,5))

listbox = tk.Listbox(listbox_frame, selectmode=tk.EXTENDED, font=("Segoe UI", 11), activestyle="none", borderwidth=0, highlightthickness=0)
listbox_scrollbar_y = ctk.CTkScrollbar(listbox_frame, command=listbox.yview)
listbox_scrollbar_x = ctk.CTkScrollbar(listbox_frame, command=listbox.xview, orientation="horizontal")
listbox.configure(yscrollcommand=listbox_scrollbar_y.set, xscrollcommand=listbox_scrollbar_x.set)

listbox_scrollbar_y.pack(side="right", fill="y")
listbox_scrollbar_x.pack(side="bottom", fill="x")
listbox.pack(padx=(0, listbox_scrollbar_y.winfo_reqwidth()), pady=(0, listbox_scrollbar_x.winfo_reqheight()), fill="both", expand=True)


def on_item_double_click(event):
    selected_indices = listbox.curselection()
    if not selected_indices:
        return
    
    index = selected_indices[0] # Chỉ xử lý item đầu tiên được chọn khi double click
    if 0 <= index < len(recovered_files_data):
        rec_file_info = recovered_files_data[index]
        file_type = rec_file_info["type"]
        file_data = rec_file_info["data"]
        metadata = rec_file_info.get("metadata")

        if file_type == "JPEG" or file_type == "PNG": # Giả sử bạn thêm PNG
            preview_image(file_data, metadata)
        elif file_type == "MKV":
            preview_mkv(file_data, metadata)
        elif file_type == "PDF":
            preview_text(file_data, metadata, file_type="PDF") # Sử dụng preview_text cho PDF
        else: # Các loại tệp khác (nếu có)
            preview_text(file_data, metadata, file_type=file_type)

listbox.bind("<Double-Button-1>", on_item_double_click)


# -- Right-click context menu for metadata --
context_menu = tk.Menu(root, tearoff=0, font=("Segoe UI", 10))

def show_selected_file_metadata():
    selected_indices = listbox.curselection()
    if not selected_indices:
        return
    index = selected_indices[0] # Lấy item đầu tiên
    if 0 <= index < len(recovered_files_data):
        rec_file_info = recovered_files_data[index]
        metadata_to_show = rec_file_info.get("metadata", "Không có metadata cho tệp này.")
        show_metadata_window(metadata_to_show, root) # Hiển thị metadata trong cửa sổ riêng

context_menu.add_command(label="Hiển Thị Metadata", command=show_selected_file_metadata)

def show_listbox_context_menu(event):
    # Chọn item dưới con trỏ chuột trước khi hiển thị menu
    # Điều này giúp người dùng không cần click trái trước khi click phải
    # listbox.selection_clear(0, tk.END) # Xóa lựa chọn cũ (tùy chọn)
    # listbox.selection_set(listbox.nearest(event.y)) # Chọn item gần nhất với vị trí y của chuột
    # listbox.activate(listbox.nearest(event.y))

    # Chỉ hiển thị menu nếu có item được chọn
    if listbox.curselection():
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()

listbox.bind("<Button-3>", show_listbox_context_menu)


# -- Action Buttons Frame (Recover, Save Report) --
action_buttons_frame = ctk.CTkFrame(main_frame)
action_buttons_frame.pack(pady=10, padx=10, fill="x")

def recover_selected_files():
    if not output_dir:
        messagebox.showwarning("Chưa Chọn Thư Mục Lưu", "Vui lòng chọn thư mục để lưu các tệp phục hồi.", parent=root)
        return
        
    selected_indices = listbox.curselection()
    if not selected_indices:
        messagebox.showinfo("Chưa Chọn Tệp", "Vui lòng chọn ít nhất một tệp từ danh sách để phục hồi.", parent=root)
        return
    
    success_count = 0
    error_files = []

    for idx in selected_indices:
        if 0 <= idx < len(recovered_files_data):
            rec_file_info = recovered_files_data[idx]
            try:
                # Tạo thư mục con theo loại tệp nếu muốn
                # type_specific_dir = os.path.join(output_dir, rec_file_info["type"])
                # os.makedirs(type_specific_dir, exist_ok=True)
                # output_file_path = os.path.join(type_specific_dir, rec_file_info["name"])
                
                output_file_path = os.path.join(output_dir, rec_file_info["name"])
                
                # Kiểm tra nếu file đã tồn tại, có thể thêm số vào tên file
                counter = 1
                base_name, ext = os.path.splitext(output_file_path)
                while os.path.exists(output_file_path):
                    output_file_path = f"{base_name}_{counter}{ext}"
                    counter += 1
                
                with open(output_file_path, "wb") as f_out:
                    f_out.write(rec_file_info["data"])
                
                # Lưu metadata nếu có
                if rec_file_info.get("metadata"):
                    meta_file_path = output_file_path + ".meta.json"
                    try:
                        with open(meta_file_path, "w", encoding='utf-8') as f_meta: # Luôn dùng UTF-8 cho JSON
                            # Làm sạch metadata trước khi dump
                            def convert_bytes_final(obj):
                                if isinstance(obj, bytes): return obj.decode('utf-8', 'replace')
                                if isinstance(obj, dict): return {k: convert_bytes_final(v) for k,v in obj.items()}
                                if isinstance(obj, list): return [convert_bytes_final(i) for i in obj]
                                return obj
                            cleaned_metadata = convert_bytes_final(rec_file_info["metadata"])
                            json.dump(cleaned_metadata, f_meta, indent=4, ensure_ascii=False)
                    except Exception as e_meta_save:
                         print(f"Lỗi khi lưu metadata cho {rec_file_info['name']}: {e_meta_save}")
                
                success_count += 1
            except Exception as e_write:
                error_files.append(f"{rec_file_info['name']} (Lỗi: {e_write})")
    
    if not error_files:
        messagebox.showinfo("Hoàn Tất Phục Hồi", f"Đã phục hồi thành công {success_count}/{len(selected_indices)} tệp đã chọn.", parent=root)
    else:
        errors_str = "\n".join(error_files)
        messagebox.showwarning("Hoàn Tất Với Lỗi", 
                               f"Đã phục hồi {success_count}/{len(selected_indices)} tệp.\n"
                               f"Các tệp sau gặp lỗi:\n{errors_str}", parent=root)

recover_button = ctk.CTkButton(action_buttons_frame, text="Phục Hồi Tệp Đã Chọn", command=recover_selected_files)
recover_button.pack(side="left", padx=5, pady=5)

def save_scan_report():
    if not recovered_files_data:
        messagebox.showwarning("Không Có Dữ Liệu", "Không có dữ liệu quét để lưu báo cáo.", parent=root)
        return
    
    report_file_path = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        title="Lưu Báo Cáo Quét",
        parent=root
    )
    
    if report_file_path:
        try:
            # Chuẩn bị dữ liệu cho báo cáo (không bao gồm 'data' của tệp)
            report_content = {
                "scan_timestamp": datetime.now().isoformat(),
                "scanned_drive": drive_var.get(),
                "scan_mode": scan_mode_var.get(),
                "selected_file_types": [ftype for ftype, var_obj in selected_types_vars.items() if var_obj.get() == 1],
                "total_files_found": len(recovered_files_data),
                "recovered_files_summary": [
                    {
                        "name": f_info["name"],
                        "type": f_info["type"],
                        "size_bytes": f_info["size"],
                        "sha256_hash": f_info["hash"],
                        "detected_offset": f_info["offset"],
                        "discovery_time": f_info["discovery_time"],
                        "metadata_summary": {k: (type(v).__name__ if not isinstance(v, (str, int, float, bool)) else v) 
                                             for k,v in (f_info.get("metadata", {}) or {}).items()} # Tóm tắt metadata
                    } for f_info in recovered_files_data
                ]
            }
            
            with open(report_file_path, "w", encoding='utf-8') as f_report:
                json.dump(report_content, f_report, indent=4, ensure_ascii=False)
            
            messagebox.showinfo("Lưu Báo Cáo Thành Công", f"Báo cáo quét đã được lưu tại:\n{report_file_path}", parent=root)
        except Exception as e_save_report:
            messagebox.showerror("Lỗi Lưu Báo Cáo", f"Không thể lưu báo cáo quét: {e_save_report}", parent=root)

report_button = ctk.CTkButton(action_buttons_frame, text="Lưu Báo Cáo Quét", command=save_scan_report)
report_button.pack(side="left", padx=5, pady=5)

# -- Status Bar (Optional, for more detailed messages or tips) --
# status_bar = ctk.CTkLabel(root, text="Sẵn sàng.", anchor="w")
# status_bar.pack(side="bottom", fill="x", padx=10, pady=5)

# Đảm bảo các cửa sổ con được đóng khi cửa sổ chính đóng
def on_closing():
    close_current_preview() # Đóng cửa sổ preview nếu có
    if messagebox.askokcancel("Thoát", "Bạn có chắc chắn muốn thoát ứng dụng?", parent=root):
        root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
