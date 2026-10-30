import os
import hashlib

# 1. Expanded Magic Bytes Dictionary
MAGIC_BYTES = {
    b'\xFF\xD8\xFF': "JPEG",
    b'\x89PNG': "PNG",
    b'%PDF': "PDF",
    b'PK\x03\x04': "ZIP",
    b'MZ': "EXE",
    b'Rar!': "RAR",
    b'\x7FELF': "ELF" # Linux Executable
}


def identify_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(8)
        for magic, ftype in MAGIC_BYTES.items():
            if header.startswith(magic):
                return ftype
        return "UNKNOWN"
    except Exception:
        return "ERROR"

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def scan_directory(directory_path):
    """Diye gaye folder ke andar ki saari files ko scan karta hai."""
    print(f"\n=== Scanning Directory: {directory_path} ===")
    
    if not os.path.exists(directory_path):
        print("Folder nahi mila! Sahi path dalein.")
        return

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root, file)
            ext = os.path.splitext(file)[1][1:].upper()
            
            # Agar file ka koi extension nahi hai
            if not ext: ext = "NO_EXT"
            
            real_type = identify_file(full_path)
            
            # Agar error aayi file read karne mein toh skip karein
            if real_type == "ERROR": continue 
            
            # Suspicious file detection (Mismatch check)
            is_suspicious = False
            if real_type != "UNKNOWN" and ext != real_type:
                is_suspicious = True
            elif ext == "EXE" or real_type == "EXE": 
                # Executables ko default scanning ke liye include kar sakte hain
                is_suspicious = True

            if is_suspicious:
                print(f"\n[!] SUSPICIOUS: {file}")
                print(f"    - Claimed: {ext} | Actual: {real_type}")
                
                # Hash calculation aur VirusTotal check
                f_hash = get_file_hash(full_path)
                print(f"    - SHA256: {f_hash}")
                print("-" * 30)

if __name__ == "__main__":
    import os
    
    print("=" * 50)
    print("🛡️  WELCOME TO FILE IDENTIFIER & MALWARE SCANNER 🛡️")
    print("=" * 50)
    
    # Prompt the user to enter the directory path dynamically
    folder_to_scan = input("👉 Enter the directory path to scan: ").strip()
    
    print("-" * 50)
    
    # Check if the entered path actually exists
    if os.path.exists(folder_to_scan):
        scan_directory(folder_to_scan)
    else:
        print(f"❌ Error: The directory '{folder_to_scan}' does not exist! Please check the path.")
    
    print("=" * 50)