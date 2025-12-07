import os

def create_dummy_file(filename, size_in_mb):
    print(f"Generating {filename} ({size_in_mb} MB)...")
    # 1 MB = 1024 * 1024 bytes
    size_in_bytes = size_in_mb * 1024 * 1024
    
    with open(filename, "wb") as f:
        # Write dummy 'A' characters to fill the size
        f.write(b'A' * size_in_bytes)
    
    print(f"[+] Created {filename}")

if __name__ == "__main__":
    create_dummy_file("test_1MB.log", 1)
    create_dummy_file("test_10MB.log", 10)
    create_dummy_file("test_100MB.log", 100)
    print("--- Done! Move these files to your Desktop ---")