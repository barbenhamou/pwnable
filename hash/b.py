import hashlib
import itertools
import string
from multiprocessing import Pool, cpu_count

target_hash = "537500469ddfc5b29e9379cdcc2f3c86"

charset = string.ascii_letters + string.digits + "_{}!@#$%^&*()-=+"

# Adjust based on expected flag length and complexity
min_length = 1
max_length = 6  # Adjust this as needed

def check(candidate):
    candidate_str = ''.join(candidate)
    candidate_hash = hashlib.md5(candidate_str.encode()).hexdigest()
    if candidate_hash == target_hash:
        return candidate_str
    return None

if __name__ == "__main__":
    print("[*] Starting brute-force...")

    with Pool(cpu_count()) as pool:
        for length in range(min_length, max_length + 1):
            args = itertools.product(charset, repeat=length)
            for result in pool.imap_unordered(check, args, chunksize=10000):
                if result:
                    print(f"[+] Flag cracked: {result}")
                    exit(0)

    print("[-] Flag not found within given charset and length constraints.")
