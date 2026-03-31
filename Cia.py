import struct

# ──────────────────────────────────────────────
# DJB2 Hash Implementation (32-bit)
# ──────────────────────────────────────────────

def djb2_hash(message: str) -> str:
    """
    DJB2 Hash by Dan Bernstein.
    Steps:
      1. Start with magic seed 5381
      2. For each character: hash = (hash << 5) + hash + ord(char)
         which is equivalent to hash * 33 + ord(char)
      3. Mask to 32 bits after every step
      4. Return as 8-character hex string
    """
    hash_value = 5381  # Magic seed

    for char in message:
        # (hash << 5) + hash  ==  hash * 33
        hash_value = ((hash_value << 5) + hash_value + ord(char)) & 0xFFFFFFFF

    return format(hash_value, '08x')  # 8-char hex string


# ──────────────────────────────────────────────
# Myszkowski Cipher
# ──────────────────────────────────────────────

KEY = "RITHWIK"


def get_column_order(key):
    """
    Assign a rank to each column based on alphabetical order of key chars.
    Duplicate letters share the same rank and are read together row-by-row.
    """
    sorted_chars = sorted(enumerate(key), key=lambda x: x[1])
    rank = 0
    order = [0] * len(key)
    i = 0
    while i < len(sorted_chars):
        j = i
        while j < len(sorted_chars) and sorted_chars[j][1] == sorted_chars[i][1]:
            j += 1
        for k in range(i, j):
            order[sorted_chars[k][0]] = rank
        rank += 1
        i = j
    return order


def myszkowski_encrypt(text, key):
    num_cols = len(key)
    remainder = len(text) % num_cols
    if remainder != 0:
        text += 'X' * (num_cols - remainder)

    num_rows = len(text) // num_cols
    grid = [list(text[r * num_cols:(r + 1) * num_cols]) for r in range(num_rows)]

    col_order = get_column_order(key)
    num_ranks = max(col_order) + 1
    ciphertext = ""

    for rank in range(num_ranks):
        cols_with_rank = [c for c, r in enumerate(col_order) if r == rank]
        for r in range(num_rows):
            for c in cols_with_rank:
                ciphertext += grid[r][c]

    return ciphertext


def myszkowski_decrypt(ciphertext, key):
    num_cols = len(key)
    num_rows = len(ciphertext) // num_cols

    col_order = get_column_order(key)
    num_ranks = max(col_order) + 1

    rank_char_counts = {}
    for rank in range(num_ranks):
        cols_with_rank = [c for c, r in enumerate(col_order) if r == rank]
        rank_char_counts[rank] = num_rows * len(cols_with_rank)

    rank_chunks = {}
    idx = 0
    for rank in range(num_ranks):
        count = rank_char_counts[rank]
        rank_chunks[rank] = ciphertext[idx:idx + count]
        idx += count

    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
    for rank in range(num_ranks):
        cols_with_rank = [c for c, r in enumerate(col_order) if r == rank]
        chunk = rank_chunks[rank]
        pos = 0
        for r in range(num_rows):
            for c in cols_with_rank:
                grid[r][c] = chunk[pos]
                pos += 1

    plaintext = ""
    for row in grid:
        plaintext += "".join(row)
    return plaintext


# ──────────────────────────────────────────────
# Sender
# ──────────────────────────────────────────────

def send_message(message, key=KEY):
    print()
    print("=" * 55)
    print("SENDER SIDE")
    print("=" * 55)
    print(f"Original message : {message}")

    hash_hex = djb2_hash(message)
    print(f"DJB2 hash        : {hash_hex}  ({len(hash_hex)} hex chars = 32 bits)")

    encrypted_hash = myszkowski_encrypt(hash_hex, key)
    print(f"Encrypted hash   : {encrypted_hash}")

    payload = message + "||" + encrypted_hash
    print(f"Payload sent     : {payload}")
    print()
    return payload


# ──────────────────────────────────────────────
# Receiver
# ──────────────────────────────────────────────

def receive_message(payload, key=KEY):
    print("=" * 55)
    print("RECEIVER SIDE")
    print("=" * 55)

    parts = payload.split("||", 1)
    if len(parts) != 2:
        print("ERROR: Malformed payload — delimiter '||' not found.")
        return

    received_message, received_enc_hash = parts
    print(f"Received message : {received_message}")
    print(f"Encrypted hash   : {received_enc_hash}")

    decrypted_hash = myszkowski_decrypt(received_enc_hash, key)
    decrypted_hash = decrypted_hash[:8]  # DJB2 output is always 8 hex chars
    print(f"Decrypted hash   : {decrypted_hash}")

    computed_hash = djb2_hash(received_message)
    print(f"Computed hash    : {computed_hash}")

    print()
    if decrypted_hash == computed_hash:
        print("✅ Hashes MATCH — Message is authentic!")
        print(f"Message : {received_message}")
    else:
        print("❌ Hashes DO NOT MATCH — Message has been tampered!")


# ──────────────────────────────────────────────
# DJB2 Verification
# ──────────────────────────────────────────────

def verify_djb2():
    """
    Verify DJB2 against known correct values.
    These are precomputed correct DJB2-32 outputs.
    """
    print("── DJB2 Hash Verification ──")

    test_vectors = {
    ""            : "00001505",
    "a"           : "0002b606",
    "abc"         : "0b885c8b",   
    "hello"       : "0f923099",  
    "hello world" : "3551c8c1",   
    }

    all_pass = True
    for msg, expected in test_vectors.items():
        got = djb2_hash(msg)
        status = "✅" if got == expected else "❌"
        if got != expected:
            all_pass = False
        print(f"  {status} djb2({repr(msg):10s}) = {got}  (expected {expected})")

    print("  All passed!\n" if all_pass else "  Some tests FAILED.\n")
    return all_pass


# ──────────────────────────────────────────────
# Main — User Input
# ──────────────────────────────────────────────

if __name__ == "__main__":

    print("╔══════════════════════════════════════════════════════╗")
    print("║   Message Authentication — Type B (DJB2 + Myszkowski)║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    # Verify DJB2 first
    verify_djb2()

    # Get message from user
    message = input("Enter the message to send: ").strip()
    if not message:
        print("Message cannot be empty.")
        exit(1)

    # Sender builds and sends payload
    payload = send_message(message)

    # Receiver verifies the authentic payload
    receive_message(payload)

    # Tamper test
    print()
    print("── Tamper Test ──")
    tamper_choice = input("Do you want to test with a tampered message? (y/n): ").strip().lower()
    if tamper_choice == 'y':
        tampered_message = input("Enter the tampered message: ").strip()
        tampered_payload = tampered_message + "||" + payload.split("||")[1]
        print()
        receive_message(tampered_payload)
