# Message Authentication — Type B
### Myszkowski Cipher + DJB2 Hash

A Python implementation of **Message Authentication Code (MAC) Type B** flow using the Myszkowski transposition cipher and the DJB2 hash function, built from scratch without any cryptographic libraries.

---

## What is MAC Type B?

In a Type B MAC flow, the **message is sent in plaintext** alongside an **encrypted hash** of that message. The receiver independently hashes the received message and compares it to the decrypted hash to verify authenticity.

```
Sender                                      Receiver
──────                                      ────────
message ──────────────────────────────────► message
       hash(message) → encrypt → MAC ───► decrypt(MAC) → hash'
                                            compare hash == hash' ?
```

This is different from Type A (where the message itself is encrypted) — here only the hash is encrypted, acting as a tamper-evident seal.

---

## Algorithms Used

### DJB2 Hash (32-bit)

A classic hash function invented by Dan Bernstein. Simple, fast, and effective for non-cryptographic purposes.

**Steps:**
1. Start with magic seed `5381`
2. For each character in the message:
   ```
   hash = (hash << 5) + hash + ord(char)
        = hash * 33 + ord(char)
   ```
3. Mask to 32 bits after every step (`& 0xFFFFFFFF`)
4. Output as an 8-character hex string

The seed `5381` and multiplier `33` were chosen by Bernstein for their excellent bit distribution properties.

### Myszkowski Transposition Cipher

A classical transposition cipher that uses a keyword to reorder columns of a grid.

**Encryption:**
1. Write the message row-by-row into a grid with `len(key)` columns
2. Pad with `X` if the message doesn't fill the last row
3. Rank each column alphabetically by its key letter
4. Read columns in rank order — duplicate key letters are read **row-by-row together** (this is the defining Myszkowski rule)


**Decryption:** Reverse the process — reconstruct the grid column-by-column, then read row-by-row.

---

## Full Flow

```
SENDER
  1. Take plaintext message
  2. Compute DJB2 hash → 8-char hex string
  3. Encrypt the hash using Myszkowski cipher (key: CRYPTO)
  4. Send:  message || encrypted_hash
             (|| is the delimiter)

RECEIVER
  1. Split payload on || → message + encrypted_hash
  2. Decrypt encrypted_hash using Myszkowski → recovered_hash
  3. Recompute DJB2 hash of received message → computed_hash
  4. If recovered_hash == computed_hash → authentic ✅
     Else → tampered ❌
```

---

## Project Structure

```
.
├── Cia.py       # Main implementation
└── README.md    # This file
```

---

## How to Run

```bash
python Cia.py
```
---

## Key Design Decisions

| Decision | Choice | Reason |
|---|---|---|
| Hash function | DJB2 | Simple, from-scratch, no libraries |
| Hash output | 32-bit (8 hex chars) | Short enough to demonstrate cipher clearly |
| Cipher | Myszkowski | Required by assignment |
| Key | `RITHWIK` | Custom key as required |
| Delimiter | `\|\|` | Cannot appear in hex strings (only `0-9a-f`) |
| Padding char | `X` | Classic transposition cipher convention |
| Hash truncation | `[:8]` on decrypt | DJB2 always produces exactly 8 chars — strips padding `X` cleanly |

---

## Limitations

Since DJB2 is **not a cryptographic hash**, this implementation is for educational demonstration only. In a production system, a cryptographic hash (SHA-256 or stronger) would be used to prevent collision and preimage attacks.

---

## Author

Rithwik — Semester 6 Cryptography, SNU
