# After the Beep - Solver

cipher = "BOJIDWSBWEFWOPIAFN"
key = "MODEM"

# Vigenere decryption
plaintext = ""

for i, c in enumerate(cipher):
    c_val = ord(c) - ord('A')
    k_val = ord(key[i % len(key)]) - ord('A')
    p_val = (c_val - k_val) % 26

    plaintext += chr(p_val + ord('A'))

# Restore the original word grouping
words = [plaintext[:5], plaintext[5:9], plaintext[9:14], plaintext[14:]]

print("Decoded text:", " / ".join(words))
