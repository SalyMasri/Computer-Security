#!/usr/bin/env python3
from insecure_hash import hash_string
from Cryptodome.Cipher import AES

# Function to find a collision
def find_collision(message):
    key = b'A' * 16  # 16-byte key (AES-128)
    cipher = AES.new(key, AES.MODE_ECB)  # AES in ECB mode (no IV required)
    
    # Hash the message
    hashed_message = hash_string(message)
    
    # Ensure the hash is 16 bytes long, truncating or padding if necessary
    if len(hashed_message) < 16:
        hashed_message = hashed_message.ljust(16, b'\x00')  # Pad with null bytes if hash is less than 16 bytes
    elif len(hashed_message) > 16:
        hashed_message = hashed_message[:16]  # Truncate if hash is longer than 16 bytes
    
    # Encrypt the hashed message
    encrypted_message = cipher.encrypt(hashed_message)
    
    # Concatenate the encrypted message with the key
    result = encrypted_message + key
    
    return result

if __name__ == '__main__':
    message = b"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"  # Sample message
    print("Hash of %s is %s" % (message, hash_string(message)))  # Print hash of the original message
    
    # Find and print the "collision"
    collision = find_collision(message)
    print("Hash of %s is %s" % (collision, hash_string(collision)))
