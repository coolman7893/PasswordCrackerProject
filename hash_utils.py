import hashlib
import sys

# Hash a password using the specified algorithm
def hash_password(password, algorithm):

    try: # Get the hash scheme from hashlib that was passed from the command line
        hash_func_local = getattr(hashlib, algorithm)
    except AttributeError:
        print(f"Error: Hash algorithm '{algorithm}' not supported by hashlib.")
        sys.exit(1)

    # Convert password to bytes and hash it
    password_bytes = password.encode('utf-8')
    hash_obj = hash_func_local(password_bytes)

    return hash_obj.hexdigest() 
