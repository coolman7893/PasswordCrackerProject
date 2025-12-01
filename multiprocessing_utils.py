import hashlib
from multiprocessing import Event

# Global variables shared across processes
found_password_event = None
hash_func = None

# Initialize each worker process with the hash function and event flag
def init_worker(event, algorithm):
    global found_password_event, hash_func

    found_password_event = event  # Flag to signal when password is found

    try:
        hash_func = getattr(hashlib, algorithm)
    except AttributeError:
        print(f"Error: Invalid hash algorithm '{algorithm}' in worker.")
        hash_func = None