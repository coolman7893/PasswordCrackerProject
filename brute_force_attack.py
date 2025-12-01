import itertools
import time
from multiprocessing import Pool, Manager, Event
from multiprocessing_utils import init_worker, found_password_event, hash_func
from configuration import MAX_BRUTE_FORCE_LENGTH

# Check a single brute-force task (runs in parallel)
def check_brute_force_task(prefix, charset, length_to_gen, target_hash, attempt_counter, attempt_lock):
    import multiprocessing_utils
    if multiprocessing_utils.hash_func is None:  # Check if hash function is available
        return None, 0

    attempts = 0
    combinations = itertools.product(charset, repeat=length_to_gen)  # Generate all combinations of characters to append to prefix

    if length_to_gen == 0:  # Handle base case (length 0 - just check the prefix)
        attempts = 1
        if multiprocessing_utils.found_password_event.is_set():  # Stop if another process already found the password
            with attempt_lock:
                attempt_counter.value += attempts
            return None, attempts

        if multiprocessing_utils.hash_func(prefix.encode('utf-8')).hexdigest() == target_hash:  # Check if this password matches
            multiprocessing_utils.found_password_event.set()
            with attempt_lock:
                attempt_counter.value += attempts
            return prefix, attempts
        with attempt_lock:
            attempt_counter.value += attempts
        return None, attempts

    for combo_tuple in combinations:  # Try all combinations appended to the prefix
        attempts += 1

        if multiprocessing_utils.found_password_event.is_set():  # Stop if another process already found it
            with attempt_lock:
                attempt_counter.value += attempts
            return None, attempts

        password = prefix + "".join(combo_tuple)  # Build password and check hash
        if multiprocessing_utils.hash_func(password.encode('utf-8')).hexdigest() == target_hash:
            multiprocessing_utils.found_password_event.set()
            with attempt_lock:
                attempt_counter.value += attempts
            return password, attempts
    
    with attempt_lock:  # Update attempt counter
        attempt_counter.value += attempts
    return None, attempts

# Main brute-force attack function
def brute_force_attack(target_hash, algorithm, charset, max_length, num_processes):
    print(f"Using charset: '{charset}'")
    
    charset_len = len(charset)
    total_combinations = sum(charset_len ** length for length in range(1, max_length + 1))  # Calculate total possible combinations
    print(f"Total possible combinations: {total_combinations} ({charset_len}^{max_length}, based on charset = {charset_len} and MAX_BRUTE_FORCE_LENGTH = {MAX_BRUTE_FORCE_LENGTH})")
    print("")
    
    start_time = time.time()
    found = None
    total_attempts = 0

    with Manager() as manager:  # Use multiprocessing manager for shared counter across processes
        attempt_counter = manager.Value('i', 0)
        attempt_lock = manager.Lock()
        
        with Pool(processes=num_processes, initializer=init_worker, initargs=(manager.Event(), algorithm)) as pool:  # Create process pool
            for length in range(1, max_length + 1):  # Try each password length starting from 1
                if found:
                    break

                print(f"\nChecking passwords of length {length}...")

                if length == 1:  # Create tasks: each character in charset becomes a prefix for parallel processing
                    tasks = [(char, charset, 0, target_hash, attempt_counter, attempt_lock) for char in charset]
                else:
                    tasks = [(char, charset, length - 1, target_hash, attempt_counter, attempt_lock) for char in charset]

                if not tasks:
                    continue
                
                try:
                    for result in pool.starmap(check_brute_force_task, tasks):  # Run tasks in parallel and check results
                        if result[0]:  # Password found
                            found = result[0]
                            pool.terminate()
                            pool.join()
                            break
                except KeyboardInterrupt:
                    print("\nBrute-force attack interrupted.")
                    pool.terminate()
                    pool.join()
                    return None
        
        total_attempts = attempt_counter.value

    end_time = time.time()
    total_time = end_time - start_time

    if found:  # Print results
        print(f"\nSUCCESS: Password found!")
        print(f"Password: {found}")
    else:
        print(f"\nFAILED: Password not found (up to length {max_length}).")

    print(f"Total attempts needed: {total_attempts}")
    print(f"Time elapsed: {total_time:.2f} seconds.")
    return found