import time
from multiprocessing import Pool, Manager, Event, Value
from multiprocessing_utils import init_worker, found_password_event, hash_func

# Check a chunk of passwords (runs in parallel)
def check_dictionary_chunk(password_chunk, target_hash, attempt_counter, attempt_lock):
    import multiprocessing_utils

    if multiprocessing_utils.hash_func is None:  # Check if hash function is available
        return None, 0

    attempts = 0
    for password in password_chunk:  # Try each password in this chunk
        attempts += 1
        if multiprocessing_utils.found_password_event.is_set():  # Stop if another process already found it
            with attempt_lock:
                attempt_counter.value += attempts
            return None, attempts

        if multiprocessing_utils.hash_func(password.encode('utf-8')).hexdigest() == target_hash:  # Check if this password matches
            multiprocessing_utils.found_password_event.set()
            with attempt_lock:
                attempt_counter.value += attempts
            return password, attempts
    
    with attempt_lock:  # Update counter when chunk is done
        attempt_counter.value += attempts
    
    return None, attempts

# Main dictionary attack function
def dictionary_attack(target_hash, algorithm, wordlist_path, num_processes):
    start_time = time.time()

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:  # Read wordlist file
            words = [line.strip() for line in f]
    except FileNotFoundError:
        print(f"Error: Wordlist file not found at '{wordlist_path}'")
        return None
    except Exception as e:
        print(f"Error reading wordlist: {e}")
        return None

    if not words:  # Check if wordlist is empty
        print("Error: Wordlist is empty.")
        return None

    chunk_size = (len(words) + num_processes - 1) // num_processes  # Split words into chunks for parallel processing
    password_chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]
    total_chunks = len(password_chunks)
    print(f"Total passwords: {len(words)}")

    found = None
    total_attempts = 0
    
    with Manager() as manager:  # Use multiprocessing manager for a shared counter
        attempt_counter = manager.Value('i', 0)
        attempt_lock = manager.Lock()
        
        with Pool(processes=num_processes, initializer=init_worker, initargs=(manager.Event(), algorithm)) as pool:  # Create process pool
           
            tasks = [(chunk, target_hash, attempt_counter, attempt_lock) for chunk in password_chunks]  # Create tasks for each chunk
            
            results = pool.starmap_async(check_dictionary_chunk, tasks)  # Run all tasks in parallel 
            
            try:
                print("Running dictionary attack...")
                final_results = results.get()  # Wait for all tasks to complete
                
                for result in final_results:  # Check if any task found the password
                    if result[0]:  # Password found
                        found = result[0]
                        break
                        
            except KeyboardInterrupt:
                print("\nDictionary attack interrupted.")
                pool.terminate()
                pool.join()
                return None
        
        total_attempts = attempt_counter.value  # Get final attempt count

    end_time = time.time()
    total_time = end_time - start_time

    if found:  # Print results
        print(f"\nSUCCESS: Password found!")
        print(f"Password: {found}")
    else:
        print(f"\nFAILED: Password not found in wordlist.")

    print(f"Total attempts: {total_attempts} ({len(words)} words × 1 = {len(words)})")
    print(f"Time elapsed: {total_time:.2f} seconds.")
    return found