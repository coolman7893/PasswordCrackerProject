import time
from multiprocessing import Pool, Manager
from multiprocessing_utils import init_worker

# Generate variations of a word function
def generate_mutations(word):
    mutations = [word]  # Start with the original word
    
    mutations.append(word.capitalize())  # Add capitalization variations
    mutations.append(word.upper())
    mutations.append(word.lower())
    
    substitutions = {  # Define the character substitutions 
        'a': '@',
        'e': '3',
        'i': '!',
        'o': '0',
        's': '$',
        't': '7',
        'l': '1',
    }
    
    for char, replacement in substitutions.items():  # Add mutations with character substitutions
        if char in word.lower():
            substituted = word.replace(char, replacement).replace(char.upper(), replacement)  # Replace all occurrences
            if substituted != word:
                mutations.append(substituted)
                mutations.append(substituted.capitalize())
            
            idx = word.lower().find(char)  # Replace only first occurrence
            if idx != -1:
                first_replaced = word[:idx] + replacement + word[idx+1:]
                mutations.append(first_replaced)
                mutations.append(first_replaced.capitalize())
    
    for i, char in enumerate(word.lower()):  # Add mutations with substitution + different capital positions
        if char in substitutions:
            substituted = word.lower().replace(char, substitutions[char])
            for cap_pos in range(len(substituted)):
                if cap_pos < len(substituted):
                    varied = substituted[:cap_pos] + substituted[cap_pos].upper() + substituted[cap_pos+1:]
                    mutations.append(varied)
    
    for num in ['1', '2', '3', '123', '1234', '2024', '2023', '2022']:  # Add mutations with numbers appended
        mutations.append(word + num)
        mutations.append(word.capitalize() + num)
    
    for char in ['!', '@', '#', '$', '%']:  # Add mutations with special characters appended
        mutations.append(word + char)
        mutations.append(word.capitalize() + char)
    
    mutations.append(word.capitalize() + '2024!')  # Add combinations with number and special char
    mutations.append(word.capitalize() + '123!')
    
    seen = set()  # Remove duplicates while keeping order
    unique_mutations = []
    for mutation in mutations:
        if mutation not in seen:
            seen.add(mutation)
            unique_mutations.append(mutation)
    
    return unique_mutations

# Check a chunk of words with mutations (runs in parallel)
def check_hybrid_chunk(word_chunk, target_hash, attempt_counter, attempt_lock):
    import multiprocessing_utils
    
    if multiprocessing_utils.hash_func is None:  # Check if hash function is available
        return None, 0, 0

    attempts = 0
    total_mutations = 0
    for word in word_chunk:  # Try each word in the chunk
        if multiprocessing_utils.found_password_event.is_set():  # Stop if another process already found it
            with attempt_lock:
                attempt_counter.value += attempts
            return None, attempts, total_mutations
        
        mutations = generate_mutations(word)  # Generate mutations for this word
        total_mutations += len(mutations)
        
        for mutation in mutations:  # Try each mutation
            attempts += 1
            if multiprocessing_utils.found_password_event.is_set():  # Stop if password found
                with attempt_lock:
                    attempt_counter.value += attempts
                return None, attempts, total_mutations
            
            if multiprocessing_utils.hash_func(mutation.encode('utf-8')).hexdigest() == target_hash:  # Check if this mutation matches
                multiprocessing_utils.found_password_event.set()
                with attempt_lock:
                    attempt_counter.value += attempts
                return mutation, attempts, total_mutations
    
    with attempt_lock:  # Update counter when chunk is done
        attempt_counter.value += attempts
    
    return None, attempts, total_mutations

# Main hybrid attack function
def hybrid_attack(target_hash, algorithm, wordlist_path, num_processes):
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
    word_chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]
    total_chunks = len(word_chunks)
    
    sample_mutations_count = sum(len(generate_mutations(word)) for word in words[:min(100, len(words))])  # Estimate mutations per word by sampling first 100 words
    estimated_mutations_per_word = sample_mutations_count // min(100, len(words))
    estimated_total_mutations = estimated_mutations_per_word * len(words)
    
    print(f"Base dictionary words: {len(words)}")  # Print estimation info
    print(f"Estimated mutations per word: ~{estimated_mutations_per_word}")
    print(f"Estimated total passwords to try: ~{int(estimated_total_mutations)} ({len(words)} words × {estimated_mutations_per_word} mutations)")

    found = None
    total_attempts = 0
    total_mutations_generated = 0
    
    with Manager() as manager:  # Use multiprocessing manager for shared counter
        attempt_counter = manager.Value('i', 0)
        attempt_lock = manager.Lock()
        
        with Pool(processes=num_processes, initializer=init_worker, initargs=(manager.Event(), algorithm)) as pool:  # Create process pool
            tasks = [(chunk, target_hash, attempt_counter, attempt_lock) for chunk in word_chunks]  # Create tasks for each chunk
            results = pool.starmap_async(check_hybrid_chunk, tasks)  # Run all tasks in parallel
            
            try:
                print("Running hybrid attack...")
                final_results = results.get()  
                
                for result in final_results:  # Check if any task found the password
                    if result[0]:  # Password found
                        found = result[0]
                        break
                    total_mutations_generated += result[2]
                        
            except KeyboardInterrupt:
                print("\nHybrid attack interrupted.")
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
        print(f"\nFAILED: Password not found with mutations.")

    print(f"Total attempts: {total_attempts}")
    print(f"Time elapsed: {total_time:.2f} seconds.")
    return found