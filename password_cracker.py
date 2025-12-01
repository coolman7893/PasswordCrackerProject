import argparse
import sys
import os
from hash_utils import hash_password
from dictionary_attack import dictionary_attack
from brute_force_attack import brute_force_attack
from hybrid_attack import hybrid_attack
from configuration import MAX_BRUTE_FORCE_LENGTH, DEFAULT_CHARSET, ALLOWED_HASH_ALGORITHMS

# Figure out which hash type it is by looking at its length
def detect_hash_algorithm(hash_string):
    length = len(hash_string)
    if length == 32:
        return "md5"
    elif length == 40:
        return "sha1"
    elif length == 64:
        return "sha256"
    else:
        return None

def main():
    # Set up the command-line interface
    parser = argparse.ArgumentParser(
        description="A simple password cracker tool (Multiprocessing)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Create the hash command
    hash_parser = subparsers.add_parser(
        "hash", help="Hash a plaintext password.")
    hash_parser.add_argument(
        "-p", "--password",
        required=True,
        help="The plaintext password to hash."
    )
    hash_parser.add_argument(
        "-a", "--algorithm",
        required=True,
        help="Hash algorithm (e.g., md5, sha1, sha256)."
    )

    crack_parser = subparsers.add_parser(
        "crack", help="Crack a given password hash.")
    # The hash we want to crack
    crack_parser.add_argument(
        "-H", "--hash",
        dest="target_hash",
        required=True,
        help="The target password hash to crack."
    )
    # Optional - Which hash type was used to hash the password 
    crack_parser.add_argument(
        "-a", "--algorithm",
        help="Hash algorithm used to create the hash (e.g., md5, sha256). If not specified, will attempt to detect from hash length."
    )

    # Choose which attack to use
    attack_group = crack_parser.add_mutually_exclusive_group(required=True)
    attack_group.add_argument(
        "-d", "--dictionary",
        dest="wordlist_path",
        help="Path to the dictionary file for a dictionary attack."
    )
    attack_group.add_argument(
        "-hy", "--hybrid",
        dest="hybrid_wordlist_path",
        help="Path to the dictionary file for a hybrid attack."
    )
    attack_group.add_argument(
        "-b", "--brute-force",
        action="store_true",
        help="Enable brute-force attack."
    )

    brute_force_group = crack_parser.add_argument_group("Brute-Force Options")

    args = parser.parse_args()

    # Hash command - create a hash from a password
    if args.command == "hash":
        if args.algorithm not in ALLOWED_HASH_ALGORITHMS:
            print(f"Error: Unsupported hash algorithm '{args.algorithm}'. Allowed: {ALLOWED_HASH_ALGORITHMS}")
            sys.exit(1)
        hashed_val = hash_password(args.password, args.algorithm)
        print(f"Password: {args.password}")
        print(f"Algorithm: {args.algorithm}")
        print(f"Hash: {hashed_val}")

    elif args.command == "crack":
        # Set how many processes to use (up to 12)
        num_processes = min(os.cpu_count() or 4, 12)
        
        # Make the hash lowercase so it's easier to compare
        args.target_hash = args.target_hash.lower()

        # Use the given hash type, or guess it from the length
        if args.algorithm:
            if args.algorithm not in ALLOWED_HASH_ALGORITHMS:
                print(f"Error: Unsupported hash algorithm '{args.algorithm}'. Allowed: {ALLOWED_HASH_ALGORITHMS}")
                sys.exit(1)
            algorithm = args.algorithm
        else:
            algorithm = detect_hash_algorithm(args.target_hash)
            if not algorithm:
                print(f"Error: Could not detect hash algorithm from hash length ({len(args.target_hash)} characters).")
                print(f"Supported lengths: 32 (MD5), 40 (SHA-1), 64 (SHA-256)")
                sys.exit(1)
            print(f"Using hash length {len(args.target_hash)}, probable hash is: {algorithm}")

        if args.wordlist_path:
            # Dictionary attack - try words from a list
            print(f"Now breaking {algorithm} hash using dictionary attack...")
            dictionary_attack(
                args.target_hash,
                algorithm,
                args.wordlist_path,
                num_processes
            )
        elif hasattr(args, 'hybrid_wordlist_path') and args.hybrid_wordlist_path:
            # Hybrid attack - try words plus variations
            print(f"Now breaking {algorithm} hash using hybrid attack...")
            hybrid_attack(
                args.target_hash,
                algorithm,
                args.hybrid_wordlist_path,
                num_processes
            )
        elif args.brute_force:
            # Brute-force attack - try all possible combinations
            print(f"Now breaking {algorithm} hash using brute force...")
            
            # Run the brute-force attack
            brute_force_attack(
                args.target_hash,
                algorithm,
                DEFAULT_CHARSET,
                MAX_BRUTE_FORCE_LENGTH,
                num_processes
            )


# Start the program
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user. Exiting.")
        sys.exit(0)