# Configuration for password cracker

# Maximum allowed length for brute-force attacks 
MAX_BRUTE_FORCE_LENGTH = 6

# Default character set that is used
DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyz1234567890"

# Hashlib() allows for more than this schemes but have only used these. Others can be added as needed.
ALLOWED_HASH_ALGORITHMS = ["md5", "sha1", "sha256"]