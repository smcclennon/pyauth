import os, hashlib, json, base64

# Print coloured debug messages if True
debug_messages = True
def debug(message, status='debug'):
    if debug_messages:
        colours = {
            "grey": "\033[0;37m",
            "yellow_bold": "\033[1;33m",
            "red": "\033[0;31m",
            "green": "\033[0;32m",
            "end": "\033[0m"
        }
        if status == 'debug':
            status_colour = colours["grey"]
        elif status == 0:
            status_colour = colours["green"]
        elif status == 1:
            status_colour = colours["red"]
        print(f'{colours["yellow_bold"]}DEBUG: {colours["end"]}{status_colour}{message}{colours["end"]}')


# Backend modules handling cryptography and codecs
class Codec():

    # https://nitratine.net/blog/post/how-to-hash-passwords-in-python/
    def hash(password, **kwargs):
        debug('Hashing password')
        # Generate secure random salt
        new_salt = os.urandom(32)
        # Use salt argument over new_salt if provided
        salt = kwargs.get("salt", new_salt)

        # Generate key
        key = hashlib.pbkdf2_hmac(
            "sha256", # The hash digest algorithm for HMAC
            password.encode("utf-8"), # Convert the password to bytes
            salt, # Provide the salt
            100000 # It is recommended to use at least 100,000 iterations of SHA-256 
        )
        return salt, key

    def b64_encode(original_bytes):
        debug('Encoding bytes to base64')
        # Input: b'T\x8b[m\xa7>'
        base64_bytes = base64.b64encode(original_bytes)  # Encode with base64: b'VItbbac+'
        base64_string = base64_bytes.decode('utf-8')  # Bytes to string: 'VItbbac+'
        return base64_string

    def b64_decode(base64_string):
        debug('Decoding base64 to bytes')
        # Input: 'VItbbac+'
        base64_bytes = base64_string.encode('utf-8')  # b'VItbbac+'
        original_bytes = base64.b64decode(base64_bytes)  # Decode from base64: b'T\x8b[m\xa7>'
        return original_bytes


# Interface with database file
class Db_interface():
    user_db_filename = 'user_db'
    
    def save_db():
        debug('Saving database to disk')
        with open(f"{Db_interface.user_db_filename}.json", "w") as user_db_file:
            json.dump(Db_interface.users, user_db_file)
            debug('Wrote database to disk', 0)
    
    def load_db():
        debug('Loading database from disk')
        while True:
            try:
                # Load user database from file
                with open(f"{Db_interface.user_db_filename}.json", "r") as user_db_file:
                    # Store contents of file as string
                    # These contents are backed up if JSON load fails
                    user_db_string = user_db_file.read()
                    # Attempt to load file contents as JSON
                    user_db = json.loads(user_db_string)
                # Print success message
                debug('Loaded database!', 0)
                # Database loaded successfully, stop looping
                return user_db

            # If JSON is erroneous, backup file and delete original
            except json.decoder.JSONDecodeError as e:
                # New variable name for clarity
                user_db_backup = user_db_string
                # Open Create backup file
                with open(f"{Db_interface.user_db_filename}_backup.json", "w") as user_db_backup_file:
                    # Write erroneous file contents to backup file
                    user_db_backup_file.write(user_db_backup)
                debug(f'Erroneous database detected and backed up [{e}]', 1)
                # Delete original erroneous file, and re-loop to create new file
                os.remove(f'{Db_interface.user_db_filename}.json')

            # If original file missing, recreate with blank data
            except FileNotFoundError:
                debug('No database found', 1)
                # Create new file
                with open(f"{Db_interface.user_db_filename}.json", "w") as user_db_file:
                    # Initialise with empty JSON data structure
                    json.dump(dict(), user_db_file)
                # Print debug message and re-loop (to load database in to variable)
                debug('Created new database', 0)

    def getcreds(username):
        debug(f'Getting credentials for "{username}"')
        creds = []
        for item in ["salt", "key"]:
            encoded_item = Db_interface.users[username][item]
            decoded_item = Codec.b64_decode(encoded_item)
            creds.append(decoded_item)
        debug('Credentials retrieved!', 0)
        return creds[0], creds[1]  # return salt, key

    def putcreds(username, salt, key):
        debug(f'Putting credentials for "{username}"')
        creds = []
        for item in [salt, key]:
            encoded_item = Codec.b64_encode(item)
            creds.append(encoded_item)
        Db_interface.users[username]["salt"] = creds[0]
        Db_interface.users[username]["key"] = creds[1]
        debug('Put credentials!', 0)
        Db_interface.save_db()


# Authentication code
class Auth():

    def authenticate(username, password):
        debug(f'Authenticating "{username}"')
        if username in Db_interface.users:
            # Get correct keys from database, converting string back to bytes
            original_salt, original_key = Db_interface.getcreds(username)

            # Generate new keys using provided credentials
            original_salt, new_key = Codec.hash(password, salt=original_salt)

            # Compare new keys to correct keys
            if original_key == new_key:
                debug('Authentication success!', 0)
                return "success"
            else:
                debug('Authentication failure, invalid_password', 1)
                return "invalid_password"
        else:
            debug('Authentication failure, invalid_user', 1)
            return "invalid_user"

    def register(username, password):
        debug(f'Registering {username}')
        if username in Db_interface.users:
            debug('Registration failure, username_taken', 1)
            return "username_taken"
        else:
            # Generate secure keys for storage
            salt, key = Codec.hash(password)

            # Initialise user entry
            Db_interface.users[username] = {
                "salt": "",
                "key": "",
                "example_data": 0
            }
            # Store non-plaintext password
            Db_interface.putcreds(username, salt, key)
            debug('Registration success!', 0)
            return "success"


# Frontend code
class Display:
    
    def secure(username):
        print('\n* Top secret information')
        print(f'Welcome, {username}')
        input('[press enter to go back]')

    def login():
        print("\n== Login ==")
        username = input("Username: ")
        password = input("Password: ")
        choice = input("1. [Login]\n2. [Register]\n")

        if choice.lower() in ["login", "l", "1"]:
            # Generate keys for provided credentials and compare against database
            auth_response = Auth.authenticate(username, password)

            # Handle response code
            if auth_response == "success":
                Display.secure(username)
            elif auth_response == "invalid_user":
                print("User does not exist")
            elif auth_response == "invalid_password":
                print("Incorrect password")

        elif choice in ["register", "r", "2"]:
            # Generate secure keys and attempt to store
            register_response = Auth.register(username, password)

            # Handle response code
            if register_response == "success":
                Display.secure(username)
            elif register_response == "username_taken":
                print("Username taken")

    def main_menu():
        while True:
            print("\n== Welcome ==")
            Display.login()

Db_interface.users = Db_interface.load_db()
Display.main_menu()