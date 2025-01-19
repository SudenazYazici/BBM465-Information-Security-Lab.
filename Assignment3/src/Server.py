import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

class Server:
    def __init__(self):
        self.db_file = "database.txt"
        self.private_key = None
        self.public_key = None
        self.load_keys()
        if not os.path.exists(self.db_file):
            self.init_database()

    def load_keys(self):
        """Load RSA keys from files"""
        with open("private.pem", "rb") as priv_file:
            self.private_key = RSA.import_key(priv_file.read())
        with open("public.pem", "rb") as pub_file:
            self.public_key = RSA.import_key(pub_file.read())

    def init_database(self):
        """Initialize an empty encrypted database file"""
        open(self.db_file, "wb").close()

    def encrypt_database_line_by_line(self, users):
        """Encrypt database contents line by line and save to file"""
        cipher = PKCS1_OAEP.new(self.public_key)
        with open(self.db_file, "wb") as db:
            for user in users:
                encrypted_line = cipher.encrypt(user.encode())
                db.write(len(encrypted_line).to_bytes(2, "big") + encrypted_line)

    def decrypt_database_line_by_line(self):
        """Decrypt database contents line by line and return as a list"""
        cipher = PKCS1_OAEP.new(self.private_key)
        users = []
        with open(self.db_file, "rb") as db:
            while True:
                length_bytes = db.read(2)
                if not length_bytes:
                    break
                length = int.from_bytes(length_bytes, "big")
                encrypted_line = db.read(length)
                decrypted_line = cipher.decrypt(encrypted_line)
                users.append(decrypted_line.decode())
        return users

    def register_user(self, username, hashed_password, otp_chain):
        """Register a new user and update the encrypted database"""
        users = self.decrypt_database_line_by_line()
        for user in users:
            stored_username = user.split(";")[0]
            if stored_username == username:
                return False, "User already exists."

        new_user = f"{username};{hashed_password};{otp_chain[0]};100"
        users.append(new_user)
        self.encrypt_database_line_by_line(users)
        return True, "User registered successfully."

    def validate_login(self, username, hashed_password):
        """Validate login credentials"""
        users = self.decrypt_database_line_by_line()
        for user in users:
            stored_username, stored_password, _, _ = user.split(";")
            if stored_username == username and stored_password == hashed_password:
                return True, "Login successful."
        return False, "Invalid username or password."

    def get_next_otp(self, username):
        """Get the next OTP in the chain for a user"""
        users = self.decrypt_database_line_by_line()
        for user in users:
            stored_username, _, stored_otp, _ = user.split(";")
            if stored_username == username:
                return stored_otp
        return None

    def validate_otp(self, username, otp):
        """Validate OTP and update OTP chain"""
        users = self.decrypt_database_line_by_line()
        for i, user in enumerate(users):
            stored_username, hashed_password, stored_otp, counter = user.split(";")
            if stored_username == username and stored_otp == otp:
                if int(counter) <= 1:
                    # Generate new OTP chain when chain is exhausted
                    new_otp_chain = self.generate_otp_chain(hashed_password)  # Use hashed password as the seed
                    users[i] = f"{username};{hashed_password};{new_otp_chain[0]};100"
                    self.encrypt_database_line_by_line(users)            
                    return True, "OTP validated successfully. New OTP chain generated."
                
                new_otp = SHA256.new(otp.encode()).hexdigest()
                users[i] = f"{username};{hashed_password};{new_otp};{int(counter) - 1}"
                self.encrypt_database_line_by_line(users)
                return True, "OTP validated successfully."
        return False, "Invalid OTP."

    def generate_otp_chain(self, password, n=100):
        """Generate a hash chain for OTP"""
        otp_chain = []
        current = password
        for _ in range(n):
            hashed = SHA256.new(current.encode()).hexdigest()
            otp_chain.append(hashed)
            current = hashed
        return otp_chain[::-1]  # Reverse for chain order