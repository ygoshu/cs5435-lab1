from csv import reader
import hashlib, binascii
from app.util.hash import * 

COMMON_PASSWORDS_PATH = 'common_passwords.txt'
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def load_common_passwords():
    with open(COMMON_PASSWORDS_PATH) as f:
        pws = list(reader(f))
    return pws

def brute_force_attack(target_hash, target_salt):
    common_passwords = load_common_passwords()
    salt_hashed_password_2_password = {}
    for password in common_passwords:
        salt_hashed_password = hash_pbkdf2(password[0], target_salt)
        salt_hashed_password_2_password[salt_hashed_password] = password[0]
    if (target_hash in salt_hashed_password_2_password):
        return salt_hashed_password_2_password[target_hash]
    else:
        return None

def main():
    salted_creds = load_breach(SALTED_BREACH_PATH)
    brute_force_attack(salted_creds[0][1], salted_creds[0][2])

if __name__ == "__main__":
    main()
