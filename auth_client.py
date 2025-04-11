from __future__ import annotations
import datetime
from functools import wraps
import re
from typing import Any, Callable, Literal
from client import Client, run_client
from tests.test_key import KEY
import time
import hashlib
import hmac
from dotenv import load_dotenv
import os
import jwt
import sqlite3
import uuid

# Load environment variables from .env file
load_dotenv()

#####
# Rate limiting will be handled with crow
#
# This client will read and write to an sqlite database that is stored and
# backed up on two different hardrives.
#####

SALT = os.getenv("salt").encode('utf-8')
HMAC_KEY = os.getenv("hmac_key").encode('utf-8')
JWT_KEY = os.getenv("jwt_key").encode('utf-8')
JWT_REFRESH_SECRET = os.getenv("jwt_refresh_secret").encode('utf-8')
API_KEY_SALT = os.getenv("api_key_salt").encode('utf-8')

example_packet = {
    "service":"login",
    "email":"wdjiwji@wjidjiw.com",
    "password":"jjdwijo2989j2893dnienjnei"
}

# Token expiration times
ACCESS_EXPIRE = 15 * 60  # 15 minutes
REFRESH_EXPIRE = 7 * 24 * 60 * 60  # 7 days

class AuthFailed(Exception):
    def __init__(self, msg:str = "Authorization failed.", *args):
        self.msg = msg
        super().__init__(*args)

class InvalidSubmission(Exception):
    def __init__(self, msg:str = "Invalid submission.", *args):
        self.msg = msg
        super().__init__(*args)



def hash_s256(input_string:bytes|str):
    hmac_hash = hmac.new(HMAC_KEY, (input_string if isinstance(input_string, bytes) else input_string.encode()) + SALT, hashlib.sha256)
    return hmac_hash.digest()

def verify_jwt(token:str, secret:str):
    try:
        return jwt.decode(token, secret, algorithm="HS256")
        # TODO Verify payload with database
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        raise AuthFailed
    
EMAIL_REGEX = re.compile(
    r"^(?P<local>[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*)"
    r"@"
    r"(?P<domain>(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$"
)

PASSWORD_REGEX = re.compile(
    r"^(?=(.*\d.*){3,})(?=(.*[A-Z].*){1,})(?=(.*[^\w\s].*){1,}).{12,}$"
)

def is_valid_email(email:str) -> bool:
    return bool(EMAIL_REGEX.match(email))

def is_valid_password(password:str|bytes) -> bool:
    if isinstance(password, bytes):
        password = password.decode()
    return bool(PASSWORD_REGEX.match(password))

def create_response(success:bool = True, **kwargs:dict[str, Any]) -> dict:
    return {
        "success":success,
        **kwargs
    }

def service_type(s_type:str):
    def decorator(func):
        @wraps(func)
        def wrapper(self, full_data:dict[str, Any]):
            return func(self, full_data["data"])
        wrapper._s_type = s_type
        return wrapper
    return decorator

class ServiceBase:
    services:dict[str, Callable] = {}
    available_services:set[str] = set()

    def __init_subclass__(cls):
        super().__init_subclass__()
        cls.available_services:set[str] = set()
        cls.services:dict[str, Callable] = {}

        for name, method in cls.__dict__.items():
            if hasattr(method, "_s_type"):
                key = method._s_type
                cls.available_services.add(key)
                cls.services[key] = method


class AccountClient(Client[dict[Literal["db_path"], str]], ServiceBase):
    client_type = b"Auth"
    
    # SQL QUERIES

    def sql_account_exists(self, email:str, password_hash:str|bytes) -> bool:
        cursor = self.sql_conn.cursor()
        cursor.execute("SELECT 1 FROM credential WHERE email = ? AND password = ? LIMIT 1", (email, password_hash))
        valid = cursor.fetchone() is not None
        self.sql_conn.commit()
        cursor.close()
        return valid
    
    def sql_get_account_id(self, email:str, password_hash:str|bytes) -> int|None:
        cursor = self.sql_conn.cursor()
        cursor.execute("SELECT id FROM credential WHERE email = ? AND password = ? LIMIT 1", (email, password_hash))
        id = cursor.fetchone()
        self.sql_conn.commit()
        cursor.close()
        if id:
            return id[0]
    
    def sql_email_exists(self, email:str) -> bool:
        cursor = self.sql_conn.cursor()
        cursor.execute("SELECT 1 FROM credential WHERE email = ? LIMIT 1", (email,))
        valid = cursor.fetchone() is not None
        self.sql_conn.commit()
        cursor.close()
        return valid
    
    def sql_verify_refresh_token(self, token:str|bytes) -> bool:
        cursor = self.sql_conn.cursor()
        cursor.execute("SELECT 1 FROM refresh_token WHERE token = ? LIMIT 1", token)
        valid = cursor.fetchone() is not None
        self.sql_conn.commit()
        cursor.close()
        return valid
    
    def sql_set_refresh_token(self, id:int, token:str):
        cursor = self.sql_conn.cursor()
        cursor.execute("""
            INSERT INTO refresh_token (token, credential_id)
            VALUES (?, ?)
            ON CONFLICT(credential_id) DO UPDATE SET
                token = excluded.token;
        """, (token, id))
        self.sql_conn.commit()
        cursor.close()
        return token

    
    def sql_verify_api_key(self, key:str|bytes) -> bool:
        cursor = self.sql_conn.cursor()
        cursor.execute("SELECT 1 FROM api_key WHERE key = ? LIMIT 1", (key,))
        valid = cursor.fetchone() is not None
        self.sql_conn.commit()
        cursor.close()
        return valid
    
    def sql_create_api_key(self, credential_id:int) -> str:
        
        cursor = self.sql_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM api_key")
        num_keys = cursor.fetchone()[0]

        now_dt = datetime.datetime.now()

        api_key = hash_s256(f"{API_KEY_SALT}{num_keys}{credential_id}{now_dt.hour}{now_dt.microsecond}{now_dt.day}{now_dt.year}{now_dt.month}{now_dt.minute}")

        cursor.execute("""
            INSERT INTO api_key (credential_id, key) VALUES (?, ?)
            ON CONFLICT(credential_id) DO UPDATE SET
                key = excluded.key;
            """, (credential_id, api_key))
        

        self.sql_conn.commit()
        cursor.close()
        
        return api_key.decode()
    
    def sql_register_account(self, email:str, password:str, DOB:datetime.date, first_name:str, last_name:str):

        # TODO
        
        cursor = self.sql_conn.cursor()
        cursor.execute("INSERT INTO credential (email, password) VALUES (?, ?)", (email, password))

        
        try:
            cursor.execute("INSERT INTO user (id, date_of_birth, first_name, last_name) SELECT id, ?, ?, ? FROM credential WHERE email = ? and password = ?", (DOB, first_name, last_name, email, password))
        except sqlite3.Error:
            cursor.execute("DELETE FROM credential WHERE email = ? and password = ?", (email, password))
            self.sql_conn.commit()
            cursor.close()
            raise sqlite3.Error
        
        self.sql_conn.commit()
        cursor.close()
        
    # END SQL QUERIES

    def before_connect(self):
        self.sql_conn = sqlite3.connect(self.cli_args['db_path'])
        cursor = self.sql_conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS credential (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email VARCHAR(30) UNIQUE,
            password CHAR(64)  -- SHA-256 hashes are 64 hex characters
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_id INTEGER UNIQUE,
            date_of_birth DATE,
            first_name CHAR(30),
            last_name CHAR(30),
            FOREIGN KEY (credential_id) REFERENCES credential(id) ON DELETE CASCADE ON UPDATE CASCADE
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS refresh_token (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_id INTEGER UNIQUE,
            token TEXT UNIQUE,
            FOREIGN KEY (credential_id) REFERENCES credential(id) ON DELETE CASCADE ON UPDATE CASCADE
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_key (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_id INTEGER UNIQUE,
            key CHAR(64) UNIQUE,
            FOREIGN KEY (credential_id) REFERENCES credential(id) ON DELETE CASCADE ON UPDATE CASCADE           
        );
        """)

        cursor.close()
        
        self.sql_conn.commit()
    
    def create_access_token(self, user_id: int|str) -> str:
        payload = {"sub": str(user_id), "exp": time.time() + ACCESS_EXPIRE}
        return jwt.encode(payload, JWT_KEY, algorithm="HS256")
    
    def create_refresh_token(self, user_id: int|str) -> str:
        payload = {"sub": str(user_id), "jti": str(uuid.uuid4()), "exp": time.time() + REFRESH_EXPIRE}
        token = jwt.encode(payload, JWT_REFRESH_SECRET, algorithm="HS256")
        self.sql_set_refresh_token(user_id, token)
        return token

    def verify_refresh_token(self, token:str):
        try:
            # Verify that the token is a valid JWT token
            verify_jwt(token, JWT_REFRESH_SECRET)
            
            return self.sql_verify_refresh_token(token)
        except jwt.ExpiredSignatureError:
            raise False
        except jwt.InvalidTokenError:
            raise False

    @service_type("login")
    def login(self, data:dict[str, Any]):
        EMAIL = data["email"]
        PASSWORD = hash_s256(data["password"])

        # Verify login with database.
        ID = self.sql_get_account_id(EMAIL, PASSWORD)

        if ID is None:
            raise AuthFailed
        
        # Use ID to create jwt tokens

        return create_response(access_token = self.create_access_token(ID), refresh_token = self.create_refresh_token(ID))
    
    @service_type("refresh_login")
    def refresh_login(self, data:dict[str, Any]):
        ACCOUNT_JWT = data["refresh_token"]

        payload = self.verify_refresh_token(ACCOUNT_JWT)

        ID = payload["sub"]

        return create_response(access_token = self.create_access_token(ID), refresh_token = self.create_refresh_token(ID))
    
    @service_type("verify_account")
    def verify_account(self, data:dict[str, Any]):
        ACCOUNT_JWT = data["access_token"]

        verify_jwt(ACCOUNT_JWT, JWT_KEY)

        return create_response(success=True)
    
    @service_type("register")
    def register(self, data:dict[str, Any]):
        EMAIL = data["email"]
        F_NAME:str = data["first_name"]
        L_NAME:str = data["last_name"]

        if not F_NAME.isalpha() or \
        not L_NAME.isalpha() or \
        len(F_NAME) < 1 or len(L_NAME) < 1:
            raise InvalidSubmission("First and Last name should be provided and must only use letters.")

        if not is_valid_email(EMAIL):
            raise InvalidSubmission("Not a valid email.")
        
        if self.sql_email_exists(EMAIL):
            raise InvalidSubmission("Account already exists.")
        
        try:
            DOB = datetime.datetime.strptime(data["DOB"], "%Y-%m-%d").date()
            today_date = datetime.date.today()
            if DOB > datetime.date(today_date.year - 13, today_date.month, today_date.day):
                # Under 13 years old
                raise InvalidSubmission("User must be 13 years or older to register an account.")
        except ValueError:
            # incorrect format (this should never trigger unless someone is spoofing the frontend)
            raise InvalidSubmission("Bad date of birth format.")

        if not is_valid_password(data["password"]):
            raise AuthFailed("Password must be at least 12 characters, contain at least 3 digits, at least 1 capital letter and at least 1 symbol.")

        PASSWORD = hash_s256(data["password"])
        RE_PASSWORD = hash_s256(data["re-password"])

        if PASSWORD != RE_PASSWORD:
            raise AuthFailed("Passwords do not match.")

        self.sql_register_account(EMAIL, PASSWORD, DOB, F_NAME, L_NAME)

        return create_response(success=True)
    
    @service_type("verify_API_key")
    def verify_api_key(self, data:dict[str, Any]):
        API_KEY = data["api_key"]
        return create_response(
            success=self.sql_verify_api_key(API_KEY)
        )
    
    @service_type("generate_API_key")
    def generate_api_key(self, data:dict[str, Any]):
        ACCOUNT_JWT = data["access_token"]

        payload = verify_jwt(ACCOUNT_JWT, JWT_KEY)

        ID = payload["sub"]

        api_key = self.sql_create_api_key(ID)

        return create_response(success=True, api_key = api_key)

    def handle_workload(self, incoming:dict|list) -> tuple[list[int|float]]:
        outgoing = create_response(success=False, error="Authorization failed.")
        try:
            req_service = incoming["service"]
            print(req_service, "in", self.available_services)
            if req_service in self.available_services:
                outgoing = self.services[req_service](self, incoming)
            else:
                raise AuthFailed("Malformed authorization request.")
        except AuthFailed as e:
            outgoing = {"error":e.msg, "success":False}
        except InvalidSubmission as e:
            outgoing = {"error":e.msg, "success":False}
        # except Exception as e:
        #     print(e)
        #     outgoing = {"error":"Malformed authorization request.", "success":False}
        print(outgoing)
        return outgoing
    
if __name__ == "__main__":
    run_client(AccountClient, db_path=(str, "The path to the sql database."))