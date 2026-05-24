import hashlib
import os
import pyotp
from typing import List, Optional
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr
import uvicorn

app = FastAPI(
    title="Health Passport Secure Backend",
    version="1.0.0",
    description="Secure SHA-256 PBKDF2 and TOTP Two-Factor Authenticated Medical Ledger maybe it will use USSD IDK"
)

#Memory database stores (Connect to PostgreSQL/SQLAlchemy in production)
USERS_DB = {}
HEALTH_PASSPORTS = {}


# SHA-256 PBKDF2 Hashing

def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:

    #Generates a secure SHA-256 hash derived with PBKDF2 standard i guess.
    if not salt:
        salt = os.urandom(16)  # Cryptographically secure salt (16 bytes)
    # RFC 2898 standard: 100,000 hashing loops
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return pwd_hash.hex(), salt.hex()


def verify_password(stored_hash: str, salt_hex: str, raw_password: str) -> bool:
    #Matches verification password with hashed saaaaaaaalt signature???.
    try:
        salt_bytes = bytes.fromhex(salt_hex)
        new_hash, _ = hash_password(raw_password, salt_bytes)
        return new_hash == stored_hash
    except Exception:
        return False


#Pydantic Data Models (Type-checked validation schemas)

class PatientSignUp(BaseModel):
    email: EmailStr
    password: str


class SignUpResponse(BaseModel):
    email: EmailStr
    totp_secret: str
    totp_uri: str
    # I will used by Kotlin App to generate visual setup QR Code


class CodeVerification(BaseModel):
    email: EmailStr
    totp_token: str


class PassportRecord(BaseModel):
    id: str
    date: str  # YYYY-MM-DD
    facility: str  # Hospital name
    practitioner: str  # MD or Specialist ooooor docucter
    diagnosis: str  # Diagnostic findings
    prescription: Optional[str] = None
    notes: Optional[str] = None


# API Secure Endpoints

@app.post("/api/auth/register", response_model=SignUpResponse, status_code=201)
def register_patient(payload: PatientSignUp):
    if payload.email in USERS_DB:
        raise HTTPException(status_code=400, detail="Account already registered under this email")

    # Hash raw password cleanly
    stored_hash, salt_hex = hash_password(payload.password)

    # Instantiate 2nd-factor authentication secret key (Google Authenticator suite)
    totp_secret = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name=payload.email,
        issuer_name="HealthPassportSystem"
    )

    USERS_DB[payload.email] = {
        "password_hash": stored_hash,
        "salt": salt_hex,
        "totp_secret": totp_secret,
        "is_two_factor_verified": False
    }


    # Initialize??? ledger history
    HEALTH_PASSPORTS[payload.email] = []

    return {
        "email": payload.email,
        "totp_secret": totp_secret,
        "totp_uri": totp_uri
    }


@app.post("/api/auth/verify-2fa")
def verify_2fa_token(payload: CodeVerification):
    user = USERS_DB.get(payload.email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")

    # Verify TOTP dynamically based on RFC 6238 time-step bounds
    totp_verifier = pyotp.TOTP(user["totp_secret"])
    if totp_verifier.verify(payload.totp_token):
        user["is_two_factor_verified"] = True
        return {"status": "authorized", "message": "Two factor validation accomplished successfully."}

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA token code")


@app.get("/api/passport/{email}", response_model=List[PassportRecord])
def get_health_records(email: str):
    if email not in HEALTH_PASSPORTS:
        raise HTTPException(status_code=404, detail="No Health Passport assigned to this patient account.")
    return HEALTH_PASSPORTS[email]


@app.post("/api/passport/{email}", response_model=PassportRecord)
def append_passport_record(email: str, record: PassportRecord):
    if email not in HEALTH_PASSPORTS:
        raise HTTPException(status_code=404, detail="Patient file not found.")

    HEALTH_PASSPORTS[email].append(record)
    return record
@app.get("/")
def root():
    return{ "Message": "Health Passport API is running use 127.0.0.1:8000/docs", "docs":"/docs "


    }








if __name__ == "__main__":
    uvicorn.run("Health Passport System:app", host="127.0.0.1", port=8000, reload=True)
