# Enhancing the Security and User Management in JWKS Server  
![Python Version](https://img.shields.io/badge/python-blue)

---

## **Overview**  
This project enhances the security and functionality of the basic JWKS server by introducing AES encryption for private keys, user registration capabilities, logging of authentication requests, and an optional rate limiter to control request frequency. The encryption and key management now provide stronger security for sensitive data, while the user registration system allows for safe handling of user credentials. 

---

## 📌 Requirements  
✅ **AES Encryption**: Encrypt private keys in the database using AES encryption, with the encryption key provided through the environment variable `NOT_MY_KEY`.  
✅ **User Registration**: Implement a user registration system with password hashing using Argon2, storing user data securely in a SQLite database.  
✅ **Authentication Logging**: Log each authentication request with details like request IP and timestamp into an `auth_logs` table.  
✅ **Rate Limiting (Optional)**: Implement a rate limiter for the `/auth` endpoint to limit requests to 10 per second. Requests exceeding this limit should return a `429 Too Many Requests` status.  
✅ **Environment Variable**: Use the environment variable `NOT_MY_KEY` to securely handle the AES encryption key.

---

## 📌 Endpoints  

| **Method** | **Endpoint**             | **Description**                              |  
| ---------- | ------------------------ | -------------------------------------------- |  
| `GET`      | `/.well-known/jwks.json` | Returns active public keys in JWKS format    |  
| `POST`     | `/auth`                  | Returns a signed JWT                         |  
| `POST`     | `/auth?expired=true`     | Returns a JWT signed with an expired key     |  
| `POST`     | `/register`              | Registers a new user                         |

---

## 🚀 Installation & Setup

### **Prerequisites**  
Before setting up the server, ensure you have the following:

- Python 3.x  
- Virtual Environment (Venv)  
- Flask (Web framework)  
- PyJWT (JWT Library)  
- SQLite (Database)  
- Argon2 (Password hashing)  
- Cryptography (For AES encryption)

### **1️⃣ Create a Virtual Environment**  
```bash  
python -m venv venv  
```

## 2️⃣ Activate the Virtual Environment

**Windows:**
```bash
.\venv\Scripts\activate
```

**Linux/macOS:**
```bash
source venv/bin/activate
```

---

## 3️⃣ Clone the Repository
```bash
git clone https://github.com/NiallJC/Enhancing-my-JWKS-server.git
cd Enhancing-my-JWKS-server
```

---

## 4️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 5️⃣ Set the Encryption Key

Make sure to set the environment variable `NOT_MY_KEY` with your AES encryption key:

**Windows (Powershell):**
```bash
$env:NOT_MY_KEY="your-encryption-key-here"
```

**Linux/macOS:**
```bash
export NOT_MY_KEY="your-encryption-key-here"
```

---

## 6️⃣ Initialize the Database & Run the Server
```bash
python server.py
```

---

## 7️⃣ Run Tests

To run the test suite, use the following command:
```bash
python -m pytest --cov=server --cov-report=term server_test_suite.py
```

---

# 🛠 How It Works

## AES Encryption
- Private keys are encrypted using AES (Advanced Encryption Standard) in the database.
- The encryption and decryption processes use the key provided through the `NOT_MY_KEY` environment variable.
- The encryption ensures that sensitive data like private keys are protected.

## User Registration
- A `/register` endpoint allows users to register with a unique username and email.
- The password is generated securely using UUIDv4 and then hashed using the Argon2 algorithm.
- The user’s hashed password and other details are stored in the database.

## Authentication Logging
- Authentication requests are logged into the `auth_logs` table.
- Information such as request IP, timestamp, and user ID are recorded for auditing purposes.

## Rate Limiting (Optional)
- The `/auth` endpoint has a rate limit of 10 requests per second.
- Requests exceeding this limit return a `429 Too Many Requests` status.

---

# ✅ Example Requests & Responses

## Retrieve JWKS

**Request:**
```bash
curl http://127.0.0.1:8080/.well-known/jwks.json
```

**Response:**
```json
{
  "keys": [
    {
      "alg": "RS256",
      "e": "AQAB",
      "kid": "1",
      "kty": "RSA",
      "n": "vhdL0XQ0Bw5BbJm2YPXL...",
      "use": "sig"
    }
  ]
}
```

---

## Issue a JWT

**Request:**
```bash
curl -X POST http://127.0.0.1:8080/auth -H "Content-Type: application/json" -d '{"username": "userABC"}'
```

**Response:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ..."
}
```

---

## Register a New User

**Request:**
```bash
curl -X POST http://127.0.0.1:8080/register -H "Content-Type: application/json" -d '{"username": "newUser", "email": "newuser@example.com"}'
```

**Response:**
```json
{
  "password": "123e4567-e89b-12d3-a456-426614174000"
}
```

---

# 📸 Screenshots

- 📌 Gradebot Output
- 📌 Test Suite Coverage Report

_Screenshots are included in the repository._

---

# ⭐ Future Improvements

- Implement full user authentication.
- Secure key storage (e.g., hardware security modules or encrypted storage).
- Add logging and monitoring for security events.
- Implement more granular rate limiting strategies.

---


