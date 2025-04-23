"""Unit tests for server authentication, key management, and registration."""

import unittest
import datetime
import sqlite3
import json

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from server import app, initialize_db, save_private_key, fetch_private_key, generate_keys


class TestApp(unittest.TestCase):
    """Test class for validating server functionality"""

    @classmethod
    def setUpClass(cls):
        """Setup for the entire test class."""
        initialize_db()

    def setUp(self):
        """Setup for each test."""
        self.client = app.test_client()  # Creates a test client
        self.app = app
        self._clear_db()  # Clear the database before each test.

    def tearDown(self):
        """Clean up after each test."""
        self._clear_db()  # Clear the database after each test.

    def _clear_db(self):
        """Helper function to clear the database."""
        connection = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = connection.cursor()
        cursor.execute("DELETE FROM keys")  # Delete rows from the 'keys' table
        cursor.execute("DELETE FROM users")  # Delete rows from the 'users' table
        cursor.execute("DELETE FROM auth_logs")  # Clear auth logs
        connection.commit()
        connection.close()

    def test_initialize_db(self):
        """Test if the database and tables are initialized."""
        connection = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = connection.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
        )
        result = cursor.fetchone()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        )
        result_users = cursor.fetchone()
        connection.close()
        self.assertIsNotNone(result)
        self.assertIsNotNone(result_users)

    def test_generate_and_store_keys(self):
        """Test key generation and storage."""
        generate_keys()
        connection = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        connection.close()
        self.assertGreater(count, 0)

    def test_register_user(self):
        """Test user registration."""
        payload = {"username": "testuser", "email": "testuser@example.com"}
        response = self.client.post('/register', json=payload)
        self.assertEqual(response.status_code, 201)
        response_data = json.loads(response.data)
        self.assertIn('password', response_data)

    def authenticate_user(self, username, password):
        """Helper method to authenticate a user and return the response."""
        return self.client.post('/auth', json={
            "username": username,
            "password": password
        })

    def test_authenticate_user_success(self):
        """Test authentication with valid credentials."""
        generate_keys()
        payload = {"username": "testuser", "email": "testuser@example.com"}
        response = self.client.post('/register', json=payload)
        self.assertEqual(response.status_code, 201)
        response_data = json.loads(response.data)
        password = response_data['password']

        auth_payload = {"username": "testuser", "password": password}
        response = self.client.post('/auth', json=auth_payload)

        print(response.data.decode())

        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertIn('token', response_data)

        try:
            decoded_token = jwt.decode(response_data['token'], options={"verify_signature": False})
            self.assertIn('sub', decoded_token)
            self.assertIn('exp', decoded_token)
        except jwt.ExpiredSignatureError:
            self.fail("JWT token has expired")
        except jwt.InvalidTokenError as e:
            self.fail(f"JWT decoding failed: {e}")

    def test_authenticate_user_failure(self):
        """Test authentication with invalid credentials."""
        response = self.client.post('/auth', json={
            "username": "nonexistentuser",
            "password": "wrongpassword"
        })
        self.assertEqual(response.status_code, 401)

    def test_get_jwks(self):
        """Test the /.well-known/jwks.json endpoint."""
        generate_keys()
        response = self.client.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertIn('keys', response_data)
        self.assertGreater(len(response_data['keys']), 0)

    def test_get_private_key_from_db(self):
        """Test private key retrieval from the database."""
        valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        exp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600
        save_private_key(valid_key, exp)

        kid, key = fetch_private_key(expired=False)
        self.assertIsNotNone(kid)
        self.assertIsNotNone(key)

    def test_save_private_key_to_db(self):
        """Test saving a private key to the database."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        exp = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        save_private_key(private_key, exp)

        connection = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        connection.close()
        self.assertGreater(count, 0)

    def test_expired_key(self):
        """Test expired key handling."""
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 3600
        save_private_key(expired_key, expired_time)

        kid, private_key = fetch_private_key(expired=True)
        self.assertIsNotNone(kid)
        self.assertIsNotNone(private_key)

    def test_jwks_with_expired_keys(self):
        """Test if expired keys appear in the JWKS endpoint."""
        generate_keys()
        response = self.client.get('/.well-known/jwks.json?expired=true')
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertGreater(len(response_data['keys']), 0)

    def test_register_user_existing_email(self):
        """Test registration with existing email."""
        self.client.post('/register', json={"username": "user1", "email": "user1@example.com"})
        response = self.client.post(
            '/register', json={"username": "user2", "email": "user1@example.com"})
        self.assertEqual(response.status_code, 400)


if __name__ == '__main__':
    unittest.main()
