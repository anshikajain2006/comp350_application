"""
Comprehensive Unit Test Suite for PIM System
Tests for auth_module, storage_module, particle_module, and main API endpoints
"""

import unittest
import tempfile
import os
import sqlite3
import json
import datetime
from unittest.mock import patch, MagicMock, Mock
import secrets
import hmac
import hashlib
from dataclasses import dataclass
from typing import Optional, List
import uuid

# Import modules to test
import auth_module as auth
import storage_module as storage
import particle_module as particles
from fastapi.testclient import TestClient
from main import app


class TestAuthModule(unittest.TestCase):
    """Test cases for authentication module functions"""
    
    def setUp(self):
        """Set up test database and environment"""
        self.test_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.test_db_path = self.test_db.name
        self.test_db.close()
        
        # Initialize test database
        storage.init_database(self.test_db_path)
        particles.init_particles_db(self.test_db_path)
        
        # Mock server secret
        self.original_secret = auth.server_secret
        auth.server_secret = b'test_secret_key_for_testing_only'
    
    def tearDown(self):
        """Clean up test database"""
        auth.server_secret = self.original_secret
        try:
            os.unlink(self.test_db_path)
        except:
            pass
    
    def test_hex_encode_decode(self):
        """Test hexadecimal encoding and decoding"""
        test_bytes = b'test_data_123'
        encoded = auth.hex_encode(test_bytes)
        self.assertIsInstance(encoded, str)
        
        decoded = auth.hex_decode(encoded)
        self.assertEqual(decoded, test_bytes)
        
        # Test empty string
        self.assertEqual(auth.hex_decode(''), b'')
        self.assertEqual(auth.hex_decode(None), b'')
    
    def test_hash_password(self):
        """Test password hashing functionality"""
        password = "SecurePassword123!"
        salt_hex, hash_hex = auth.hash_password(password)
        
        self.assertIsInstance(salt_hex, str)
        self.assertIsInstance(hash_hex, str)
        self.assertEqual(len(auth.hex_decode(salt_hex)), auth.SALT_BYTES)
        self.assertEqual(len(auth.hex_decode(hash_hex)), auth.HASH_BYTES)
        
        # Same password should generate different salts
        salt_hex2, hash_hex2 = auth.hash_password(password)
        self.assertNotEqual(salt_hex, salt_hex2)
        self.assertNotEqual(hash_hex, hash_hex2)
    
    def test_verify_password(self):
        """Test password verification"""
        password = "TestPassword456"
        salt_hex, hash_hex = auth.hash_password(password)
        
        # Correct password should verify
        self.assertTrue(auth.verify_password(password, salt_hex, hash_hex))
        
        # Wrong password should not verify
        self.assertFalse(auth.verify_password("WrongPassword", salt_hex, hash_hex))
        
        # Empty/None values should return False
        self.assertFalse(auth.verify_password(password, None, hash_hex))
        self.assertFalse(auth.verify_password(password, salt_hex, None))
        self.assertFalse(auth.verify_password(password, '', hash_hex))
    
    def test_create_new_user(self):
        """Test user creation"""
        with patch('auth_module.get_db_connection') as mock_conn:
            mock_cursor = MagicMock()
            mock_connection = MagicMock()
            mock_connection.execute.return_value = mock_cursor
            mock_cursor.fetchone.return_value = [1]
            mock_conn.return_value = mock_connection
            
            user = auth.create_new_user("testuser", "password123")
            
            self.assertEqual(user.username, "testuser")
            self.assertEqual(user.password, "*")
            self.assertEqual(user.user_id, 1)
            self.assertIsNone(user.token)
    
    def test_login_backoff(self):
        """Test login backoff calculation"""
        with patch('auth_module.get_db_connection') as mock_conn:
            mock_cursor = MagicMock()
            mock_connection = MagicMock()
            mock_connection.execute.return_value = mock_cursor
            mock_conn.return_value = mock_connection
            
            # No failed attempts
            mock_cursor.fetchone.return_value = None
            backoff = auth.login_backoff_seconds("user1")
            self.assertEqual(backoff, 0)
            
            # 3 failed attempts (no backoff yet)
            mock_cursor.fetchone.return_value = (3, datetime.datetime.now().isoformat())
            backoff = auth.login_backoff_seconds("user1")
            self.assertEqual(backoff, 0)
            
            # 4 failed attempts (should have backoff)
            recent_time = datetime.datetime.now(datetime.timezone.utc)
            mock_cursor.fetchone.return_value = (4, recent_time.isoformat())
            backoff = auth.login_backoff_seconds("user1")
            self.assertGreater(backoff, 0)
    
    def test_session_signature(self):
        """Test session signing"""
        test_text = "session_token_123"
        signature = auth.sign(test_text)
        
        self.assertIsInstance(signature, str)
        self.assertEqual(len(signature), 64)  # SHA256 hex digest length
        
        # Same input should produce same signature
        signature2 = auth.sign(test_text)
        self.assertEqual(signature, signature2)
        
        # Different input should produce different signature
        signature3 = auth.sign("different_token")
        self.assertNotEqual(signature, signature3)


class TestParticleModule(unittest.TestCase):
    """Test cases for particle module functions"""
    
    def setUp(self):
        """Set up test database"""
        self.test_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.test_db_path = self.test_db.name
        self.test_db.close()
        
        particles.init_particles_db(self.test_db_path)
        self.user_id = "test_user_123"
    
    def tearDown(self):
        """Clean up test database"""
        try:
            os.unlink(self.test_db_path)
        except:
            pass
    
    def test_extract_tags_and_references(self):
        """Test tag and reference extraction"""
        # Test tags
        body = "This is a test #tag1 and #tag2 with some #tag1 duplicates"
        tags, refs = particles.extract_tags_and_references(body)
        self.assertEqual(tags, ['tag1', 'tag2'])
        
        # Test UUID references
        uuid1 = "123e4567-e89b-12d3-a456-426614174000"
        body = f"Reference to {uuid1}"
        tags, refs = particles.extract_tags_and_references(body)
        self.assertEqual(refs, [uuid1])
        
        # Test numeric references
        body = "Reference to #123 and #456"
        tags, refs = particles.extract_tags_and_references(body)
        self.assertEqual(refs, ['123', '456'])
        
        # Mixed content
        body = f"#python #coding with ref {uuid1} and #123"
        tags, refs = particles.extract_tags_and_references(body)
        self.assertEqual(tags, ['coding', 'python'])
        self.assertEqual(refs, [uuid1])
    
    def test_create_particle(self):
        """Test particle creation"""
        title = "Test Particle"
        body = "This is a test #tag1 #tag2"
        
        particle = particles.create_particle(
            self.user_id, title, body, self.test_db_path
        )
        
        self.assertIsInstance(particle, particles.Particle)
        self.assertEqual(particle.title, title)
        self.assertEqual(particle.body, body)
        self.assertEqual(particle.tags, ['tag1', 'tag2'])
        self.assertEqual(particle.user_id, self.user_id)
        self.assertIsInstance(particle.id, str)
        
        # Verify it's in database
        retrieved = particles.get_particle(
            particle.id, self.user_id, self.test_db_path
        )
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.title, title)
    
    def test_update_particle(self):
        """Test particle update"""
        # Create initial particle
        particle = particles.create_particle(
            self.user_id, "Original", "Original body", self.test_db_path
        )
        
        # Update it
        updated = particles.update_particle(
            particle.id, self.user_id, 
            title="Updated Title",
            body="Updated body with #newtag",
            db_path=self.test_db_path
        )
        
        self.assertIsNotNone(updated)
        self.assertEqual(updated.title, "Updated Title")
        self.assertEqual(updated.body, "Updated body with #newtag")
        self.assertEqual(updated.tags, ['newtag'])
        
        # Update non-existent particle
        result = particles.update_particle(
            "non-existent-id", self.user_id,
            title="Test", db_path=self.test_db_path
        )
        self.assertIsNone(result)
    
    def test_delete_particle(self):
        """Test particle deletion"""
        # Create particle
        particle = particles.create_particle(
            self.user_id, "To Delete", "Body", self.test_db_path
        )
        
        # Delete it
        success = particles.delete_particle(
            particle.id, self.user_id, self.test_db_path
        )
        self.assertTrue(success)
        
        # Verify it's gone
        retrieved = particles.get_particle(
            particle.id, self.user_id, self.test_db_path
        )
        self.assertIsNone(retrieved)
        
        # Delete non-existent particle
        success = particles.delete_particle(
            "non-existent", self.user_id, self.test_db_path
        )
        self.assertFalse(success)
    
    def test_search_particles(self):
        """Test particle search functionality"""
        # Create test particles
        p1 = particles.create_particle(
            self.user_id, "Python Tutorial", 
            "Learn Python #programming", self.test_db_path
        )
        p2 = particles.create_particle(
            self.user_id, "JavaScript Guide",
            "JavaScript #programming #web", self.test_db_path
        )
        p3 = particles.create_particle(
            self.user_id, "Cooking Recipe",
            "How to cook #food", self.test_db_path
        )
        
        # Search for "Python"
        results = particles.search_particles(
            self.user_id, "Python", db_path=self.test_db_path
        )
        self.assertEqual(results['total'], 1)
        self.assertEqual(len(results['particles']), 1)
        
        # Search for tag
        results = particles.search_particles(
            self.user_id, "programming", db_path=self.test_db_path
        )
        self.assertGreaterEqual(results['total'], 2)
        
        # Empty search returns all
        results = particles.search_particles(
            self.user_id, "", db_path=self.test_db_path
        )
        self.assertEqual(results['total'], 3)
    
    def test_fuzzy_search(self):
        """Test fuzzy search with edit distance"""
        # Create particles
        p1 = particles.create_particle(
            self.user_id, "Python Programming",
            "Learn Python basics", self.test_db_path
        )
        
        # Test exact match
        results = particles.fuzzy_search_particles(
            self.user_id, "Python", db_path=self.test_db_path
        )
        self.assertGreater(results['total'], 0)
        
        # Test fuzzy match (typo)
        results = particles.fuzzy_search_particles(
            self.user_id, "Pyton", db_path=self.test_db_path
        )
        self.assertGreater(results['total'], 0)
        
        # Test very different query
        results = particles.fuzzy_search_particles(
            self.user_id, "xyz123", db_path=self.test_db_path
        )
        self.assertEqual(results['total'], 0)
    
    def test_levenshtein_distance(self):
        """Test Levenshtein distance calculation"""
        # Exact match
        self.assertEqual(particles.levenshtein("test", "test"), 0)
        
        # One character difference
        self.assertEqual(particles.levenshtein("test", "text"), 1)
        self.assertEqual(particles.levenshtein("test", "tests"), 1)
        
        # Empty strings
        self.assertEqual(particles.levenshtein("", "test"), 4)
        self.assertEqual(particles.levenshtein("test", ""), 4)
        self.assertEqual(particles.levenshtein("", ""), 0)
        
        # Complex example
        self.assertEqual(particles.levenshtein("kitten", "sitting"), 3)
    
    def test_get_all_tags(self):
        """Test retrieving all tags"""
        # Create particles with tags
        particles.create_particle(
            self.user_id, "P1", "Content #tag1 #tag2", self.test_db_path
        )
        particles.create_particle(
            self.user_id, "P2", "Content #tag2 #tag3", self.test_db_path
        )
        
        tags = particles.get_all_tags(self.user_id, self.test_db_path)
        self.assertEqual(set(tags), {'tag1', 'tag2', 'tag3'})
        self.assertEqual(tags, sorted(tags))  # Should be sorted
    
    def test_particle_references(self):
        """Test particle reference tracking"""
        # Create particles
        p1 = particles.create_particle(
            self.user_id, "Particle 1", "Content", self.test_db_path
        )
        p2 = particles.create_particle(
            self.user_id, "Particle 2",
            f"Reference to {p1.id}", self.test_db_path
        )
        
        # Get references
        refs = particles.get_particle_references(
            p1.id, self.user_id, self.test_db_path
        )
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0].id, p2.id)


class TestStorageModule(unittest.TestCase):
    """Test cases for storage module functions"""
    
    def setUp(self):
        """Set up test database"""
        self.test_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.test_db_path = self.test_db.name
        self.test_db.close()
        
        storage.init_database(self.test_db_path)
    
    def tearDown(self):
        """Clean up test database"""
        try:
            os.unlink(self.test_db_path)
        except:
            pass
    
    def test_init_database(self):
        """Test database initialization"""
        # Should create required tables
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        
        # Check Users table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Users'")
        self.assertIsNotNone(cursor.fetchone())
        
        # Check Sessions table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Sessions'")
        self.assertIsNotNone(cursor.fetchone())
        
        # Check FailedLogins table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='FailedLogins'")
        self.assertIsNotNone(cursor.fetchone())
        
        conn.close()
    
    def test_convert_to_csstring(self):
        """Test list to comma-separated string conversion"""
        self.assertEqual(storage.convert_to_csstring(['a', 'b', 'c']), 'a,b,c')
        self.assertEqual(storage.convert_to_csstring([]), '')
        self.assertEqual(storage.convert_to_csstring(['single']), 'single')
    
    def test_cstring_to_list(self):
        """Test comma-separated string to list conversion"""
        self.assertEqual(storage.cstring_to_list('a,b,c'), ['a', 'b', 'c'])
        self.assertEqual(storage.cstring_to_list(''), [])
        self.assertEqual(storage.cstring_to_list('single'), ['single'])
    
    def test_store_user(self):
        """Test storing user in database"""
        user = storage.User(
            user_id=None,
            username="testuser",
            password="hashedpass",
            token="token123"
        )
        
        storage.store_user(user, self.test_db_path)
        
        # Verify user was stored
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users WHERE username=?", ("testuser",))
        row = cursor.fetchone()
        
        self.assertIsNotNone(row)
        self.assertEqual(row[1], "testuser")  # username
        self.assertEqual(row[2], "hashedpass")  # password
        self.assertEqual(row[3], "token123")  # token
        
        conn.close()


class TestMainAPI(unittest.TestCase):
    """Test cases for FastAPI endpoints"""
    
    def setUp(self):
        """Set up test client and database"""
        self.client = TestClient(app)
        
        # Create test database
        self.test_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.test_db_path = self.test_db.name
        self.test_db.close()
        
        # Patch database paths in modules
        self.db_patches = [
            patch('main.DATABASE_FILE', self.test_db_path),
            patch('auth_module.DB_FILE', self.test_db_path),
            patch('storage_module.DB_FILE', self.test_db_path),
            patch('particle_module.DB_FILE', self.test_db_path),
        ]
        
        for p in self.db_patches:
            p.start()
        
        # Initialize database
        storage.init_database(self.test_db_path)
        particles.init_particles_db(self.test_db_path)
        
        # Create test user
        self.test_username = "testuser"
        self.test_password = "testpass123"
        self.create_test_user()
    
    def tearDown(self):
        """Clean up"""
        for p in self.db_patches:
            p.stop()
        
        try:
            os.unlink(self.test_db_path)
        except:
            pass
    
    def create_test_user(self):
        """Helper to create a test user"""
        response = self.client.post("/auth/signup", json={
            "username": self.test_username,
            "password": self.test_password
        })
        self.assertEqual(response.status_code, 200)
    
    def login_test_user(self):
        """Helper to login and get session cookie"""
        response = self.client.post("/auth/login", json={
            "username": self.test_username,
            "password": self.test_password
        })
        self.assertEqual(response.status_code, 200)
        return response.cookies
    
    def test_root_endpoint(self):
        """Test root endpoint returns login page"""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers['content-type'])
    
    def test_signup_endpoint(self):
        """Test user signup"""
        response = self.client.post("/auth/signup", json={
            "username": "newuser",
            "password": "newpass123"
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('user_id', data)
        
        # Duplicate username should fail
        response = self.client.post("/auth/signup", json={
            "username": "newuser",
            "password": "anotherpass"
        })
        self.assertEqual(response.status_code, 400)
    
    def test_login_endpoint(self):
        """Test user login"""
        # Valid credentials
        response = self.client.post("/auth/login", json={
            "username": self.test_username,
            "password": self.test_password
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('session', response.cookies)
        
        # Invalid credentials
        response = self.client.post("/auth/login", json={
            "username": self.test_username,
            "password": "wrongpassword"
        })
        self.assertEqual(response.status_code, 401)
    
    def test_logout_endpoint(self):
        """Test user logout"""
        cookies = self.login_test_user()
        
        response = self.client.post("/auth/logout", cookies=cookies)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'success')
    
    def test_create_particle_endpoint(self):
        """Test particle creation via API"""
        cookies = self.login_test_user()
        
        response = self.client.post("/particles", 
            json={
                "title": "Test Particle",
                "body": "Test content #api"
            },
            cookies=cookies
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['title'], "Test Particle")
        self.assertEqual(data['tags'], ['api'])
        
        # Without auth should fail
        response = self.client.post("/particles", 
        json={
            "title": "Test",
            "body": "Body"
            }
    # No cookies parameter = no authentication
)
self.assertEqual(response.status_code, 401)
    
    def test_list_particles_endpoint(self):
        """Test particle listing"""
        cookies = self.login_test_user()
        
        # Create some particles
        for i in range(3):
            self.client.post("/particles",
                json={
                    "title": f"Particle {i}",
                    "body": f"Body {i}"
                },
                cookies=cookies
            )
        
        # List particles
        response = self.client.get("/particles", cookies=cookies)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['total'], 3)
        self.assertEqual(len(data['particles']), 3)
    
    def test_search_particles_endpoint(self):
        """Test particle search via API"""
        cookies = self.login_test_user()
        
        # Create particles
        self.client.post("/particles",
            json={
                "title": "Python Guide",
                "body": "Learn Python programming"
            },
            cookies=cookies
        )
        self.client.post("/particles",
            json={
                "title": "Java Tutorial",
                "body": "Learn Java programming"
            },
            cookies=cookies
        )
        
        # Search
        response = self.client.get("/particles?query=Python", cookies=cookies)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(data['total'], 0)
    
    def test_update_particle_endpoint(self):
        """Test particle update via API"""
        cookies = self.login_test_user()
        
        # Create particle
        response = self.client.post("/particles",
            json={
                "title": "Original",
                "body": "Original body"
            },
            cookies=cookies
        )
        particle_id = response.json()['id']
        
        # Update it
        response = self.client.put(f"/particles/{particle_id}",
            json={
                "title": "Updated",
                "body": "Updated body"
            },
            cookies=cookies
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['title'], "Updated")
        self.assertEqual(data['body'], "Updated body")
    
    def test_delete_particle_endpoint(self):
        """Test particle deletion via API"""
        cookies = self.login_test_user()
        
        # Create particle
        response = self.client.post("/particles",
            json={
                "title": "To Delete",
                "body": "Will be deleted"
            },
            cookies=cookies
        )
        particle_id = response.json()['id']
        
        # Delete it
        response = self.client.delete(f"/particles/{particle_id}", cookies=cookies)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'deleted')
        
        # Verify it's gone
        response = self.client.get(f"/particles/{particle_id}", cookies=cookies)
        self.assertEqual(response.status_code, 404)
    
    def test_authorization_required(self):
        """Test that endpoints require authorization"""
        endpoints = [
            ("/particles", "GET"),
            ("/particles", "POST"),
            ("/particles/123", "GET"),
            ("/particles/123", "PUT"),
            ("/particles/123", "DELETE"),
            ("/particles/tags/all", "GET"),
        ]
        
        for endpoint, method in endpoints:
            if method == "GET":
                response = self.client.get(endpoint)
            elif method == "POST":
                response = self.client.post(endpoint, json={})
            elif method == "PUT":
                response = self.client.put(endpoint, json={})
            elif method == "DELETE":
                response = self.client.delete(endpoint)
            
            self.assertEqual(response.status_code, 401,
                           f"Endpoint {method} {endpoint} should require auth")


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows"""
    
    def setUp(self):
        """Set up test environment"""
        self.client = TestClient(app)
        self.test_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.test_db_path = self.test_db.name
        self.test_db.close()
        
        # Patch all database paths
        self.db_patches = [
            patch('main.DATABASE_FILE', self.test_db_path),
            patch('auth_module.DB_FILE', self.test_db_path),
            patch('storage_module.DB_FILE', self.test_db_path),
            patch('particle_module.DB_FILE', self.test_db_path),
        ]
        
        for p in self.db_patches:
            p.start()
        
        storage.init_database(self.test_db_path)
        particles.init_particles_db(self.test_db_path)
    
    def tearDown(self):
        """Clean up"""
        for p in self.db_patches:
            p.stop()
        
        try:
            os.unlink(self.test_db_path)
        except:
            pass
    
    def test_complete_user_workflow(self):
        """Test complete user workflow from signup to particle management"""
        # 1. Sign up
        response = self.client.post("/auth/signup", json={
            "username": "integrationuser",
            "password": "integrationpass123"
        })
        self.assertEqual(response.status_code, 200)
        
        # 2. Login
        response = self.client.post("/auth/login", json={
            "username": "integrationuser",
            "password": "integrationpass123"
        })
        self.assertEqual(response.status_code, 200)
        cookies = response.cookies
        
        # 3. Create particles
        particle_ids = []
        for i in range(3):
            response = self.client.post("/particles",
                json={
                    "title": f"Integration Test {i}",
                    "body": f"Content {i} #test #integration"
                },
                cookies=cookies
            )
            self.assertEqual(response.status_code, 200)
            particle_ids.append(response.json()['id'])
        
        # 4. Search particles
        response = self.client.get("/particles?query=integration", cookies=cookies)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['total'], 3)
        
        # 5. Get tags
        response = self.client.get("/particles/tags/all", cookies=cookies)
        self.assertEqual(response.status_code, 200)
        tags = response.json()['tags']
        self.assertIn('test', tags)
        self.assertIn('integration', tags)
        
        # 6. Update a particle
        response = self.client.put(f"/particles/{particle_ids[0]}",
            json={"title": "Updated Integration Test"},
            cookies=cookies
        )
        self.assertEqual(response.status_code, 200)
        
        # 7. Delete a particle
        response = self.client.delete(f"/particles/{particle_ids[1]}", cookies=cookies)
        self.assertEqual(response.status_code, 200)
        
        # 8. Verify deletion
        response = self.client.get("/particles", cookies=cookies)
        self.assertEqual(response.json()['total'], 2)
        
        # 9. Logout
        response = self.client.post("/auth/logout", cookies=cookies)
        self.assertEqual(response.status_code, 200)
        
        # 10. Verify can't access after logout
        response = self.client.get("/particles", cookies=cookies)
        self.assertEqual(response.status_code, 401)


def run_all_tests():
    """Run all test suites"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestAuthModule))
    suite.addTests(loader.loadTestsFromTestCase(TestParticleModule))
    suite.addTests(loader.loadTestsFromTestCase(TestStorageModule))
    suite.addTests(loader.loadTestsFromTestCase(TestMainAPI))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)


if __name__ == "__main__":
    run_all_tests()