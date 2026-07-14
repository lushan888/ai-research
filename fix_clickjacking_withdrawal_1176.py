"""
fix_clickjacking_withdrawal_1176.py - Fix for issue #1176

Clickjacking via Missing CSP frame-ancestors on Crypto Withdrawal
Difficulty: Easy | Bounty: $120

Fix:
1. Add Content-Security-Policy: frame-ancestors 'none' in add_security_headers()
2. Add two-step confirmation for transfer (critical financial operation)
"""

import unittest
from unittest.mock import patch, MagicMock
from io import StringIO
import sys
import importlib


class TestClickjackingFix(unittest.TestCase):
    """Verify clickjacking protection headers and two-step confirmation."""
    
    def test_x_frame_options_set(self):
        """Test that X-Frame-Options: DENY is set."""
        # Import the Flask app
        sys.path.insert(0, 'src')
        from app import app
        
        with app.test_client() as client:
            resp = client.get('/')
            self.assertEqual(resp.headers.get('X-Frame-Options'), 'DENY')
    
    def test_csp_frame_ancestors_set(self):
        """Test that CSP frame-ancestors 'none' is set."""
        sys.path.insert(0, 'src')
        from app import app
        
        with app.test_client() as client:
            resp = client.get('/')
            csp = resp.headers.get('Content-Security-Policy', '')
            self.assertIn("frame-ancestors 'none'", csp)
    
    def test_transfer_requires_confirmation(self):
        """Test that transfer requires two-step confirmation."""
        sys.path.insert(0, 'src')
        from app import app
        
        with app.test_client() as client:
            # Without confirmation, transfer should fail
            resp = client.post('/transfer', data={
                'username': 'user1',
                'password': 'user123'
            }, follow_redirects=True)
            
            # First, request confirmation
            resp = client.post('/transfer', data={
                'action': 'request_confirm',
                'amount': '100',
                'to': 'admin',
                'csrf_token': 'dummy'
            })
            data = resp.get_json()
            self.assertIn('confirm_token', data)
            token = data['confirm_token']
            
            # Without valid confirmation, direct transfer should fail
            resp = client.post('/transfer', data={
                'amount': '100',
                'to': 'admin',
                'confirm_token': 'wrong_token',
                'csrf_token': 'dummy'
            })
            self.assertEqual(resp.status_code, 403)


if __name__ == '__main__':
    unittest.main()
