#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Autotests for respmod_logger.py ICAP server.
Tests that the server logs URL, filename, and SHA1 hash of files.
"""

import hashlib
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

# Add parent directory to path to import pyicap
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from examples.respmod_logger import ICAPHandler, ThreadingSimpleServer


class MockRfile:
    """Mock file-like object for reading."""
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def readline(self, size=-1):
        if self.pos >= len(self.data):
            return b''
        end = self.data.find(b'\r\n', self.pos)
        if end == -1:
            end = len(self.data)
        else:
            end += 2  # Include \r\n
        result = self.data[self.pos:end]
        self.pos = end
        return result

    def read(self, size=-1):
        if size == -1:
            result = self.data[self.pos:]
            self.pos = len(self.data)
        else:
            result = self.data[self.pos:self.pos + size]
            self.pos += len(result)
        return result


class MockWfile:
    """Mock file-like object for writing."""
    def __init__(self):
        self.data = b''

    def write(self, data):
        self.data += data


class TestICAPLoggerHandler(unittest.TestCase):
    """Test cases for ICAP logger handler."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_content = b"Hello, World! This is a test file content."
        self.expected_sha1 = hashlib.sha1(self.test_content).hexdigest()

    def test_compute_sha1(self):
        """Test SHA1 computation."""
        handler = ICAPHandler.__new__(ICAPHandler)
        result = handler.compute_sha1(self.test_content)
        self.assertEqual(result, self.expected_sha1)

    def test_extract_filename_and_url(self):
        """Test URL and filename extraction."""
        handler = ICAPHandler.__new__(ICAPHandler)
        handler.enc_req = [b'GET', b'/path/to/testfile.txt', b'HTTP/1.1']
        handler.enc_req_headers = {b'host': [b'example.com']}
        
        url, filename = handler.extract_filename_and_url()
        
        self.assertEqual(url, "http://example.com/path/to/testfile.txt")
        self.assertEqual(filename, "testfile.txt")

    def test_extract_filename_and_url_no_host(self):
        """Test URL extraction without host header."""
        handler = ICAPHandler.__new__(ICAPHandler)
        handler.enc_req = [b'GET', b'/path/to/testfile.txt', b'HTTP/1.1']
        handler.enc_req_headers = {}
        
        url, filename = handler.extract_filename_and_url()
        
        self.assertEqual(url, "/path/to/testfile.txt")
        self.assertEqual(filename, "testfile.txt")

    def test_extract_filename_and_url_root_path(self):
        """Test filename extraction with root path."""
        handler = ICAPHandler.__new__(ICAPHandler)
        handler.enc_req = [b'GET', b'/index.html', b'HTTP/1.1']
        handler.enc_req_headers = {b'host': [b'example.com']}
        
        url, filename = handler.extract_filename_and_url()
        
        self.assertEqual(url, "http://example.com/index.html")
        self.assertEqual(filename, "index.html")


class TestICAPServerIntegration(unittest.TestCase):
    """Integration tests for the ICAP server."""

    @classmethod
    def setUpClass(cls):
        """Start the ICAP server in a thread."""
        cls.port = 13441  # Use different port for tests
        cls.server = ThreadingSimpleServer(('127.0.0.1', cls.port), ICAPHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.5)  # Give server time to start

    @classmethod
    def tearDownClass(cls):
        """Stop the ICAP server."""
        cls.server.shutdown()
        cls.server.server_close()
        # Clean up log file
        log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icap_server.log')
        if os.path.exists(log_file):
            os.remove(log_file)

    def send_icap_request(self, method, service, body_content, url_path=b'/test/file.txt'):
        """Send an ICAP request and return response."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(('127.0.0.1', self.port))
            
            # Calculate proper offsets for encapsulated sections
            req_hdr = b'GET ' + url_path + b' HTTP/1.1\r\nHost: example.com\r\n\r\n'
            res_hdr = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n'
            
            req_hdr_start = 0
            res_hdr_start = len(req_hdr)
            body_start = res_hdr_start + len(res_hdr)
            
            encapsulated = f'req-hdr={req_hdr_start}, res-hdr={res_hdr_start}, res-body={body_start}'.encode()
            
            # Build chunked body
            hex_len = format(len(body_content), 'x').encode()
            chunked_body = hex_len + b'\r\n' + body_content + b'\r\n0\r\n\r\n'
            
            # Build ICAP request
            request = (
                method + b' icap://127.0.0.1:' + str(self.port).encode() + b'/' + service + b' ICAP/1.0\r\n' +
                b'Host: 127.0.0.1\r\n' +
                b'User-Agent: TestClient/1.0\r\n' +
                b'Encapsulated: ' + encapsulated + b'\r\n' +
                b'\r\n' +
                req_hdr +
                res_hdr +
                chunked_body
            )
            
            sock.sendall(request)
            
            # Read response
            response = b''
            sock.settimeout(2)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            
            return response
        finally:
            sock.close()

    def test_respmod_logs_file_info(self):
        """Test that RESPMOD request logs URL, filename, and SHA1."""
        test_content = b"Test file content for logging"
        expected_sha1 = hashlib.sha1(test_content).hexdigest()
        
        # Send RESPMOD request
        response = self.send_icap_request(
            b'RESPMOD', 
            b'example', 
            test_content
        )
        
        # Check response contains 204 status
        self.assertIn(b'204', response)
        
        # Check log file exists and contains expected info
        time.sleep(0.5)  # Give time for log to be written
        self.assertTrue(os.path.exists('icap_server.log'), "Log file should exist")
        
        with open('icap_server.log', 'r') as f:
            log_content = f.read()
        
        # Verify log contains URL, filename, and SHA1
        self.assertIn('URL:', log_content)
        self.assertIn('Filename:', log_content)
        self.assertIn('SHA1:', log_content)
        self.assertIn(expected_sha1, log_content)

    def test_respmod_different_files(self):
        """Test logging with different file contents."""
        test_cases = [
            (b"File content 1", b'/path/document.pdf'),
            (b"Another file with different content", b'/downloads/image.png'),
            (b"Third test file", b'/files/archive.zip'),
        ]
        
        for content, path in test_cases:
            expected_sha1 = hashlib.sha1(content).hexdigest()
            
            response = self.send_icap_request(
                b'RESPMOD',
                b'example',
                content,
                path
            )
            
            self.assertIn(b'204', response)
            
            # Verify SHA1 is logged
            time.sleep(0.3)
            with open('icap_server.log', 'r') as f:
                log_content = f.read()
            self.assertIn(expected_sha1, log_content)

    def test_options_response(self):
        """Test OPTIONS method returns correct capabilities."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(('127.0.0.1', self.port))
            
            request = (
                b"OPTIONS icap://127.0.0.1:" + str(self.port).encode() + b"/example ICAP/1.0\r\n" +
                b"Host: 127.0.0.1\r\n" +
                b"User-Agent: TestClient/1.0\r\n" +
                b"\r\n"
            )
            
            sock.sendall(request)
            
            response = sock.recv(4096)
            
            # Check response contains 200 OK and required headers
            self.assertIn(b'200', response)
            self.assertIn(b'Methods', response)
            self.assertIn(b'RESPMOD', response)
        finally:
            sock.close()


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
