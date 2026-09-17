#!/bin/env python
# -*- coding: utf8 -*-

import hashlib
import logging
import random
import re
import tempfile

try:
    import socketserver
except ImportError:
    import SocketServer
    socketserver = SocketServer

import sys
sys.path.append('.')

from pyicap import *

# Configure logging to file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('icap_server.log'),
    ]
)
logger = logging.getLogger(__name__)


class ThreadingSimpleServer(socketserver.ThreadingMixIn, ICAPServer):
    pass


class ICAPHandler(BaseICAPRequestHandler):

    def example_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'RESPMOD')
        self.set_icap_header(b'Service', b'PyICAP Logger Server 1.0')
        self.set_icap_header(b'Preview', b'0')
        self.set_icap_header(b'Transfer-Preview', b'*')
        self.set_icap_header(b'Transfer-Ignore', b'jpg,jpeg,gif,png,swf,flv')
        self.set_icap_header(b'Transfer-Complete', b'')
        self.set_icap_header(b'Max-Connections', b'100')
        self.set_icap_header(b'Options-TTL', b'3600')
        self.send_headers(False)

    def read_into(self, f):
        while True:
            chunk = self.read_chunk()
            if chunk == b'':
                return
            f.write(chunk)

    def extract_filename_and_url(self):
        """Extract URL and filename from request headers."""
        url = ""
        filename = ""
        
        # Get URL from Host and Request-Line
        host = ""
        for h, values in self.enc_req_headers.items():
            if h.lower() == b'host':
                host = values[0].decode('utf-8', errors='replace')
                break
        
        if self.enc_req:
            # enc_req is like [b'GET', b'/path/file.txt', b'HTTP/1.1']
            if len(self.enc_req) >= 2:
                path = self.enc_req[1].decode('utf-8', errors='replace')
                if host:
                    url = f"http://{host}{path}"
                else:
                    url = path
                
                # Extract filename from path
                match = re.search(r'([^/]+)$', path)
                if match:
                    filename = match.group(1)
        
        return url, filename

    def compute_sha1(self, content):
        """Compute SHA1 hash of content."""
        sha1_hash = hashlib.sha1()
        sha1_hash.update(content)
        return sha1_hash.hexdigest()

    def example_RESPMOD(self):
        # Set response to 204 No Modifications
        self.set_icap_response(204)
        
        # Copy encapsulated response headers
        if self.enc_res_status is not None:
            self.set_enc_status(b' '.join(self.enc_res_status))
        for h in self.enc_res_headers:
            for v in self.enc_res_headers[h]:
                self.set_enc_header(h, v)

        if not self.has_body:
            self.send_headers(False)
            return
        
        # Read everything from the response to a temporary file
        with tempfile.NamedTemporaryFile(prefix='pyicap.', suffix='.tmp') as upstream:
            self.read_into(upstream)
            if self.preview and not self.ieof:
                self.cont()
                self.read_into(upstream)
            upstream.seek(0)
            
            # Read content for hashing
            content = upstream.read()
            
            # Extract URL and filename
            url, filename = self.extract_filename_and_url()
            
            # Compute SHA1 hash
            sha1_hash = self.compute_sha1(content)
            
            # Log the information
            logger.info(f"URL: {url}, Filename: {filename}, SHA1: {sha1_hash}")
            
            # Write content back to downstream (no modifications)
            self.write_chunk(content)


port = 13440

if __name__ == '__main__':
    server = ThreadingSimpleServer((b'', port), ICAPHandler)
    try:
        while 1:
            server.handle_request()
    except KeyboardInterrupt:
        print("Finished")
