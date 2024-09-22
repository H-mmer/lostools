# tests/test_lfi_scanner.py

import unittest
from unittest.mock import patch, AsyncMock
import asyncio
from scanners.lfi_scanner import run_lfi_scanner

class TestLFIScanner(unittest.TestCase):
    @patch('scanners.lfi_scanner.asyncio')
    def test_run_lfi_scanner(self, mock_asyncio):
        # Mock the asyncio event loop
        mock_loop = mock_asyncio.get_event_loop.return_value
        mock_loop.run_until_complete = AsyncMock()
        
        # Mock inputs
        urls = ['http://example.com/page?file=']
        payloads = ['../../etc/passwd']
        threads = 5
        output_file = None
        
        # Run the scanner
        run_lfi_scanner(urls=urls, payloads=payloads, threads=threads, output_file=output_file)
        
        # Assert that the event loop was called
        mock_loop.run_until_complete.assert_called_once()
        
    @patch('scanners.lfi_scanner.aiohttp.ClientSession.get')
    def test_perform_request(self, mock_get):
        from scanners.lfi_scanner import perform_request
        # Configure the mock to return a response containing the success criteria
        async def mock_response(*args, **kwargs):
            class MockResponse:
                async def text(self):
                    return "root:x:0:0:root:/root:/bin/bash"
            return MockResponse()
        mock_get.side_effect = mock_response
        
        # Run the perform_request function
        session = AsyncMock()
        session.get = mock_get
        url = 'http://example.com/page?file='
        payload = '../../etc/passwd'
        
        # Since perform_request is an async function, we need to run it in an event loop
        async def test_coroutine():
            is_vulnerable, target_url, response_time = await perform_request(session, url, payload)
            self.assertTrue(is_vulnerable)
            self.assertEqual(target_url, url + payload)
        
        asyncio.run(test_coroutine())

if __name__ == '__main__':
    unittest.main()
