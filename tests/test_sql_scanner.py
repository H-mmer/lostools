# tests/test_sql_scanner.py

import unittest
from unittest.mock import patch, AsyncMock
import asyncio
from scanners.sql_scanner import run_sql_scanner

class TestSQLScanner(unittest.TestCase):
    @patch('scanners.sql_scanner.asyncio')
    def test_run_sql_scanner(self, mock_asyncio):
        # Mock the asyncio event loop
        mock_loop = mock_asyncio.get_event_loop.return_value
        mock_loop.run_until_complete = AsyncMock()
        
        # Mock inputs
        urls = ['http://example.com/page?id=']
        payloads = ["' OR '1'='1' -- "]
        cookie = None
        threads = 5
        output_file = None
        
        # Run the scanner
        run_sql_scanner(urls=urls, payloads=payloads, cookie=cookie, threads=threads, output_file=output_file)
        
        # Assert that the event loop was called
        mock_loop.run_until_complete.assert_called_once()
        
    @patch('scanners.sql_scanner.aiohttp.ClientSession.get')
    def test_perform_request(self, mock_get):
        from scanners.sql_scanner import perform_request
        # Configure the mock to return a response with a delay
        async def mock_response(*args, **kwargs):
            class MockResponse:
                async def text(self):
                    return "Test response"
            return MockResponse()
        mock_get.side_effect = mock_response
        
        # Run the perform_request function
        session = AsyncMock()
        session.get = mock_get
        url = 'http://example.com/page?id='
        payload = "' OR '1'='1' -- "
        cookie = None
        
        # Since perform_request is an async function, we need to run it in an event loop
        async def test_coroutine():
            success, url_with_payload, response_time, error_message = await perform_request(session, url, payload, cookie)
            self.assertIsInstance(success, bool)
            self.assertIsInstance(url_with_payload, str)
            self.assertIsInstance(response_time, float)
            self.assertIsNone(error_message)
        
        asyncio.run(test_coroutine())

if __name__ == '__main__':
    unittest.main()
