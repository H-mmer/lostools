# tests/test_or_scanner.py

import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
from scanners.or_scanner import run_or_scanner

class TestORScanner(unittest.TestCase):
    @patch('scanners.or_scanner.asyncio')
    def test_run_or_scanner(self, mock_asyncio):
        # Mock the asyncio event loop
        mock_loop = mock_asyncio.get_event_loop.return_value
        mock_loop.run_until_complete = MagicMock()
        
        # Mock inputs
        urls = ['http://example.com/redirect?url=']
        payloads = ['https://malicious.com']
        threads = 5
        output_file = None
        
        # Run the scanner
        run_or_scanner(urls=urls, payloads=payloads, threads=threads, output_file=output_file)
        
        # Assert that the event loop was called
        mock_loop.run_until_complete.assert_called_once()
        
    @patch('scanners.or_scanner.webdriver.Chrome')
    def test_scan_url(self, mock_chrome):
        from scanners.or_scanner import scan_url
        # Configure the mock WebDriver
        mock_driver = MagicMock()
        mock_driver.current_url = 'https://www.google.com/'
        mock_chrome.return_value = mock_driver
        
        # Mock semaphore
        sem = AsyncMock()
        
        # Run scan_url
        async def test_coroutine():
            is_vulnerable, target_url = await scan_url(sem, mock_driver, 'http://example.com/redirect?url=', 'https://malicious.com')
            self.assertTrue(is_vulnerable)
            self.assertEqual(target_url, 'http://example.com/redirect?url=https://malicious.com')
        
        asyncio.run(test_coroutine())

if __name__ == '__main__':
    unittest.main()
