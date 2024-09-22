# tests/test_xss_scanner.py

import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
from scanners.xss_scanner import run_xss_scanner

class TestXSSScanner(unittest.TestCase):
    @patch('scanners.xss_scanner.asyncio')
    def test_run_xss_scanner(self, mock_asyncio):
        # Mock the asyncio event loop
        mock_loop = mock_asyncio.get_event_loop.return_value
        mock_loop.run_until_complete = MagicMock()
        
        # Mock inputs
        urls = ['http://example.com/search?q=']
        payloads = ["<script>alert(1)</script>"]
        threads = 5
        output_file = None
        
        # Run the scanner
        run_xss_scanner(urls=urls, payloads=payloads, threads=threads, output_file=output_file)
        
        # Assert that the event loop was called
        mock_loop.run_until_complete.assert_called_once()
        
    @patch('scanners.xss_scanner.webdriver.Chrome')
    def test_scan_url(self, mock_chrome):
        from scanners.xss_scanner import MassScanner
        # Configure the mock WebDriver
        mock_driver = MagicMock()
        mock_chrome.return_value = mock_driver
        mock_driver.switch_to.alert.text = '1'
        mock_driver.switch_to.alert.accept = MagicMock()
        
        # Instantiate MassScanner
        scanner = MassScanner(
            urls=['http://example.com/search?q='],
            payloads=["<script>alert(1)</script>"],
            output=None,
            concurrency=1,
            timeout=3
        )
        
        # Mock semaphore
        sem = AsyncMock()
        
        # Run scan_url
        async def test_coroutine():
            await scanner.scan_url(sem, mock_driver, 'http://example.com/search?q=<script>alert(1)</script>')
            # Assert that the URL was added to injectables
            self.assertIn('http://example.com/search?q=<script>alert(1)</script>', scanner.injectables)
        
        asyncio.run(test_coroutine())

if __name__ == '__main__':
    unittest.main()
