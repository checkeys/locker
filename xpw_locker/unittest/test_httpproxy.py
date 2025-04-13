# coding:utf-8

import unittest
from unittest import mock

from xpw_locker import httpproxy


class TestServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mock.patch.object(httpproxy, "ThreadingHTTPServer", mock.MagicMock())
    def test_run(self):
        listen_address = ("0.0.0.0", 8080)
        target_url = "https://example.com/"
        self.assertIsNone(httpproxy.run(listen_address, target_url))


if __name__ == "__main__":
    unittest.main()
