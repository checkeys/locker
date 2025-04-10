# coding:utf-8

import unittest
from unittest import mock

from xpw_locker import server


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

    @mock.patch.object(server, "ThreadingHTTPServer", mock.MagicMock())
    def test_run(self):
        listen_address = ("0.0.0.0", 8080)
        request_proxy = server.AuthRequestProxy("https://example.com/")
        self.assertIsNone(server.run(listen_address, request_proxy))


if __name__ == "__main__":
    unittest.main()
