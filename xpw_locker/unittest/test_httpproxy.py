# coding:utf-8

from errno import ECANCELED
import unittest
from unittest import mock

from xpw.authorize import Argon2Auth

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


class TestCommand(unittest.TestCase):

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

    @mock.patch.object(httpproxy, "run")
    @mock.patch.object(httpproxy.AuthInit, "from_file")
    def test_main(self, mock_auth, _):
        mock_auth.side_effect = [Argon2Auth({"users": {"test", "unit"}})]
        self.assertEqual(httpproxy.main([]), ECANCELED)


if __name__ == "__main__":
    unittest.main()
