# coding:utf-8

from errno import ECANCELED
import unittest
from unittest import mock

from xpw.authorize import Argon2Auth

from xpw_locker import httpproxy


class TestCommand(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.listen_address = ("0.0.0.0", 8080)
        cls.target_url = "https://example.com/"

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mock.patch.object(httpproxy, "ThreadingHTTPServer", mock.MagicMock())
    def test_run(self):
        self.assertIsNone(httpproxy.run(self.listen_address, self.target_url))

    @mock.patch.object(httpproxy, "run")
    @mock.patch.object(httpproxy.AuthInit, "from_file")
    def test_main(self, mock_auth, _):
        mock_auth.side_effect = [Argon2Auth({"users": {"test", "unit"}})]
        self.assertEqual(httpproxy.main([]), ECANCELED)


if __name__ == "__main__":
    unittest.main()
