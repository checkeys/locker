# coding:utf-8

from errno import ECANCELED
import unittest
from unittest import mock

from xpw.authorize import Argon2Auth
from xpw_locker import command


class TestCmd(unittest.TestCase):

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

    @mock.patch.object(command.server.APP, "run")
    @mock.patch.object(command.AuthInit, "from_file")
    def test_main(self, mock_auth, _):
        mock_auth.side_effect = [Argon2Auth({"users": {"test", "unit"}})]
        self.assertEqual(command.main([]), ECANCELED)


if __name__ == "__main__":
    unittest.main()
