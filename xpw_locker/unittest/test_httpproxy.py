# coding:utf-8

from errno import ECANCELED
import os
import unittest
from unittest import mock

from xpw import Argon2Auth
from xpw import BasicConfig

from xpw_locker import httpproxy


class TestAuthRequestProxy(unittest.TestCase):
    BASE: str = os.path.dirname(os.path.dirname(__file__))

    @classmethod
    def setUpClass(cls):
        cls.target_url = "https://example.com/"
        cls.resources = os.path.join(cls.BASE, "resources")

    @classmethod
    def tearDownClass(cls):
        pass

    @mock.patch.object(BasicConfig, "dumpf", mock.MagicMock())
    def setUp(self):
        self.config = BasicConfig("auth", {"users": {"demo": "test"}})
        self.auth = Argon2Auth(self.config)
        self.account = httpproxy.Account(self.auth)
        self.template = httpproxy.LocaleTemplate(self.resources)
        self.proxy = httpproxy.AuthRequestProxy.create(
            template=self.template,
            target_url=self.target_url,
            account=self.account
        )

    def tearDown(self):
        pass

    def test_authenticate_favicon(self):
        self.assertIsNone(self.proxy.authenticate("/favicon.ico", "GET", b"", {}))  # noqa:E501

    def test_authenticate_basic_authorization(self):
        self.proxy.account.members.create_api_token(token="test")
        self.assertIsNone(self.proxy.authenticate("/", "GET", b"", {"Authorization": "Basic ZGVtbzp0ZXN0"}))  # noqa:E501
        self.assertIsNone(self.proxy.authenticate("/", "GET", b"", {"Authorization": "Basic OnRlc3Q="}))  # noqa:E501

    def test_authenticate_bearer_authorization(self):
        self.account.members.create_api_token(token="test")
        self.assertIsNone(self.proxy.authenticate("/", "GET", b"", {"Authorization": "Bearer test"}))  # noqa:E501

    def test_authenticate_apikey_authorization(self):
        self.account.members.create_api_token(token="test")
        self.assertIsNone(self.proxy.authenticate("/", "GET", b"", {"Authorization": "ApiKey test"}))  # noqa:E501

    def test_authenticate_session_id(self):
        self.assertIsInstance(self.proxy.authenticate("/", "GET", b"", {}), httpproxy.ResponseProxy)  # noqa:E501

    def test_authenticate_verify(self):
        self.account.tickets.sign_in(session_id="test", identity="demo")
        self.assertIsNone(self.proxy.authenticate("/", "GET", b"", {"Cookie": "session_id=test"}))  # noqa:E501

    def test_authenticate_post_login_password_null(self):
        self.assertIsInstance(self.proxy.authenticate("/", "POST", b"username=demo&password=", {"Cookie": "session_id=test"}), httpproxy.ResponseProxy)  # noqa:E501

    def test_authenticate_post_login_password_error(self):
        self.assertIsInstance(self.proxy.authenticate("/", "POST", b"username=demo&password=unit", {"Cookie": "session_id=test"}), httpproxy.ResponseProxy)  # noqa:E501

    def test_authenticate_post_login(self):
        self.assertIsInstance(self.proxy.authenticate("/", "POST", b"username=demo&password=test", {"Cookie": "session_id=test"}), httpproxy.ResponseProxy)  # noqa:E501

    def test_authenticate_get_login(self):
        self.assertIsInstance(self.proxy.authenticate("/", "GET", b"", {"Cookie": "session_id=test"}), httpproxy.ResponseProxy)  # noqa:E501

    def test_request_authenticate(self):
        with mock.patch.object(self.proxy, "authenticate") as mock_auth:
            fake_auth = mock.MagicMock()
            mock_auth.side_effect = [fake_auth]
            self.assertIs(self.proxy.request(), fake_auth)


class TestCommand(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.listen_address = ("0.0.0.0", 8080)
        cls.target_url = "https://example.com/"

    @classmethod
    def tearDownClass(cls):
        pass

    @mock.patch.object(BasicConfig, "dumpf", mock.MagicMock())
    def setUp(self):
        self.config = BasicConfig("auth", {"users": {"demo": "test"}})
        self.auth = Argon2Auth(self.config)
        self.account = httpproxy.Account(self.auth)

    def tearDown(self):
        pass

    @mock.patch.object(httpproxy, "ThreadingHTTPServer", mock.MagicMock())
    def test_run(self):
        with mock.patch.object(httpproxy.Account, "from_file", mock.MagicMock(side_effect=[self.account])):  # noqa:E501
            self.assertIsNone(httpproxy.run(self.listen_address, self.target_url))  # noqa:E501

    @mock.patch.object(httpproxy.Account, "from_file", mock.MagicMock())
    @mock.patch.object(httpproxy, "run", mock.MagicMock())
    def test_main(self):
        self.assertEqual(httpproxy.main([]), ECANCELED)


if __name__ == "__main__":
    unittest.main()
