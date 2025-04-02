# coding:utf-8

import os
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from xpw.authorize import Argon2Auth
from xpw_locker import server

server.AUTH = Argon2Auth({"users": {"test": "unit"}})
server.PROXY = server.FlaskProxy("https://example.com/")
server.TEMPLATE = server.LocaleTemplate(os.path.join(server.BASE, "resources"))
server.SESSIONS = server.SessionKeys(lifetime=86400)
server.APP.secret_key = server.SESSIONS.secret.key


class TestFavicon(unittest.TestCase):

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

    def test_favicon_origin(self):
        with patch.object(server.PROXY, "request") as mock_request:
            fake_request = MagicMock()
            fake_request.status_code = 200
            mock_request.side_effect = [fake_request]
            with server.APP.test_request_context("/favicon.ico"):
                self.assertIs(server.favicon(), fake_request)

    def test_favicon_locked(self):
        with patch.object(server, "requests") as mock_requests:
            mock_requests.get.return_value.status_code = 500
            with server.APP.test_request_context("/favicon.ico"):
                response = server.favicon()
                self.assertEqual(response.status_code, 200)
                self.assertIsInstance(response.data, bytes)


class TestProxy(unittest.TestCase):

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

    def test_session_id_is_none(self):
        with server.APP.test_client() as client:
            response = client.get("/")
            self.assertEqual(response.status_code, 302)

    def test_session_id_password_empty(self):
        with patch.object(server.SESSIONS, "verify") as mock_verify:
            mock_verify.side_effect = [False]
            with server.APP.test_client() as client:
                client.set_cookie("session_id", "test")
                response = client.post("/", data={"username": "test", "password": ""},  # noqa:E501
                                       content_type="application/x-www-form-urlencoded")  # noqa:E501
                self.assertEqual(response.status_code, 200)

    def test_session_id_password_right(self):
        with patch.object(server.SESSIONS, "verify") as mock_verify:
            mock_verify.side_effect = [False]
            with server.APP.test_client() as client:
                client.set_cookie("session_id", "test")
                with patch.object(server.AUTH, "verify") as mock_auth:
                    mock_auth.side_effect = [True]
                    response = client.post("/", data={"username": "test", "password": "unit"},  # noqa:E501
                                           content_type="application/x-www-form-urlencoded")  # noqa:E501
                    self.assertEqual(response.status_code, 302)

    @patch.object(server, "PROXY")
    def test_proxy_ConnectionError_502(self, mock_proxy):
        with patch.object(server.SESSIONS, "verify") as mock_verify:
            mock_verify.side_effect = [True]
            mock_proxy.request.side_effect = [
                server.requests.ConnectionError()]
            with server.APP.test_client() as client:
                client.set_cookie("session_id", "test")
                response = client.get("/test")
                self.assertEqual(response.status_code, 502)
                self.assertEqual(response.data, b"Bad Gateway")

    @patch.object(server, "PROXY")
    def test_proxy(self, mock_proxy):
        fake_response = MagicMock()
        mock_proxy.request.side_effect = [fake_response]
        with server.APP.test_client() as client:
            headers = {"Host": f"localhost:{server.PORT}"}
            response = client.get("/test", headers=headers)
            self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
