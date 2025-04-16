# coding:utf-8

from errno import ECANCELED
import unittest
from unittest import mock

from xpw.authorize import Argon2Auth

from xpw_locker import sockproxy


class TestAuthProxy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.target_host = "example.com"
        cls.target_port = 80

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.proxy = sockproxy.AuthProxy(self.target_host, self.target_port, token="test")  # noqa:E501

    def tearDown(self):
        pass

    @mock.patch.object(sockproxy, "socket")
    def test_authenticate_favicon(self, mock_socket):
        fake_socket = mock.MagicMock()
        mock_socket.side_effect = [fake_socket]
        client = sockproxy.socket()
        self.assertIs(client, fake_socket)
        with mock.patch.object(self.proxy.proxy, "new_connection") as mock_new_connection:  # noqa:E501
            fake_new_connection = mock.MagicMock()
            mock_new_connection.side_effect = [fake_new_connection]
            head = sockproxy.RequestHeader.parse(b"GET /favicon.ico HTTP/1.1\r\n\r\n")  # noqa:E501
            self.assertIsInstance(head, sockproxy.RequestHeader)
            assert isinstance(head, sockproxy.RequestHeader)
            self.assertIs(self.proxy.authenticate(client=client, head=head, data=b"test"), fake_new_connection)  # noqa:E501

    @mock.patch.object(sockproxy, "socket")
    def test_authenticate_basic_authorization(self, mock_socket):
        fake_socket = mock.MagicMock()
        mock_socket.side_effect = [fake_socket]
        client = sockproxy.socket()
        self.assertIs(client, fake_socket)
        with mock.patch.object(self.proxy.proxy, "new_connection") as mock_new_connection:  # noqa:E501
            fake_new_connection = mock.MagicMock()
            mock_new_connection.side_effect = [fake_new_connection]
            head = sockproxy.RequestHeader.parse(b"GET / HTTP/1.1\r\nAuthorization: Basic ZGVtbzp0ZXN0\r\n\r\n")  # noqa:E501
            self.assertIsInstance(head, sockproxy.RequestHeader)
            assert isinstance(head, sockproxy.RequestHeader)
            with mock.patch.object(self.proxy.authentication, "verify") as mock_verify:  # noqa:E501
                mock_verify.side_effect = [True]
                self.assertIs(self.proxy.authenticate(client=client, head=head, data=b"test"), fake_new_connection)  # noqa:E501

    @mock.patch.object(sockproxy, "socket")
    def test_authenticate_bearer_authorization(self, mock_socket):
        fake_socket = mock.MagicMock()
        mock_socket.side_effect = [fake_socket]
        client = sockproxy.socket()
        self.assertIs(client, fake_socket)
        with mock.patch.object(self.proxy.proxy, "new_connection") as mock_new_connection:  # noqa:E501
            fake_new_connection = mock.MagicMock()
            mock_new_connection.side_effect = [fake_new_connection]
            head = sockproxy.RequestHeader.parse(b"GET / HTTP/1.1\r\nAuthorization: Bearer test\r\n\r\n")  # noqa:E501
            self.assertIsInstance(head, sockproxy.RequestHeader)
            assert isinstance(head, sockproxy.RequestHeader)
            with mock.patch.object(self.proxy.authentication, "verify") as mock_verify:  # noqa:E501
                mock_verify.side_effect = [True]
                self.assertIs(self.proxy.authenticate(client=client, head=head, data=b"test"), fake_new_connection)  # noqa:E501

    @mock.patch.object(sockproxy, "socket")
    def test_authenticate_apikey_authorization(self, mock_socket):
        fake_socket = mock.MagicMock()
        mock_socket.side_effect = [fake_socket]
        client = sockproxy.socket()
        self.assertIs(client, fake_socket)
        with mock.patch.object(self.proxy.proxy, "new_connection") as mock_new_connection:  # noqa:E501
            fake_new_connection = mock.MagicMock()
            mock_new_connection.side_effect = [fake_new_connection]
            head = sockproxy.RequestHeader.parse(b"GET / HTTP/1.1\r\nAuthorization: ApiKey test\r\n\r\n")  # noqa:E501
            self.assertIsInstance(head, sockproxy.RequestHeader)
            assert isinstance(head, sockproxy.RequestHeader)
            with mock.patch.object(self.proxy.authentication, "verify") as mock_verify:  # noqa:E501
                mock_verify.side_effect = [True]
                self.assertIs(self.proxy.authenticate(client=client, head=head, data=b"test"), fake_new_connection)  # noqa:E501

    @mock.patch.object(sockproxy, "socket")
    def test_authenticate_session_id(self, mock_socket):
        fake_socket = mock.MagicMock()
        mock_socket.side_effect = [fake_socket]
        client = sockproxy.socket()
        self.assertIs(client, fake_socket)
        head = sockproxy.RequestHeader.parse(b"GET / HTTP/1.1\r\n\r\n")
        self.assertIsInstance(head, sockproxy.RequestHeader)
        assert isinstance(head, sockproxy.RequestHeader)
        self.assertIsNone(self.proxy.authenticate(client=client, head=head, data=b"test"))  # noqa:E501

    @mock.patch.object(sockproxy, "socket")
    def test_authenticate_session_id_verify(self, mock_socket):
        fake_socket = mock.MagicMock()
        mock_socket.side_effect = [fake_socket]
        client = sockproxy.socket()
        self.assertIs(client, fake_socket)
        with mock.patch.object(self.proxy.proxy, "new_connection") as mock_new_connection:  # noqa:E501
            fake_new_connection = mock.MagicMock()
            mock_new_connection.side_effect = [fake_new_connection]
            head = sockproxy.RequestHeader.parse(b"GET / HTTP/1.1\r\nCookie: session_id=123456\r\n\r\n")  # noqa:E501
            self.assertIsInstance(head, sockproxy.RequestHeader)
            assert isinstance(head, sockproxy.RequestHeader)
            with mock.patch.object(self.proxy.sessions, "verify") as mock_verify:  # noqa:E501
                mock_verify.side_effect = [True]
                self.assertIs(self.proxy.authenticate(client=client, head=head, data=b"test"), fake_new_connection)  # noqa:E501

    @mock.patch.object(sockproxy, "socket")
    def test_authenticate_post_login_password_null(self, mock_socket):
        fake_socket = mock.MagicMock()
        fake_socket.recv.side_effect = [b"username=demo&password="]
        mock_socket.side_effect = [fake_socket]
        client = sockproxy.socket()
        self.assertIs(client, fake_socket)
        data = b"POST / HTTP/1.1\r\nContent-Length: 23\r\nCookie: session_id=123456\r\n\r\n"  # noqa:E501
        head = sockproxy.RequestHeader.parse(data)  # noqa:E501
        self.assertIsInstance(head, sockproxy.RequestHeader)
        assert isinstance(head, sockproxy.RequestHeader)
        with mock.patch.object(self.proxy.sessions, "verify") as mock_verify1:
            mock_verify1.side_effect = [False]
            with mock.patch.object(self.proxy.authentication, "verify") as mock_verify2:  # noqa:E501
                mock_verify2.side_effect = [True]
                self.assertIsNone(self.proxy.authenticate(client=client, head=head, data=data))  # noqa:E501

    @mock.patch.object(sockproxy, "socket")
    def test_authenticate_post_login(self, mock_socket):
        fake_socket = mock.MagicMock()
        fake_socket.recv.side_effect = [b"username=demo&password=test"]
        mock_socket.side_effect = [fake_socket]
        client = sockproxy.socket()
        self.assertIs(client, fake_socket)
        data = b"POST / HTTP/1.1\r\nContent-Length: 27\r\nCookie: session_id=123456\r\n\r\n"  # noqa:E501
        head = sockproxy.RequestHeader.parse(data)  # noqa:E501
        self.assertIsInstance(head, sockproxy.RequestHeader)
        assert isinstance(head, sockproxy.RequestHeader)
        with mock.patch.object(self.proxy.sessions, "verify") as mock_verify1:
            mock_verify1.side_effect = [False]
            with mock.patch.object(self.proxy.authentication, "verify") as mock_verify2:  # noqa:E501
                mock_verify2.side_effect = [True]
                self.assertIsNone(self.proxy.authenticate(client=client, head=head, data=data))  # noqa:E501

    @mock.patch.object(sockproxy, "socket")
    def test_authenticate_get_login(self, mock_socket):
        fake_socket = mock.MagicMock()
        mock_socket.side_effect = [fake_socket]
        client = sockproxy.socket()
        self.assertIs(client, fake_socket)
        head = sockproxy.RequestHeader.parse(b"GET / HTTP/1.1\r\nCookie: session_id=123456\r\n\r\n")  # noqa:E501
        self.assertIsInstance(head, sockproxy.RequestHeader)
        assert isinstance(head, sockproxy.RequestHeader)
        with mock.patch.object(self.proxy.sessions, "verify") as mock_verify:
            mock_verify.side_effect = [False]
            self.assertIsNone(self.proxy.authenticate(client=client, head=head, data=b"test"))  # noqa:E501

    @mock.patch.object(sockproxy, "socket")
    def test_request(self, mock_socket):
        fake_socket = mock.MagicMock()
        fake_socket.fileno.side_effect = [1]
        fake_socket.recv.side_effect = [b"POST / HTTP/1.1\r\nContent-Length: 27\r\nCookie: session_id=123456\r\n\r\nusername=demo&password=test"]  # noqa:E501
        mock_socket.side_effect = [fake_socket]
        client = sockproxy.socket()
        self.assertIs(client, fake_socket)
        self.assertIsNone(self.proxy.request(client=client, address=("127.0.0.1", 1234)))  # noqa:E501

    @mock.patch.object(sockproxy, "socket")
    def test_request_raise(self, mock_socket):
        fake_socket = mock.MagicMock()
        fake_socket.fileno.side_effect = [1]
        fake_socket.recv.side_effect = [b"POST / HTTP/1.1\r\nContent-Length: 27\r\nCookie: session_id=123456\r\n\r\nusername=demo&password=test"]  # noqa:E501
        mock_socket.side_effect = [fake_socket]
        client = sockproxy.socket()
        self.assertIs(client, fake_socket)
        with mock.patch.object(self.proxy, "authenticate") as mock_auth:
            mock_auth.side_effect = [Exception()]
            self.assertIsNone(self.proxy.request(client=client, address=("127.0.0.1", 1234)))  # noqa:E501

    @mock.patch.object(sockproxy, "socket")
    def test_request_null(self, mock_socket):
        fake_socket = mock.MagicMock()
        fake_socket.fileno.side_effect = [1]
        fake_socket.recv.side_effect = [b""]
        mock_socket.side_effect = [fake_socket]
        client = sockproxy.socket()
        self.assertIs(client, fake_socket)
        self.assertIsNone(self.proxy.request(client=client, address=("127.0.0.1", 1234)))  # noqa:E501


class TestCommand(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.listen_address = ("0.0.0.0", 8080)
        cls.target_host = "example.com"
        cls.target_port = 80

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mock.patch.object(sockproxy, "socket", mock.MagicMock())
    @mock.patch.object(sockproxy, "AuthProxy", mock.MagicMock())
    @mock.patch.object(sockproxy, "ThreadPool", mock.MagicMock())
    def test_run(self):
        with sockproxy.socket(sockproxy.AF_INET, sockproxy.SOCK_STREAM) as server:  # noqa:E501
            server.accept.side_effect = [(mock.MagicMock(), ("127.0.0.1", 1234))]  # noqa:E501
            self.assertRaises(StopIteration, sockproxy.run,
                              listen_address=self.listen_address,
                              target_host=self.target_host,
                              target_port=self.target_port)

    @mock.patch.object(sockproxy, "run")
    @mock.patch.object(sockproxy.AuthInit, "from_file")
    def test_main(self, mock_auth, _):
        mock_auth.side_effect = [Argon2Auth({"users": {"test", "unit"}})]
        self.assertEqual(sockproxy.main([]), ECANCELED)


if __name__ == "__main__":
    unittest.main()
