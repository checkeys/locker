# coding:utf-8

from errno import ECANCELED
import os
from socket import AF_INET
from socket import SOCK_STREAM
from socket import socket
from typing import Optional
from typing import Sequence
from typing import Tuple
from urllib.parse import parse_qs

from xhtml.header.cookie import Cookies
from xhtml.header.headers import Headers
from xhtml.locale.template import LocaleTemplate
from xkits_command import ArgParser
from xkits_command import Command
from xkits_command import CommandArgument
from xkits_command import CommandExecutor
from xkits_lib import TimeUnit
from xkits_logger import Color
from xkits_logger import Logger
from xkits_thread import ThreadPool
from xpw import AuthInit
from xpw import BasicAuth
from xpw import DEFAULT_CONFIG_FILE
from xpw import Pass
from xpw import SessionKeys
from xserver.sock.header import RequestHeader
from xserver.sock.proxy import SockProxy

from xpw_locker.attribute import __description__
from xpw_locker.attribute import __official_name__
from xpw_locker.attribute import __urlhome__
from xpw_locker.attribute import __version__


class AuthProxy():
    BASE: str = os.path.dirname(__file__)

    def __init__(self, host: str, port: int,  # pylint:disable=R0913,R0917
                 timeout: TimeUnit = 300, lifetime: int = 86400,
                 auth: Optional[BasicAuth] = None,
                 token: Optional[str] = None):
        resources: str = os.path.join(self.BASE, "resources")
        self.__authentication: BasicAuth = auth or AuthInit.from_file()
        self.__sessions: SessionKeys = SessionKeys(lifetime=lifetime)
        self.__template: LocaleTemplate = LocaleTemplate(resources)
        self.__proxy: SockProxy = SockProxy(host, port, timeout)
        self.__token: Optional[str] = token

    @property
    def authentication(self) -> BasicAuth:
        return self.__authentication

    @property
    def api_token(self) -> Optional[str]:
        return self.__token

    @property
    def sessions(self) -> SessionKeys:
        return self.__sessions

    @property
    def template(self) -> LocaleTemplate:
        return self.__template

    @property
    def proxy(self) -> SockProxy:
        return self.__proxy

    def send_redirect(self, client: socket, location: str, session_id: Optional[str] = None):  # noqa:E501
        client.sendall(b"HTTP/1.1 302 Found\r\n")
        client.sendall(f"{Headers.LOCATION.value}: {location}\r\n".encode())
        if session_id:
            client.sendall(f"{Headers.SET_COOKIE.value}: session_id={session_id}\r\n".encode())  # noqa:E501
        client.sendall(b"\r\n")

    def send_html(self, client: socket, content: str):
        client.sendall(f"HTTP/1.1 200 OK\r\n{Headers.CONTENT_TYPE.value}: text/html\r\n{Headers.CONTENT_LENGTH.value}: {len(content)}\r\n\r\n".encode())  # noqa:E501
        client.sendall(content.encode())

    def authenticate(self, client: socket, head: RequestHeader, data: bytes):  # noqa:501 pylint:disable=R0911,R0912,R0914
        if head.request_line.target == "/favicon.ico":
            return self.proxy.new_connection(client, data)

        authorization: str = head.headers.get(Headers.AUTHORIZATION.value, "")
        if authorization:
            from xhtml.header.authorization import \
                Authorization  # pylint:disable=import-outside-toplevel

            auth: Authorization.Auth = Authorization.paser(authorization)
            if auth.type == Authorization.Basic.TYPE:
                assert isinstance(auth, Authorization.Basic)
                if self.authentication.verify(auth.username, auth.password):
                    return self.proxy.new_connection(client, data)  # verified
            elif auth.type == Authorization.Bearer.TYPE:
                assert isinstance(auth, Authorization.Bearer)
                if self.api_token and auth.token == self.api_token:
                    return self.proxy.new_connection(client, data)  # verified
            elif auth.type == Authorization.APIKey.TYPE:
                assert isinstance(auth, Authorization.APIKey)
                if self.api_token and auth.key == self.api_token:
                    return self.proxy.new_connection(client, data)  # verified

        cookies: Cookies = Cookies(head.headers.get(Headers.COOKIE.value, ""))
        session_id: str = cookies.get("session_id")
        if not session_id:
            return self.send_redirect(client, head.request_line.target, self.sessions.search().name)  # noqa:E501
        if self.sessions.verify(session_id):
            return self.proxy.new_connection(client, data)

        input_error_prompt: str = ""
        accept_language: str = head.headers.get(Headers.ACCEPT_LANGUAGE.value, "en")  # noqa:E501
        section = self.template.search(accept_language, "login")
        if head.request_line.method == "POST":
            data = data[head.length:]
            if (dlen := int(head.headers.get(Headers.CONTENT_LENGTH.value, "0")) - len(data)) > 0:  # noqa:E501
                data += client.recv(dlen)
            form_data = parse_qs(data.decode("utf-8"))
            username = form_data.get("username", [""])[0]
            password = form_data.get("password", [""])[0]
            if not password:
                input_error_prompt = section.get("input_password_is_null")
            elif self.authentication.verify(username, password):
                self.sessions.sign_in(session_id)
                return self.send_redirect(client, head.request_line.target)
            else:
                input_error_prompt = section.get("input_verify_error")
        context = section.fill(name=f"{__official_name__}(socket)", version=__version__)  # noqa:E501
        context.setdefault("input_error_prompt", input_error_prompt)
        context.setdefault("url", __urlhome__)
        content = self.template.seek("login.html").render(**context)
        return self.send_html(client, content)

    def request(self, client: socket, address: Tuple[str, int]):
        Logger.stderr(Color.yellow(f"Connection {address} connecting"))

        try:
            data: bytes = client.recv(1048576)  # 1MiB
            head = RequestHeader.parse(data)

            if head is not None:
                Logger.stderr(f"{head.request_line.method} {head.request_line.target}")  # noqa:E501
                self.authenticate(client, head, data)
                Logger.stderr(Color.red(f"Connection {address} closed"))
            else:
                Logger.stderr(Color.red(f"Invalid request: {data}"))

        except Exception:  # pylint:disable=broad-exception-caught
            import traceback  # pylint:disable=import-outside-toplevel

            Logger.stderr(Color.red(traceback.format_exc()))

        finally:
            if client.fileno() >= 0:
                client.close()


def run(listen_address: Tuple[str, int],  # pylint:disable=R0913,R0917
        target_host: str, target_port: int,
        auth: Optional[BasicAuth] = None,
        token: Optional[str] = None,
        lifetime: int = 86400,
        timeout: TimeUnit = 10,
        max_workers: int = 100):
    max_workers = max(min(10, max_workers), 1000)
    with socket(AF_INET, SOCK_STREAM) as server:
        server.bind(listen_address)
        server.listen(int(max_workers / 2))

        Logger.stderr(Color.green(f"Server listening on {listen_address}"))

        with ThreadPool(max_workers=max_workers) as pool:
            proxy: AuthProxy = AuthProxy(
                host=target_host, port=target_port,
                timeout=timeout, lifetime=lifetime,
                auth=auth, token=token
            )

            while True:
                client, address = server.accept()
                pool.submit(proxy.request, client, address)


@CommandArgument("locker-sock", description=__description__)
def add_cmd(_arg: ArgParser):
    _arg.add_argument("--config", type=str, dest="config_file",
                      help="Authentication configuration", metavar="FILE",
                      default=os.getenv("CONFIG_FILE", DEFAULT_CONFIG_FILE))
    _arg.add_argument("--expires", type=int, dest="lifetime",
                      help="Session login interval hours", metavar="HOUR",
                      default=int(os.getenv("EXPIRES", "1")))
    _arg.add_argument("--target-host", type=str, dest="target_host",
                      help="Proxy target host", metavar="HOST",
                      default=os.getenv("TARGET_HOST", "localhost"))
    _arg.add_argument("--target-port", type=int, dest="target_port",
                      help="Proxy target port", metavar="PORT",
                      default=int(os.getenv("TARGET_PORT", "80")))
    _arg.add_argument("--host", type=str, dest="listen_address",
                      help="Listen address", metavar="ADDR",
                      default=os.getenv("LISTEN_ADDRESS", "0.0.0.0"))
    _arg.add_argument("--port", type=int, dest="listen_port",
                      help="Listen port", metavar="PORT",
                      default=int(os.getenv("LISTEN_PORT", "3000")))
    _arg.add_argument("--key", type=str, dest="api_token",
                      help="API key", metavar="KEY",
                      default=os.getenv("API_KEY"))
    _arg.add_argument("--timeout", type=int, dest="timeout",
                      help="Socket timeout", metavar="SECONDS",
                      default=int(os.getenv("TIMEOUT", "5")))
    _arg.add_argument("--max-workers", type=int, dest="max_workers",
                      help="Maximum number of threads", metavar="THREADS",
                      default=int(os.getenv("MAX_WORKERS", "100")))


@CommandExecutor(add_cmd)
def run_cmd(cmds: Command) -> int:
    timeout: int = cmds.args.timeout
    max_workers: int = cmds.args.max_workers
    target_host: str = cmds.args.target_host
    target_port: int = cmds.args.target_port
    lifetime: int = cmds.args.lifetime * 3600
    auth: BasicAuth = AuthInit.from_file(cmds.args.config_file)
    listen_address: Tuple[str, int] = (cmds.args.listen_address, cmds.args.listen_port)  # noqa:E501
    api_token: str = cmds.args.api_token or Pass.random_generate(32, Pass.CharacterSet.BASIC).value  # noqa:E501
    cmds.logger.info(f"API key: {api_token}")
    run(listen_address=listen_address,
        target_host=target_host,
        target_port=target_port,
        auth=auth, token=api_token,
        lifetime=lifetime,
        timeout=timeout,
        max_workers=max_workers)
    return ECANCELED


def main(argv: Optional[Sequence[str]] = None) -> int:
    cmds = Command()
    cmds.version = __version__
    return cmds.run(root=add_cmd, argv=argv, epilog=f"For more, please visit {__urlhome__}.")  # noqa:E501


if __name__ == "__main__":
    run(("0.0.0.0", 3000), "example.com", 80, timeout=3)
