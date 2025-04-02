# coding:utf-8

from errno import ECANCELED
import os
from typing import Optional
from typing import Sequence

from xhtml import FlaskProxy
from xhtml import LocaleTemplate
from xkits_command import ArgParser
from xkits_command import Command
from xkits_command import CommandArgument
from xkits_command import CommandExecutor
from xpw import AuthInit
from xpw import DEFAULT_CONFIG_FILE
from xpw import SessionKeys

from xpw_locker import server
from xpw_locker.attribute import __description__
from xpw_locker.attribute import __project__
from xpw_locker.attribute import __urlhome__
from xpw_locker.attribute import __version__


@CommandArgument(__project__, description=__description__)
def add_cmd(_arg: ArgParser):
    _arg.add_argument("--config", type=str, dest="config_file",
                      help="Authentication configuration", metavar="FILE",
                      default=os.getenv("CONFIG_FILE", DEFAULT_CONFIG_FILE))
    _arg.add_argument("--expires", type=int, dest="lifetime",
                      help="Session login interval hours", metavar="HOUR",
                      default=int(os.getenv("EXPIRES", "1")))
    _arg.add_argument("--target", type=str, dest="target_url",
                      help="Proxy target url", metavar="URL",
                      default=os.getenv("TARGET_URL", "http://localhost"))
    _arg.add_argument("--host", type=str, dest="listen_address",
                      help="Listen address", metavar="ADDR",
                      default=os.getenv("LISTEN_ADDRESS", "0.0.0.0"))
    _arg.add_argument("--port", type=int, dest="listen_port",
                      help="Listen port", metavar="PORT",
                      default=int(os.getenv("LISTEN_PORT", "3000")))


@CommandExecutor(add_cmd)
def run_cmd(cmds: Command) -> int:
    server.PORT = cmds.args.listen_port
    server.HOST = cmds.args.listen_address
    server.AUTH = AuthInit.from_file(cmds.args.config_file)
    server.PROXY = FlaskProxy(cmds.args.target_url)
    server.SESSIONS = SessionKeys(lifetime=cmds.args.lifetime * 3600)
    server.TEMPLATE = LocaleTemplate(os.path.join(server.BASE, "resources"))
    server.run()
    return ECANCELED


def main(argv: Optional[Sequence[str]] = None) -> int:
    cmds = Command()
    cmds.version = __version__
    return cmds.run(root=add_cmd, argv=argv, epilog=f"For more, please visit {__urlhome__}.")  # noqa:E501
