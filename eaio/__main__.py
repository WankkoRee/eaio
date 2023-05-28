import argparse
from pathlib import Path
import sys

from loguru import logger

from eaio import __fullname__, __description__, __electron_repo_root__, __electron_source__
from eaio.entry.gui import gui
from eaio.entry.cli import link, unlink, check, status, download
from eaio.util.utils import to_drive, log


def log_config(verbose: bool = False):
    logger.remove()
    log_format = "<level>{level: ^8}</level> | <level>{message}</level>"
    logger.add(log, filter=lambda log_instance: log_instance['level'].name == "DEBUG")
    logger.add(log, filter=lambda log_instance: log_instance['level'].name == "WARNING")

    logger.add(sys.stdout, format=log_format, filter=lambda log_instance: log_instance['level'].name == "INFO")
    logger.add(sys.stderr, format=log_format, filter=lambda log_instance: log_instance['level'].name == "ERROR")

    if verbose:
        logger.add(sys.stdout, format=log_format, filter=lambda log_instance: log_instance['level'].name == "DEBUG")
        logger.add(sys.stderr, format=log_format, filter=lambda log_instance: log_instance['level'].name == "WARNING")


def main():
    log_config()
    if sys.platform != 'win32':
        logger.error('当前仅支持 Windows 平台，其他平台敬请期待')
        exit(0)

    parser = argparse.ArgumentParser(
        description=f'{__fullname__}\n{__description__}',
        epilog='注意:\n'
               f'1. 本工具会在所有磁盘分区下创建 {__electron_repo_root__} 目录作为链接仓库，请不要删除。\n'
               '2. 虽然删除后不会导致已链接的程序不可用，但会使得其失去原本的硬链接特性，需要重新链接才能减少磁盘占用。\n'
               '3. 请不要编辑任何已链接的文件(可通过执行 check 操作列出)内容，这会造成其他相同链接的 Electron 应用也发生变动。',
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,  # 使手动换行有效
    )
    parser.add_argument(
        '-V', '--Verbose',
        dest='verbose',
        action='store_true',
        help='显示详细日志',
    )
    parser.add_argument(
        '-v', '--version',
        help='闲着无聊就来看看当前版本',
        action='version', default=argparse.SUPPRESS,
        version=__fullname__,
    )
    parser.add_argument(
        '-h', '--help',
        help='就是显示你现在看到的这些提示',
        action='help', default=argparse.SUPPRESS,
    )
    subparsers = parser.add_subparsers(
        dest='action',
        title='可执行的操作',
        description='本工具提供的功能都在这里',
    )

    link_parser = subparsers.add_parser(
        name='link',
        aliases=['l'],
        help='为目标 Electron 应用创建硬链接以减少磁盘占用',
    )
    link_parser.add_argument(
        'path',
        help='目标 Electron 应用所在路径',
    )

    unlink_parser = subparsers.add_parser(
        name='unlink',
        aliases=['u'],
        help='为已经创建硬链接的目标 Electron 应用取消硬链接',
    )
    unlink_parser.add_argument(
        'path',
        help='目标 Electron 应用所在路径',
    )

    check_parser = subparsers.add_parser(
        name='check',
        aliases=['c'],
        help='列出目标 Electron 应用的硬链接情况',
    )
    check_parser.add_argument(
        'path',
        help='目标 Electron 应用所在路径',
    )

    status_parser = subparsers.add_parser(
        name='status',
        aliases=['s'],
        help=f'查看各个磁盘分区下链接仓库的使用情况，并检查其完整性和有效性',
    )

    download_parser = subparsers.add_parser(
        name='download',
        aliases=['d'],
        help='下载 Electron 预编译程序到指定磁盘分区下的链接仓库',
    )
    download_parser.add_argument(
        'drive',
        help='链接仓库所在磁盘分区, 如: C、D、E、F',
    )
    download_parser.add_argument(
        'version',
        help='目标 Electron 版本，如: 1.2.3',
    )
    download_parser.add_argument(
        'arch',
        help='目标 CPU 架构',
        choices=['ia32', 'x64', 'arm64'],
    )
    download_parser.add_argument(
        '-p',
        '--proxy',
        dest='proxy',
        help='网络代理(可选)',
        metavar='scheme://host:port',
        required=False,
    )
    download_parser.add_argument(
        '-s',
        '--source',
        dest='source',
        help='在线仓库源(可选)',
        metavar=__electron_source__[0],
        required=False,
    )

    args = parser.parse_args()
    if args.verbose:
        log_config(True)

    match args.action:
        case None:
            gui()
            exit(0)
        case 'link' | 'l':
            link(Path(args.path))
            exit(0)
        case 'unlink' | 'u':
            unlink(Path(args.path))
            exit(0)
        case 'check' | 'c':
            check(Path(args.path))
            exit(0)
        case 'status' | 's':
            status()
            exit(0)
        case 'download' | 'd':
            download(to_drive(to_drive(f'{args.drive.strip().upper()}:').drive), args.version, args.arch, args.proxy, args.source)
            exit(0)
        case _:
            logger.error('未知的操作')
            exit(1)


if __name__ == '__main__':
    main()
