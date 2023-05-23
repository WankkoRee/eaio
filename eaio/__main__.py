import argparse
from pathlib import Path
import sys

from loguru import logger

from eaio import __version__, __description__
from eaio.check import check
from eaio.download import download
from eaio.link import link
from eaio.status import status


def main():
    if sys.platform != 'win32':
        logger.error('当前仅支持 Windows 平台，其他平台敬请期待')
        exit(0)

    parser = argparse.ArgumentParser(
        description=f'eaio (Electron All in One) v{__version__}\n'
                    f'{__description__}',
        epilog='注意:\n'
               '1. 本工具会在所有磁盘分区下创建 .electron 目录作为硬链接源仓库(link 或 check 时创建)，请不要删除。\n'
               '2. 虽然删除后不会导致已链接的程序不可用，但会使得其失去原本的硬链接特性，需要重新链接才能减少磁盘占用。\n'
               '3. 请不要编辑任何已链接的文件(可通过执行 check 操作列出)内容，这会造成其他相同链接的 Electron 应用也发生变动。',
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,  # 使手动换行有效
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
        dest='path',
        help='目标 Electron 应用所在路径',
    )

    check_parser = subparsers.add_parser(
        name='check',
        aliases=['c'],
        help='列出目标 Electron 应用的硬链接情况',
    )
    check_parser.add_argument(
        dest='path',
        help='目标 Electron 应用所在路径',
    )

    status_parser = subparsers.add_parser(
        name='status',
        aliases=['s'],
        help='查看各个磁盘分区下 .electron 仓库的使用情况，并检查其完整性和有效性',
    )

    download_parser = subparsers.add_parser(
        name='download',
        aliases=['d'],
        help='下载 Electron 预编译程序到指定磁盘分区下的 .electron 仓库',
    )
    download_parser.add_argument(
        dest='drive',
        help='目标 .electron 仓库所在磁盘分区, 如: C、D、E、F',
    )
    download_parser.add_argument(
        dest='version',
        help='目标 Electron 版本，如: 1.2.3',
    )
    download_parser.add_argument(
        dest='arch',
        help='目标 CPU 架构',
        choices=['ia32', 'x64', 'arm64'],
    )

    version_parser = subparsers.add_parser(
        name='version',
        aliases=['v'],
        help='闲着无聊就来看看当前版本',
    )

    help_parser = subparsers.add_parser(
        name='help',
        aliases=['h'],
        help='就是显示你现在看到的这些提示',
    )

    args = parser.parse_args()
    match args.action:
        case None:
            parser.print_help()
            exit(0)
        case 'link' | 'l':
            link(Path(args.path))
            exit(0)
        case 'check' | 'c':
            check(Path(args.path))
            exit(0)
        case 'status' | 's':
            status()
            exit(0)
        case 'download' | 'd':
            download(Path(f'{args.drive.upper()}:'), args.version, args.arch)
            exit(0)
        case 'help' | 'h':
            parser.print_help()
            exit(0)
        case 'version' | 'v':
            logger.info(f'eaio (Electron All in One) v{__version__}')
            exit(0)
        case _:
            logger.error('未知的操作')
            exit(1)


if __name__ == '__main__':
    main()
