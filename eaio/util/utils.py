import binascii
import io
import math
from pathlib import Path
from typing import Generator
from ctypes import create_string_buffer

from loguru import logger


def dir_tree(path: Path, depth: int = 0) -> Generator[tuple[Path, int], None, None]:
    """
    遍历目录

    不会 yield 自身
    :param path: 目录
    :param depth: 默认深度
    :return: yield path, depth
    """
    for child_path in path.iterdir():
        if child_path.is_symlink():
            logger.debug(f"{child_path} 是软连接, 跳过遍历")
            continue
        elif child_path.is_dir():
            yield child_path, depth
            yield from dir_tree(child_path, depth + 1)
        elif child_path.is_file():
            yield child_path, depth
        else:
            logger.warning(f"dir_tree: {child_path} 文件类型未知, 跳过遍历")
            continue


def file_crc(path: Path) -> str:
    """
    计算指定文件的 crc32
    :param path: 文件路径
    :return: crc32
    """
    crc = 0
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            crc = binascii.crc32(chunk, crc)
    return hex(crc)


def get_all_drives() -> Generator[Path, None, None]:
    """
    获取系统中所有磁盘分区，仅 Windows 可用
    :return: yield path, 比如 C:/
    """
    from ctypes import windll

    result = create_string_buffer(1024)
    result_len = windll.kernel32.GetLogicalDriveStringsA(1024, result)
    for drive in result.raw[:result_len].strip(b'\x00').split(b'\x00'):
        yield to_drive(drive.decode().rstrip(r'\/'))


def to_drive(drive: str) -> Path:
    """
    将形如 C: 的磁盘分区 str 转换为形如 C:/ 的 path
    :param drive: 形如 C: 的磁盘分区 str
    :return: 形如 C:/ 的 path
    """
    return Path(drive).joinpath('/')


def str_size(size_bytes: int) -> str:
    """
    将字节数转换为带单位的str

    来自: https://stackoverflow.com/a/14822210
    :param size_bytes: 字节数
    :return: 带单位的str
    """
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    if size_bytes == 0:
        i = 0
        s = 0
    else:
        i = int(math.floor(math.log(size_bytes, 1024)))
        s = round(size_bytes / math.pow(1024, i), 2)
    return "%s %s" % (s, size_name[i])


log = io.StringIO()
