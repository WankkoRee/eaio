import binascii
import io
import math
import struct
from pathlib import Path
from typing import Generator
from ctypes import create_string_buffer, wintypes

from loguru import logger
import pefile

from eaio.util.error import PEError


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


def parse_icon_group(icon_group: bytes, icon_datas: dict[int, bytes]):
    result_header = b''
    result_body = b''

    ico_reserved, ico_type, ico_number = struct.unpack('<HHH', icon_group[:6])
    if ico_reserved != 0:
        msg = f'{ico_reserved} != 0'
        logger.warning(msg)
        raise PEError(msg)
    if ico_type != 1:
        msg = f'{ico_reserved} != 1'
        logger.warning(msg)
        raise PEError(msg)
    result_header += struct.pack('<HHH', ico_reserved, ico_type, ico_number)
    for i in range(ico_number):
        ico_image_width, ico_image_height, ico_image_color_count, ico_image_reserved, ico_image_color_places, ico_image_bits, ico_image_size, ico_image_offset = struct.unpack('<BBBBHHIH', icon_group[6+i*14:6+(i+1)*14])
        result_header += struct.pack('<BBBBHHII', ico_image_width, ico_image_height, ico_image_color_count, ico_image_reserved, ico_image_color_places, ico_image_bits, ico_image_size, 6 + 16 * ico_number + len(result_body))
        result_body += icon_datas[ico_image_offset]

    return result_header + result_body


def extract_icon(target):
    with pefile.PE(target, fast_load=True) as pe:
        pe.parse_data_directories([
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
        ])

        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            msg = f'{target.name} 没有 IMAGE_DIRECTORY_ENTRY_RESOURCE'
            logger.warning(msg)
            raise PEError(msg)

        icon_group_entries = [resource for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries if resource.id == 14]
        if len(icon_group_entries) == 0:
            msg = f'{target.name} 没有 RT_GROUP_ICON'
            logger.warning(msg)
            raise PEError(msg)
        elif len(icon_group_entries) > 1:
            logger.warning(f'{target.name} 的 RT_GROUP_ICON 不唯一，默认使用第一个')
        icon_group_data = None
        for entry in icon_group_entries[0].directory.entries:
            if entry.struct.Id == 1:  # 1 represents the default icon group
                data_entry = entry.directory.entries[0]
                icon_group_data = pe.get_data(data_entry.data.struct.OffsetToData, data_entry.data.struct.Size)
                break
        if icon_group_data is None:
            msg = f'{target.name} 的 RT_GROUP_ICON 中未找到默认图标 1'
            logger.warning(msg)
            raise PEError(msg)

        icon_entries = [resource for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries if resource.id == 3]
        if len(icon_entries) == 0:
            msg = f'{target.name} 没有 RT_ICON'
            logger.warning(msg)
            raise PEError(msg)
        icon_datas = {}
        for entry in icon_entries[0].directory.entries:
            data_entry = entry.directory.entries[0]
            icon_datas[entry.struct.Id] = pe.get_data(data_entry.data.struct.OffsetToData, data_entry.data.struct.Size)

        return parse_icon_group(icon_group_data, icon_datas)


def create_win_lnk(target: Path, source: Path, icon: Path | None = None):
    import pylnk3
    lnk = pylnk3.create(str(target))
    lnk.link_flags.IsUnicode = True

    levels = list(pylnk3.path_levels(source))
    elements = [pylnk3.RootEntry(pylnk3.ROOT_MY_COMPUTER),
                pylnk3.DriveEntry(levels[0])]
    for level in levels[1:]:
        segment = pylnk3.PathSegmentEntry.create_for_path(level)
        elements.append(segment)
    lnk.shell_item_id_list = pylnk3.LinkTargetIDList()
    lnk.shell_item_id_list.items = elements

    if icon:
        lnk.link_flags.HasIconLocation = True
        lnk.icon = str(icon)
        lnk.icon_index = 0

    lnk.link_flags.HasWorkingDir = True
    lnk.work_dir = str(source.parent)

    lnk.save()


log = io.StringIO()
