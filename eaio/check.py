import re
from pathlib import Path

from loguru import logger
import pefile

from eaio.utils import dir_tree, download_electron, file_crc


def is_electron_exe(path: Path) -> tuple[str, str] | None:
    logger.debug(f'解析 {path.name} 文件头')
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories([
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
    ])
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        logger.debug(f'{path.name} 没有 IMAGE_DIRECTORY_ENTRY_EXPORT')
        return None
    export_dir_name = pe.DIRECTORY_ENTRY_EXPORT.name.decode()
    if export_dir_name != 'electron.exe':
        logger.debug(f'{path.name} 的 IMAGE_DIRECTORY_ENTRY_EXPORT 不合预期:{export_dir_name}')
        return None

    match pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]:
        case 'IMAGE_FILE_MACHINE_I386':
            arch = 'ia32'
        case 'IMAGE_FILE_MACHINE_AMD64':
            arch = 'x64'
        case 'IMAGE_FILE_MACHINE_ARM64':
            arch = 'arm64'
        case _:
            logger.warning(f'{path.name} 的 CPU 架构未知:{pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]}，如确认为应用入口，则需要提交 issue')
            arch = 'unknown'

    section_rdata = list(filter(lambda section: section.Name.strip(b'\x00') == b'.rdata', pe.sections))
    if len(section_rdata) == 0:
        logger.warning(f'{path.name} 无 .rdata 段')
        return None
    elif len(section_rdata) > 1:
        logger.warning(f'{path.name} 的 .rdata 段不唯一，默认使用第一个')
    section_rdata = section_rdata[0]
    with open(path, 'rb') as f:
        f.seek(section_rdata.PointerToRawData)
        rdata = f.read(section_rdata.SizeOfRawData)

    versions = [i.decode() for i in (set(re.findall(rb'Chrome/(?:[0-9.]+?|%s) Electron/([0-9.]+?)\x00', rdata)))]
    if len(versions) == 0:
        logger.warning(f'{path.name} 的 .rdata 段中找不到版本信息')
        return None
    elif len(versions) > 1:
        logger.warning(f'{path.name} 的 .rdata 段中版本信息不唯一:{versions}，默认使用第一个')

    logger.debug(f'{path.name} 的 electron 版本为 {versions[0]}，CPU 架构为 {arch}')
    pe.close()
    return versions[0], arch


def find_electron_exe(target: Path) -> tuple[str, str, str]:
    """
    在一级目录下寻找 electron.exe 的 fork 版本

    有 exit(1)
    :param target: 应用目录
    :return: electron_exe, electron_version, electron_arch
    """
    electron_exes = []
    for child_path in target.iterdir():
        if child_path.suffix == '.exe':
            is_electron_exe_result = is_electron_exe(child_path)
            if is_electron_exe_result is not None:
                electron_exes.append((child_path.relative_to(target), *is_electron_exe_result))
    if len(electron_exes) == 0:
        logger.error(f'{target} 中未找到应用入口')
        exit(1)
    elif len(electron_exes) > 1:
        logger.warning(f'{target} 中存在多个应用入口: {electron_exes}')
        electron_exe_index = int(input(f'请指定入口文件(下标, 范围[{0}, {len(electron_exes)-1}], 默认0):') or '0')
        if electron_exe_index >= len(electron_exes):
            logger.error(f'指定下标超出范围: {electron_exe_index} >= {len(electron_exes)}')
            exit(1)
        elif electron_exe_index < 0:
            logger.error(f'指定下标超出范围: {electron_exe_index} < 0')
            exit(1)
    else:
        electron_exe_index = 0
    return electron_exes[electron_exe_index]


def log_check_result(repo: Path, repo_name: Path | str, target: Path, target_name: Path | str):
    logger.info(f"{repo_name} 可链接到 {target_name}")


def check(target: Path):
    if not target.is_dir():
        logger.error(f'{target} 不是目录')
        exit(1)

    electron_exe, electron_version, electron_arch = find_electron_exe(target)
    logger.info(f"应用入口: {electron_exe}, Electron 版本: {electron_version}, CPU 架构: {electron_arch}")

    repo = Path(f"{target.drive}/.electron/{electron_version}-{electron_arch}")
    logger.info(f"预期链接到 {repo}")
    download_electron(electron_version, electron_arch, repo)

    linked_already = 0
    linked = 0
    no_source = 0
    not_same = 0
    for relative_name, depth in dir_tree(target):
        target_file = target.joinpath(relative_name)

        if target_file.stat().st_nlink > 1:
            linked_already += 1
            logger.info(f"{relative_name} 已创建过硬链接")
            continue

        if relative_name == electron_exe:
            linked += 1
            log_check_result(repo, 'electron.exe', target, relative_name)
            continue

        repo_file = repo.joinpath(relative_name)
        if not repo_file.exists():
            no_source += 1
            logger.info(f"{relative_name} 不存在可链接文件")
            continue
        repo_file_crc = file_crc(repo_file)
        target_file_crc = file_crc(target_file)
        if repo_file_crc != target_file_crc:
            not_same += 1
            logger.warning(f"{relative_name} 与可链接文件内容不一致")
            continue
        linked += 1
        log_check_result(repo, relative_name, target, relative_name)
    logger.info(f"已创建过硬链接: {linked_already}, 可创建硬链接: {linked}, 不存在可链接文件: {no_source}, 可链接文件内容不一致: {not_same}")
