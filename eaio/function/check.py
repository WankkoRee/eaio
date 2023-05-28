import json
import re
from pathlib import Path
from typing import Generator

from loguru import logger
import pefile

from eaio import __electron_repo_root__, __electron_repo__
from eaio.util.utils import dir_tree, file_crc, get_all_drives, to_drive
from eaio.util.status import LinkStatus, RepoStatus
from eaio.util.error import ScanError, RepoError, TargetError


def is_electron_exe(path: Path) -> bool:
    """
    检查目标可执行文件是否为 Electron 入口
    :param path: 目标可执行文件路径
    :return: is_electron
    """
    logger.debug(f'解析 {path.name} 文件头')
    with pefile.PE(path, fast_load=True) as pe:
        pe.parse_data_directories([
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
        ])
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            logger.warning(f'{path.name} 没有 IMAGE_DIRECTORY_ENTRY_EXPORT')
            return False
        export_dir_name = pe.DIRECTORY_ENTRY_EXPORT.name.decode()
        if export_dir_name != 'electron.exe':
            logger.warning(f'{path.name} 的 IMAGE_DIRECTORY_ENTRY_EXPORT 不合预期:{export_dir_name}')
            return False
    return True


def parse_electron_exe(path: Path) -> tuple[str, str]:
    """
    解析 Electron 入口中包含的架构信息和版本信息
    :param path: 目标可执行文件路径
    :return: electron_arch, electron_version
    :raise: ScanError
    """
    logger.debug(f'解析 {path.name} 文件头')
    with pefile.PE(path, fast_load=True) as pe:
        match pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]:
            case 'IMAGE_FILE_MACHINE_I386':
                electron_arch = 'ia32'
            case 'IMAGE_FILE_MACHINE_AMD64':
                electron_arch = 'x64'
            case 'IMAGE_FILE_MACHINE_ARM64':
                electron_arch = 'arm64'
            case _:
                msg = f'{path.name} 的 CPU 架构未知:{pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]}，如确认为应用入口，则需要提交 issue'
                logger.warning(msg)
                raise ScanError(msg)

        section_rdata = list(filter(lambda section: section.Name.strip(b'\x00') == b'.rdata', pe.sections))
        if len(section_rdata) == 0:
            msg = f'{path.name} 无 .rdata 段，如确认为应用入口，则需要提交 issue'
            logger.warning(msg)
            raise ScanError(msg)
        elif len(section_rdata) > 1:
            logger.warning(f'{path.name} 的 .rdata 段不唯一，默认使用第一个')
        section_rdata = section_rdata[0]

    with open(path, 'rb') as f:
        f.seek(section_rdata.PointerToRawData)
        rdata = f.read(section_rdata.SizeOfRawData)

    versions = [i.decode() for i in (set(re.findall(rb'Chrome/(?:[0-9.]+?|%s) Electron/(\S+?)\x00', rdata)))]
    if len(versions) == 0:
        msg = f'{path.name} 的 .rdata 段中找不到版本信息，如确认为应用入口，则需要提交 issue'
        logger.warning(msg)
        raise ScanError(msg)
    elif len(versions) > 1:
        logger.warning(f'{path.name} 的 .rdata 段中版本信息不唯一:{versions}，默认使用第一个')
    electron_version = versions[0]

    return electron_arch, electron_version


def check_repo_status(repo: Path, depth: int = 0) -> Generator[tuple[Path, int, RepoStatus], None, None]:
    """
    检查链接仓库状况

    会 yield 自身
    :param repo: 链接仓库路径
    :param depth: 默认深度
    :return: yield path, depth, repo_status
    """
    if not repo.exists():
        logger.warning(f"{repo} 不存在，鉴定为未下载")
        yield repo, depth, RepoStatus.NotDownload
        return
    if not repo.is_dir():
        logger.warning(f"{repo} 不是目录")
        yield repo, depth, RepoStatus.NotDownload
        return

    signed_file = repo.joinpath('eaio.signed.json')
    if not signed_file.exists():
        logger.warning(f"{signed_file} 不存在，鉴定为下载未完成")
        yield repo, depth, RepoStatus.DownloadFailed
        return

    yield repo, depth, RepoStatus.IsRepo

    with open(signed_file, 'r') as f:
        signed: dict[str, str] = json.loads(f.read())

    already_yield_parents = set()
    for filename, crc_true in signed.items():
        file = repo.joinpath(filename)
        parents = [repo.joinpath(i) for i in file.relative_to(repo).parents][::-1]
        for parent in parents:
            if parent != repo:
                if parent not in already_yield_parents:
                    yield parent, depth + len(parent.relative_to(repo).parents), RepoStatus.IsDir
                    already_yield_parents.add(parent)
        if not file.exists():
            logger.warning(f"{file} 已不存在")
            yield file, depth + len(parents), RepoStatus.Deleted
            continue
        crc_actual = file_crc(file)
        if crc_true != crc_actual:
            logger.warning(f"{file} 已被改动, CRC32 预期为 {crc_true}, 实际为 {crc_actual}")
            yield file, depth + len(parents), RepoStatus.Modified
            continue
        yield file, depth + len(parents), RepoStatus.Downloaded


def get_repos_status() -> Generator[tuple[Path, int, RepoStatus], None, None]:
    for drive in get_all_drives():
        repo_root = drive.joinpath(__electron_repo_root__)
        if not repo_root.exists():
            logger.warning(f"{repo_root} 不存在，尝试创建")
            repo_root.mkdir(parents=True)
            yield repo_root, 0, RepoStatus.IsRepoRoot
            continue
        if not repo_root.is_dir():
            logger.warning(f"{repo_root} 不为文件夹，尝试删除后重新创建")
            repo_root.unlink()
            repo_root.mkdir(parents=True)
            yield repo_root, 0, RepoStatus.IsRepoRoot
            continue
        yield repo_root, 0, RepoStatus.IsRepoRoot

        for repo in repo_root.iterdir():
            yield from check_repo_status(repo, 1)


def find_app_entries(target: Path) -> list[tuple[Path, str, str]]:
    """
    扫描目标 Electron 应用目录，并返回应用入口
    :param target: 目标 Electron 应用目录
    :return: (app_entry, electron_arch, electron_version)[]
    :raise: TargetError, ScanError
    """
    if not target.exists():
        msg = f'{target} 不存在'
        logger.warning(msg)
        raise TargetError(msg)
    if not target.is_dir():
        msg = f'{target} 不是目录'
        logger.warning(msg)
        raise TargetError(msg)

    electron_exes = [child_path for child_path in target.iterdir() if child_path.suffix == '.exe' and is_electron_exe(child_path)]
    if len(electron_exes) == 0:
        msg = f'{target} 中未找到 Electron 应用'
        logger.warning(msg)
        raise ScanError(msg)

    ret_app_entries = []
    for child_path in electron_exes:
        try:
            electron_arch, electron_version = parse_electron_exe(child_path)
            logger.debug(f'{child_path} 为 Electron 应用, CPU 架构为 {electron_arch}, electron 版本为 {electron_version}')
            ret_app_entries.append((child_path, electron_arch, electron_version))
        except ScanError as e:
            continue
    if len(ret_app_entries) == 0:
        msg = f'{target} 中无法确认 Electron 应用入口'
        logger.warning(msg)
        raise ScanError(msg)

    return ret_app_entries


def get_files_link_status(target: Path, app_entry: Path, electron_arch: str, electron_version: str) -> Generator[tuple[Path, int, LinkStatus], None, None]:
    """
    扫描目标 Electron 应用目录，并返回链接状况
    :param target: 目标 Electron 应用目录
    :param app_entry: 应用入口
    :param electron_arch: CPU 架构
    :param electron_version: Electron 版本
    :return: yield path, depth, link_status
    :raise: TargetError, RepoError
    """
    if not target.exists():
        msg = f'{target} 不存在'
        logger.warning(msg)
        raise TargetError(msg)
    if not target.is_dir():
        msg = f'{target} 不是目录'
        logger.warning(msg)
        raise TargetError(msg)

    repo = to_drive(target.drive).joinpath(__electron_repo_root__).joinpath(__electron_repo__.format(version=electron_version, arch=electron_arch))
    logger.debug(f"预期链接仓库为 {repo}")
    if any(repo_status != RepoStatus.IsRepo and repo_status != RepoStatus.IsDir and repo_status != RepoStatus.Downloaded for path, depth, repo_status in check_repo_status(repo)):
        msg = f'{repo} 链接仓库存在问题'
        logger.warning(msg)
        raise RepoError(msg)

    for child_path, depth in dir_tree(target):
        if child_path.is_dir():
            logger.debug(f"{child_path} 是目录")
            yield child_path, depth, LinkStatus.IsDir
            continue

        if child_path.stat().st_nlink > 1:
            logger.debug(f"{child_path} 已链接过")
            yield child_path, depth, LinkStatus.Linked
            continue

        if child_path == app_entry:
            logger.debug(f"{child_path} 是应用入口")
            yield child_path, depth, LinkStatus.CanLink
            continue

        repo_file = repo.joinpath(child_path.relative_to(target))
        if not repo_file.exists():
            logger.warning(f"{child_path} 的目标文件 {repo_file} 不存在")
            yield child_path, depth, LinkStatus.NoTarget
            continue

        target_file_crc = file_crc(child_path)
        repo_file_crc = file_crc(repo_file)
        if target_file_crc != repo_file_crc:
            logger.warning(f"{child_path} 与 {repo_file} 内容不一致")
            yield child_path, depth, LinkStatus.NoMatch
            continue

        logger.debug(f"{child_path} 可链接到 {repo_file}")
        yield child_path, depth, LinkStatus.CanLink
