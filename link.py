from pathlib import Path

from loguru import logger

from check import find_electron_exe
from utils import dir_tree, download_electron, file_crc


def create_link(repo: Path, repo_name: Path | str, target: Path, target_name: Path | str):
    logger.info(f"将 {repo_name} 链接到 {target_name}")
    target.joinpath(target_name).unlink()
    target.joinpath(target_name).hardlink_to(repo.joinpath(repo_name))


def link(target: Path):
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
            create_link(repo, 'electron.exe', target, relative_name)
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
        create_link(repo, relative_name, target, relative_name)
    logger.info(f"已创建过硬链接: {linked_already}, 本次创建硬链接: {linked}, 不存在可链接文件: {no_source}, 可链接文件内容不一致: {not_same}")
