import shutil
from pathlib import Path
from typing import Iterable

from loguru import logger

from eaio import __electron_repo_root__, __electron_repo__
from eaio.util.utils import to_drive


def create_link(repo: Path, repo_name: Path, target: Path, target_name: Path):
    logger.info(f"将 {repo_name} 链接到 {target_name}")
    repo_file = repo.joinpath(repo_name)
    target_file = target.joinpath(target_name)
    target_file.unlink()
    target_file.hardlink_to(repo_file)


def link(app_entry: Path, arch: str, version: str, files: Iterable[Path]):
    drive = to_drive(app_entry.drive)
    repo = drive.joinpath(__electron_repo_root__).joinpath(__electron_repo__.format(version=version, arch=arch))
    target = app_entry.parent
    for file in files:
        relative_name = file.relative_to(target)
        create_link(repo, 'electron.exe' if file == app_entry else relative_name, target, relative_name)


def delete_link(target: Path, target_name: Path | str):
    logger.info(f"取消 {target_name} 链接")
    target_file = target.joinpath(target_name)
    bak = target_file.with_name(target_file.name+'.bak')
    shutil.copy2(target_file, bak)
    target_file.unlink()
    bak.rename(target_file)


def unlink(app_entry: Path, files: Iterable[Path]):
    target = app_entry.parent
    for file in files:
        relative_name = file.relative_to(target)
        delete_link(target, relative_name)
