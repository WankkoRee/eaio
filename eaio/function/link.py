import shutil
from pathlib import Path
from typing import Iterable

from loguru import logger

from eaio import __electron_repo_root__, __electron_repo__
from eaio.util.error import PEError
from eaio.util.utils import to_drive, extract_icon, create_win_lnk


def create_link(repo: Path, repo_name: Path | str, target: Path, target_name: Path):
    logger.debug(f"将 {repo_name} 链接到 {target_name}")
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
        if file == app_entry:
            ico_data = b''
            try:
                ico_data = extract_icon(app_entry)
            except PEError as e:
                logger.error(f"提取图标失败\t{e}")
            if ico_data:
                with open(target.joinpath('eaio.ico'), 'wb') as f:
                    f.write(ico_data)
            create_win_lnk(app_entry.with_suffix('.lnk'), app_entry, target.joinpath('eaio.ico') if ico_data else None)
            create_link(repo, 'electron.exe', target, relative_name)
        else:
            create_link(repo,  relative_name, target, relative_name)


def delete_link(target: Path, target_name: Path | str):
    logger.debug(f"取消 {target_name} 链接")
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
