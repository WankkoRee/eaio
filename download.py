from pathlib import Path

from loguru import logger

from utils import download_electron


def download(drive: Path, version: str, arch: str):
    if not drive.exists():
        logger.error(f'{drive} 不是可用磁盘分区')
        exit(1)

    download_electron(version, arch, Path(f"{drive.drive}/.electron/{version}-{arch}"), True)
