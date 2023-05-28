from pathlib import Path

from loguru import logger

from eaio import __electron_source__
from eaio.function.check import get_repos_status
from eaio.function.download import download_electron
from eaio.util.status import RepoStatus


def link(target: Path):
    ...


def check(target: Path):
    ...


def status():
    for path, depth, repo_status in get_repos_status():
        match depth, repo_status:
            case 0, RepoStatus.IsRepoRoot:
                logger.info(f"{path}")
            case 1, RepoStatus.IsRepo:
                logger.info(' '*depth*2+f"{path.name}")
            case 1, _:
                logger.error(' '*depth*2+f"{path.name} {repo_status.value}")
            case _, RepoStatus.Downloaded | RepoStatus.IsDir if depth > 1:
                logger.debug(' '*2*2+f"{path.relative_to(path.parents[depth-2])} {repo_status.value}")
            case _, _ if depth > 1:
                logger.error(' '*2*2+f"{path.relative_to(path.parents[depth-2])} {repo_status.value}")
            case _, _:
                logger.error('未知: '+' '*depth*2+f"{path.name} {repo_status.value}")


def download(drive: Path, version: str, arch: str, proxy: str | None, source: str | None):
    if not drive.exists():
        logger.error(f'{drive} 不是可用磁盘分区')
        exit(1)

    download_electron(drive, version, arch, proxy or None, source or __electron_source__[0])
