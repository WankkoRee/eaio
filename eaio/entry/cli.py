from collections import Counter
from pathlib import Path

from loguru import logger

from eaio import __electron_source__
from eaio.function.link import link as link_, unlink as unlink_
from eaio.function.check import get_repos_status, find_app_entries, get_files_link_status
from eaio.function.download import download_electron
from eaio.util.error import TargetError, ScanError, RepoError, DownloadError
from eaio.util.status import RepoStatus, LinkStatus
from eaio.util.utils import to_drive, str_size


def __dir_pre(target: Path):
    try:
        app_entries = find_app_entries(target)
    except TargetError as e:
        logger.error(e)
        exit(1)
    except ScanError as e:
        logger.error(e)
        exit(1)

    if len(app_entries) > 1:
        logger.info(f'存在多个疑似应用入口: {app_entries}')
        app_entry_index_str = input('请输入正确的应用入口下标:')
        if not app_entry_index_str:
            logger.error('未输入')
            exit(1)
        app_entry_index = int(app_entry_index_str)
        if not (0 <= app_entry_index < len(app_entries)):
            logger.error('输入超出范围')
            exit(1)
    else:
        app_entry_index = 0
    app_entry, electron_arch, electron_version = app_entries[app_entry_index]
    try:
        return app_entry, electron_arch, electron_version, [i for i in get_files_link_status(target, app_entry, electron_arch, electron_version)]
    except TargetError as e:
        logger.error(e)
        exit(1)
    except RepoError as e:
        logger.error(e)
        logger.info("正在下载")
        download(to_drive(target.drive), electron_version, electron_arch)
        link(target)  # 重新执行本次操作


def link(target: Path):
    app_entry, electron_arch, electron_version, files = __dir_pre(target)
    can_link = []
    for path, depth, link_status in files:
        if link_status == LinkStatus.CanLink:
            can_link.append(path)
    logger.info(f'可链接 {len(can_link)} 个, 共 {str_size(sum(i.stat().st_size for i in can_link))}')
    link_(app_entry, electron_arch, electron_version, can_link)
    logger.info('链接完成')


def unlink(target: Path):
    app_entry, electron_arch, electron_version, files = __dir_pre(target)
    can_unlink = []
    for path, depth, link_status in files:
        if link_status == LinkStatus.Linked:
            can_unlink.append(path)
    logger.info(f'可取消链接 {len(can_unlink)} 个, 共 {str_size(sum(i.stat().st_size for i in can_unlink))}')
    unlink_(app_entry, can_unlink)
    logger.info('取消链接完成')


def check(target: Path):
    app_entry, electron_arch, electron_version, files = __dir_pre(target)
    logger.info(f'应用入口为: {app_entry}')
    logger.info(f'Electron 版本为: {electron_version}')
    logger.info(f'CPU 架构为: {electron_arch}')
    logger.info('')
    total_sum: Counter[LinkStatus] = Counter()
    total_size: Counter[LinkStatus] = Counter()
    for path, depth, link_status in files:
        logger.info('    '*depth+f'{path.name}'+'    '+link_status.value)
        total_sum[link_status] += 1
        total_size[link_status] += path.stat().st_size
    logger.info('')
    logger.info(f"已链接 {total_sum[LinkStatus.Linked]} 个, 共 {str_size(total_size[LinkStatus.Linked])}")
    logger.info(f"可链接 {total_sum[LinkStatus.CanLink]} 个, 共 {str_size(total_size[LinkStatus.CanLink])}")
    logger.info(f"内容不一致 {total_sum[LinkStatus.NoMatch]} 个, 共 {str_size(total_size[LinkStatus.NoMatch])}")
    logger.info(f"无目标 {total_sum[LinkStatus.NoTarget]} 个, 共 {str_size(total_size[LinkStatus.NoTarget])}")


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
                pass  # logger.debug(' '*2*2+f"{path.relative_to(path.parents[depth-2])} {repo_status.value}")
            case _, _ if depth > 1:
                logger.error(' '*2*2+f"{path.relative_to(path.parents[depth-2])} {repo_status.value}")
            case _, _:
                logger.error('未知: '+' '*depth*2+f"{path.name} {repo_status.value}")


def download(drive: Path, version: str, arch: str, proxy: str | None = None, source: str = __electron_source__[0]):
    if not drive.exists():
        logger.error(f'{drive} 不是可用磁盘分区')
        exit(1)

    try:
        download_electron(drive, version, arch, proxy or None, source or __electron_source__[0])
    except DownloadError as e:
        logger.error(e)
        exit(1)
