import binascii
import json
from pathlib import Path
from typing import Generator
import io
import zipfile
from ctypes import windll, create_string_buffer

from loguru import logger
import requests


def dir_tree(path: Path, base: Path = None, depth: int = 0) -> Generator[tuple[Path, int], None, None]:
    if base is None:
        base = path
    for child_path in path.iterdir():
        relative_path = child_path.relative_to(base)
        if child_path.is_symlink():
            logger.debug(f"dir_tree: {relative_path} 是软连接")
            continue
        elif child_path.is_dir():
            yield from dir_tree(child_path, base, depth + 1)
        elif child_path.is_file():
            yield relative_path, depth
        else:
            logger.warning(f"dir_tree: {relative_path} 文件类型未知")
            continue


def download_electron(version: str, arch: str, repo: Path, override: bool = False):
    if repo.exists() and not repo.is_dir():
        # 存在但不是文件夹
        repo.unlink()
    if not repo.exists():
        # 不存在
        repo.mkdir(parents=True)
    elif not override:
        return
    signed_file = repo.joinpath('eaio.signed.json')
    if signed_file.exists():
        signed_file.unlink()  # 删除校验文件，等价于将此目录标记为未下载完成
    logger.info("正在下载 Electron 预编译程序")
    logger.info(f"目标版本: electron-v{version}-win32-{arch}")
    logger.info(f"目标仓库: {repo}")
    electron_url = f"https://github.com/electron/electron/releases/download/v{version}/electron-v{version}-win32-{arch}.zip"
    logger.debug(f"下载地址: {electron_url}")
    electron_resp = requests.get(electron_url)
    if electron_resp.status_code != 200:
        logger.error(f"下载失败，HTTP {electron_resp.status_code}")
        exit(1)
    signed = {}
    with io.BytesIO(electron_resp.content) as f:
        with zipfile.ZipFile(f, 'r') as zipf:
            for file in zipf.filelist:
                with open(repo.joinpath(file.filename), 'wb') as rf:
                    # 通过覆写文件的方式来更新已被硬链接的应用，如果直接替换文件会导致已有的硬链接失效
                    rf.write(zipf.read(file.filename))
                signed[file.filename] = hex(file.CRC)
    with open(signed_file, 'w') as f:  # 写入校验文件，等价于将此目录标记为下载完成
        f.write(json.dumps(signed))
    logger.info("下载 Electron 预编译程序完成")


def file_crc(path: Path) -> str:
    crc = 0
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            crc = binascii.crc32(chunk, crc)
    return hex(crc)


def get_drives() -> Generator[Path, None, None]:
    result = create_string_buffer(1024)
    result_len = windll.kernel32.GetLogicalDriveStringsA(1024, result)
    for drive in result.raw[:result_len].strip(b'\x00').split(b'\x00'):
        yield Path(drive.decode().rstrip(r'\/'))
