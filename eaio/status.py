import json

from loguru import logger

from eaio.utils import get_drives, file_crc


def status():
    for drive in get_drives():
        repo = drive.joinpath('.electron')
        if not repo.exists():
            logger.info(f"{drive} 不存在 .electron 仓库")
            continue
        logger.info(f"{drive} 存在 .electron 仓库")
        for electron_version in repo.iterdir():
            signed_file = electron_version.joinpath('eaio.signed.json')
            download_status = signed_file.exists()
            logger.info(f"\t{electron_version.relative_to(repo)} {'下载完成' if download_status else '未下载完成'}")
            if download_status:
                with open(signed_file, 'r') as f:
                    signed: dict[str, str] = json.loads(f.read())
                for filename, crc in signed.items():
                    file = electron_version.joinpath(filename)
                    if not file.exists():
                        logger.info(f"\t\t{filename} 已不存在")
                        continue
                    c = file_crc(file)
                    if crc != c:
                        logger.info(f"\t\t{filename} 已被改动")
                        continue
