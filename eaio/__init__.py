__version__ = "0.2.0"
__description__ = "一个通过将磁盘上所有 Electron 应用中相同文件硬链接到统一位置来减少磁盘占用的解决方案，就像 pnpm 一样。"
__fullname__ = f'eaio (Electron All in One) v{__version__}'
__electron_source__ = [
    'https://github.com/electron/electron/releases/download/v{version}/electron-v{version}-{platform}-{arch}.zip',
    'https://repo.huaweicloud.com/electron/{version}/electron-v{version}-{platform}-{arch}.zip',
    'https://registry.npmmirror.com/-/binary/electron/{version}/electron-v{version}-{platform}-{arch}.zip',
]
__electron_repo_root__ = ".eaio"
__electron_repo__ = "{version}-{arch}"
__electron_repo_re__ = r"^(\S+)-(\S+?)$"
__platform__ = "win32"
