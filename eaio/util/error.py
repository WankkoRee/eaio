class RepoError(Exception):
    """
    链接仓库错误
    """
    pass


class ScanError(Exception):
    """
    扫描时错误
    """
    pass


class TargetError(Exception):
    """
    目标 Electron 应用错误
    """
    pass


class DownloadError(Exception):
    """
    下载时错误
    """
    pass


class PEError(Exception):
    """
    解析 PE 文件时错误
    """
    pass
