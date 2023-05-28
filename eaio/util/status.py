import enum


@enum.unique
class LinkStatus(enum.Enum):
    Linked = "已链接"
    CanLink = "可链接"
    NoMatch = "内容不一致"
    NoTarget = "无目标"
    IsDir = "文件夹"


@enum.unique
class RepoStatus(enum.Enum):
    Downloaded = "已下载"
    Deleted = "被删除"
    Modified = "发生改动"
    DownloadFailed = "下载失败"
    NotDownload = "未下载"
    IsDir = "文件夹"
    IsRepo = "链接仓库"
    IsRepoRoot = "链接仓库根目录"
