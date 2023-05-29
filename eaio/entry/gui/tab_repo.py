import re
import shutil
import tkinter as tk
from tkinter import ttk
from pathlib import Path

from loguru import logger


from eaio import __electron_source__, __electron_repo_re__
from eaio.entry.gui.tab import Tab
from eaio.function.check import get_repos_status
from eaio.function.download import download_electron
from eaio.util.error import DownloadError
from eaio.util.status import RepoRootStatus, RepoStatus, RepoChildStatus
from eaio.util.utils import str_size, get_all_drives, to_drive


class TabRepo(Tab):
    vChkHideDownloaded: tk.BooleanVar
    gChkHideDownloaded: ttk.Checkbutton
    gBtnRefresh: ttk.Button

    gLblDrive: ttk.Label
    gSltDrive: ttk.Combobox
    gLblVersion: ttk.Label
    vInpVersion: tk.StringVar
    gInpVersion: ttk.Entry
    gLblArch: ttk.Label
    gSltArch: ttk.Combobox
    gBtnDownload: ttk.Button

    vTree: dict[str, tuple[Path, int, RepoRootStatus | RepoStatus | RepoChildStatus]]
    gTree: ttk.Treeview
    gTreeVScroll: ttk.Scrollbar
    gTreeHScroll: ttk.Scrollbar
    mTree: tk.Menu

    gLblProxy: ttk.Label
    vInpProxy: tk.StringVar
    gInpProxy: ttk.Entry
    gLblSource: ttk.Label
    gSltSource: ttk.Combobox

    def create(self):
        row0 = ttk.Frame(self)
        row0.pack(padx=4, pady=(4, 2), fill=tk.X, expand=False)

        self.gLblDrive = ttk.Label(row0, text="磁盘分区:")
        self.gLblDrive.pack(padx=(0, 2), side=tk.LEFT)

        self.gSltDrive = ttk.Combobox(row0, state='readonly', values=[i.drive for i in get_all_drives()], width=0)
        self.gSltDrive.current(0)
        self.gSltDrive.pack(padx=(2, 2), side=tk.LEFT, fill=tk.X, expand=True)

        self.gLblVersion = ttk.Label(row0, text="版本:")
        self.gLblVersion.pack(padx=(2, 2), side=tk.LEFT)

        self.vInpVersion = tk.StringVar(row0)
        self.gInpVersion = ttk.Entry(row0, textvariable=self.vInpVersion, width=0)
        self.gInpVersion.pack(padx=(2, 2), side=tk.LEFT, fill=tk.X, expand=True)

        self.gLblArch = ttk.Label(row0, text="架构:")
        self.gLblArch.pack(padx=(2, 2), side=tk.LEFT)

        self.gSltArch = ttk.Combobox(row0, values=['ia32', 'x64', 'arm64'], width=0)
        self.gSltArch.pack(padx=(2, 2), side=tk.LEFT, fill=tk.X, expand=True)
        self.gSltArch.current(0)

        self.gBtnDownload = ttk.Button(row0, text="下载")
        self.gBtnDownload.bind("<ButtonRelease-1>", self.event)
        self.gBtnDownload.pack(padx=(2, 0), side=tk.LEFT)

        row1 = ttk.Frame(self)
        row1.pack(padx=4, pady=(2, 2), fill=tk.X, expand=False)

        self.vChkHideDownloaded = tk.BooleanVar(row1)
        self.vChkHideDownloaded.trace_add('write', lambda *_: self.scan_repo())
        self.gChkHideDownloaded = ttk.Checkbutton(row1, text="隐藏已下载文件", variable=self.vChkHideDownloaded)
        self.gChkHideDownloaded.pack(padx=(0, 2), side=tk.LEFT, anchor=tk.E, expand=True)

        self.gBtnRefresh = ttk.Button(row1, text="刷新链接仓库")
        self.gBtnRefresh.bind("<ButtonRelease-1>", self.event)
        self.gBtnRefresh.pack(padx=(2, 0), side=tk.LEFT, anchor=tk.W, expand=True)

        row2 = ttk.Frame(self)
        row2.pack(padx=4, pady=(2, 2), fill=tk.BOTH, expand=True)

        self.gTree = ttk.Treeview(row2, columns=['filename', 'size', 'status'], show='headings', selectmode=tk.BROWSE)
        # self.gTree.heading('#0', text='树', anchor=tk.CENTER)
        # self.gTree.column('#0', width=40, minwidth=40, stretch=False)
        self.gTree.heading('filename', text='文件', anchor=tk.CENTER)
        self.gTree.column('filename', width=320, minwidth=160, stretch=False, anchor=tk.W)
        self.gTree.heading('size', text='大小', anchor=tk.CENTER)
        self.gTree.column('size', width=80, minwidth=60, stretch=True, anchor=tk.E)
        self.gTree.heading('status', text='状态', anchor=tk.CENTER)
        self.gTree.column('status', width=80, minwidth=60, stretch=True, anchor=tk.CENTER)
        self.gTree.tag_configure(RepoChildStatus.Downloaded.value, background='#d3f9d8')
        self.gTree.tag_configure(RepoChildStatus.Deleted.value, background='#ffe3e3')
        self.gTree.tag_configure(RepoChildStatus.Modified.value, background='#ffe3e3')
        self.gTree.tag_configure(RepoStatus.DownloadFailed.value, background='#f1f3f5')
        self.gTree.tag_configure(RepoStatus.NotDownload.value, background='#c5f6fa')
        self.gTree.tag_configure(RepoRootStatus.NotExist.value, background='#c5f6fa')
        self.gTree.tag_configure(RepoRootStatus.NotDir.value, background='#f1f3f5')
        self.gTree.bind('<ButtonRelease-3>', self.event)
        self.gTree.grid(row=0, column=0, sticky=tk.NSEW)

        self.gTreeVScroll = ttk.Scrollbar(row2, command=self.gTree.yview, orient=tk.VERTICAL)
        self.gTreeVScroll.grid(row=0, column=1, sticky=tk.NS)
        self.gTreeHScroll = ttk.Scrollbar(row2, command=self.gTree.xview, orient=tk.HORIZONTAL)
        self.gTreeHScroll.grid(row=1, column=0, sticky=tk.EW)
        self.gTree.configure(yscrollcommand=self.gTreeVScroll.set, xscrollcommand=self.gTreeHScroll.set)

        self.mTree = tk.Menu(row2, tearoff=0)
        self.mTree.add_command(label="重新下载")
        self.mTree.add_command(label="删除")

        row2.grid_rowconfigure(0, weight=1)
        row2.grid_columnconfigure(0, weight=1)

        row3 = ttk.Frame(self)
        row3.pack(padx=4, pady=(2, 4), fill=tk.X, expand=False)

        self.gLblProxy = ttk.Label(row3, text="网络代理:")
        self.gLblProxy.pack(padx=(0, 2), side=tk.LEFT)

        self.vInpProxy = tk.StringVar(row3)
        self.gInpProxy = ttk.Entry(row3, textvariable=self.vInpProxy, width=0)
        self.gInpProxy.pack(padx=(2, 2), side=tk.LEFT, fill=tk.X, expand=True)

        self.gLblSource = ttk.Label(row3, text="在线仓库源:")
        self.gLblSource.pack(padx=(2, 2), side=tk.LEFT)

        self.gSltSource = ttk.Combobox(row3, values=__electron_source__, width=0)
        self.gSltSource.current(0)
        self.gSltSource.pack(padx=(2, 0), side=tk.LEFT, fill=tk.X, expand=True)

    def event(self, event: tk.Event, *args):
        match event.widget, event.type, event.num:
            case self.gBtnRefresh, tk.EventType.ButtonRelease, 1:
                self.scan_repo()
            case self.gBtnDownload, tk.EventType.ButtonRelease, 1:
                self.download_repo()
            case self.gTree, tk.EventType.ButtonRelease, 3:
                self.gTree.selection_set(self.gTree.identify_row(event.y))
                selected_file = self.get_select_file()
                if selected_file is not None:
                    selected_repo = self.get_select_repo()
                    self.mTree.entryconfig('重新下载', command=lambda *_: (self.select_repo_args(*selected_repo), self.download_repo()), state=tk.NORMAL if selected_repo is not None else tk.DISABLED)
                    self.mTree.entryconfig('删除', command=lambda *_: (shutil.rmtree(selected_file[0]), self.scan_repo()), state=tk.NORMAL if selected_repo is not None else tk.DISABLED)
                    self.mTree.post(event.x_root, event.y_root)
            case _:
                print(event, args)

    def active(self):
        self.scan_repo()

    def select_repo_args(self, drive: Path, version: str, arch: str):
        self.gSltDrive.set(drive.drive)
        self.vInpVersion.set(version)
        self.gSltArch.set(arch)

    def scan_repo(self):
        self.gTree.delete(*self.gTree.get_children())
        self.vTree = {}

        hide_downloaded = self.vChkHideDownloaded.get()

        for path, depth, repo_status in get_repos_status():
            if hide_downloaded and repo_status == RepoChildStatus.Downloaded:
                continue
            is_root = path.parent == to_drive(path.drive)
            is_dir = depth == 0 or depth == 1 or repo_status == RepoChildStatus.IsDir or path.is_dir()
            iid = str(path.absolute())
            self.gTree.insert('' if is_root else str(path.parent.absolute()), 'end', values=('    ' * depth + (str(path) if is_root else path.name), '' if is_dir or repo_status == RepoChildStatus.Deleted else str_size(path.stat().st_size), repo_status.value), iid=iid, open=True, tags=repo_status.value)
            self.vTree[iid] = (path, depth, repo_status)

    def download_repo(self):
        drive = to_drive(self.gSltDrive.get())
        electron_version = self.vInpVersion.get().strip().lstrip('v').strip()
        self.vInpVersion.set(electron_version)
        if not electron_version:
            self.error_msg("请输入需要下载的 Electron 版本")
            return
        electron_arch = self.gSltArch.get().strip()
        self.gSltArch.set(electron_arch)
        if not electron_arch:
            self.error_msg("请选择或输入需要下载的 CPU 架构")
            return
        proxy = self.vInpProxy.get().strip()
        self.vInpProxy.set(proxy)
        source = self.gSltSource.get().strip()
        self.gSltSource.set(source)

        try:
            download_electron(drive, electron_version, electron_arch, proxy=proxy or None, source=source or __electron_source__[0])
            self.scan_repo()
        except DownloadError as e:
            self.error_msg(str(e))

    def get_select_file(self):
        selected = self.gTree.selection()
        if len(selected) > 0:
            return self.vTree[selected[0]]
        else:
            return None

    def get_select_repo(self):
        selected = self.get_select_file()
        if selected is None:
            return None
        path, depth, repo_status = selected
        drive = to_drive(path.drive)
        regex: list[list[str]] = re.findall(__electron_repo_re__, path.name)
        if len(regex) != 1:
            logger.warning(f"选择的 {path.name} 匹配结果为 {regex}")
            return None
        version, arch = tuple(regex[0])
        return drive, version, arch
