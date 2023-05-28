import tkinter as tk
from collections import Counter
from tkinter import ttk, filedialog
from pathlib import Path
from typing import Iterable

from eaio.entry.gui.tab import Tab
from eaio.function.check import get_files_link_status, find_app_entries
from eaio.function.link import link, unlink
from eaio.util.error import TargetError, RepoError, ScanError
from eaio.util.status import LinkStatus
from eaio.util.utils import str_size, to_drive


class TabApp(Tab):
    gLblDir: tk.Label
    vInpDir: tk.StringVar
    gInpDir: ttk.Entry
    gBtnDir: ttk.Button

    vChkHideLinked: tk.BooleanVar
    gChkHideLinked: ttk.Checkbutton
    gBtnScan: ttk.Button
    gLblEntry: ttk.Label
    vEntries: list[tuple[Path, str, str]]
    gSltEntry: ttk.Combobox
    vCanLink: tk.BooleanVar
    vCanUnlink: tk.BooleanVar
    gBtnLink: ttk.Button

    vFiles: dict[str, tuple[Path, int, LinkStatus]]
    gDirTree: ttk.Treeview
    gDirTreeVScroll: ttk.Scrollbar
    gDirTreeHScroll: ttk.Scrollbar
    mTree: tk.Menu

    gLblDirTotal: ttk.Label

    def create(self):
        row0 = ttk.Frame(self)
        row0.pack(padx=4, pady=(4, 2), fill=tk.X, expand=False)

        self.gLblDir = ttk.Label(row0, text="Electron 应用目录:")
        self.gLblDir.pack(padx=(0, 2), side=tk.LEFT)

        self.vInpDir = tk.StringVar(row0)
        self.gInpDir = ttk.Entry(row0, textvariable=self.vInpDir, width=0)
        self.gInpDir.pack(padx=(2, 2), side=tk.LEFT, fill=tk.X, expand=True)

        self.gBtnDir = ttk.Button(row0, text="选择应用文件夹")
        self.gBtnDir.bind("<ButtonRelease-1>", self.event)
        self.gBtnDir.pack(padx=(2, 0), side=tk.LEFT)

        row1 = ttk.Frame(self)
        row1.pack(padx=4, pady=(2, 2), fill=tk.X, expand=False)

        self.gBtnScan = ttk.Button(row1, text="扫描")
        self.gBtnScan.bind("<ButtonRelease-1>", self.event)
        self.gBtnScan.pack(padx=(0, 2), side=tk.LEFT)

        self.vChkHideLinked = tk.BooleanVar(row1)
        self.vChkHideLinked.trace_add('write', lambda *_: self.scan_dir(True))
        self.gChkHideLinked = ttk.Checkbutton(row1, text="隐藏已链接文件", variable=self.vChkHideLinked)
        self.gChkHideLinked.pack(padx=(2, 2), side=tk.LEFT)

        self.gLblEntry = ttk.Label(row1, text="应用入口:")
        self.gLblEntry.pack(padx=(2, 2), side=tk.LEFT)

        self.vEntries = []
        self.gSltEntry = ttk.Combobox(row1, state='readonly', values=[], width=0)
        self.gSltEntry.bind("<<ComboboxSelected>>", self.event)
        self.gSltEntry.pack(padx=(2, 2), side=tk.LEFT, fill=tk.X, expand=True)

        self.gBtnLink = ttk.Button(row1, text="链接")
        self.gBtnLink.bind("<ButtonRelease-1>", self.event)
        self.gBtnLink.pack(padx=(2, 2), side=tk.LEFT)
        self.vCanLink = tk.BooleanVar(row1)
        self.vCanLink.trace_add('write', lambda *_: self.gBtnLink.configure(state='normal' if self.vCanLink.get() else 'disabled'))
        self.vCanLink.set(False)

        self.gBtnUnlink = ttk.Button(row1, text="取消链接")
        self.gBtnUnlink.bind("<ButtonRelease-1>", self.event)
        self.gBtnUnlink.pack(padx=(2, 0), side=tk.LEFT)
        self.vCanUnlink = tk.BooleanVar(row1)
        self.vCanUnlink.trace_add('write', lambda *_: self.gBtnUnlink.configure(state='normal' if self.vCanUnlink.get() else 'disabled'))
        self.vCanUnlink.set(False)

        row2 = ttk.Frame(self)
        row2.pack(padx=4, pady=(2, 2), fill=tk.BOTH, expand=True)

        self.vFiles = {}
        self.gDirTree = ttk.Treeview(row2, columns=['filename', 'size', 'status'], show='headings', selectmode=tk.BROWSE)
        # self.gDirTree.heading('#0', text='树', anchor=tk.CENTER)
        # self.gDirTree.column('#0', width=40, minwidth=40, stretch=False)
        self.gDirTree.heading('filename', text='文件', anchor=tk.CENTER)
        self.gDirTree.column('filename', width=320, minwidth=160, stretch=False, anchor=tk.W)
        self.gDirTree.heading('size', text='大小', anchor=tk.CENTER)
        self.gDirTree.column('size', width=80, minwidth=60, stretch=True, anchor=tk.E)
        self.gDirTree.heading('status', text='状态', anchor=tk.CENTER)
        self.gDirTree.column('status', width=80, minwidth=60, stretch=True, anchor=tk.CENTER)
        self.gDirTree.tag_configure(LinkStatus.Linked.value, background='#d3f9d8')
        self.gDirTree.tag_configure(LinkStatus.CanLink.value, background='#c5f6fa')
        self.gDirTree.tag_configure(LinkStatus.NoMatch.value, background='#ffe3e3')
        self.gDirTree.tag_configure(LinkStatus.NoTarget.value, background='#f1f3f5')
        self.gDirTree.bind('<ButtonRelease-3>', self.event)
        self.gDirTree.grid(row=0, column=0, sticky=tk.NSEW)

        self.gDirTreeVScroll = ttk.Scrollbar(row2, command=self.gDirTree.yview, orient=tk.VERTICAL)
        self.gDirTreeVScroll.grid(row=0, column=1, sticky=tk.NS)
        self.gDirTreeHScroll = ttk.Scrollbar(row2, command=self.gDirTree.xview, orient=tk.HORIZONTAL)
        self.gDirTreeHScroll.grid(row=1, column=0, sticky=tk.EW)
        self.gDirTree.configure(yscrollcommand=self.gDirTreeVScroll.set, xscrollcommand=self.gDirTreeHScroll.set)

        self.mTree = tk.Menu(row2, tearoff=False)
        self.mTree.add_command(label="链接")
        self.mTree.add_command(label="取消链接")

        row2.grid_rowconfigure(0, weight=1)
        row2.grid_columnconfigure(0, weight=1)

        row3 = ttk.Frame(self)
        row3.pack(padx=4, pady=(2, 4), fill=tk.X, expand=False)

        self.gLblDirTotal = ttk.Label(row3, width=0)
        self.gLblDirTotal.setvar('show_num', False)
        self.gLblDirTotal.pack(padx=(0, 0), side=tk.LEFT, fill=tk.X, expand=True)
        self.gLblDirTotal.bind("<ButtonRelease-1>", self.event)

        self.refresh_dir_total()

    def event(self, event: tk.Event, *args):
        match event.widget, event.type, event.num:
            case self.gBtnDir, tk.EventType.ButtonRelease, 1:
                select_result = filedialog.askdirectory(title="选择应用文件夹")
                if select_result:
                    self.vInpDir.set(str(Path(select_result).absolute()))
                    self.scan_entry()
            case self.gBtnScan, tk.EventType.ButtonRelease, 1:
                self.scan_entry()
            case self.gSltEntry, tk.EventType.VirtualEvent, _:
                self.scan_dir()
            case self.gBtnLink, tk.EventType.ButtonRelease, 1:
                self.link(file[0] for file in self.vFiles.values() if file[2] == LinkStatus.CanLink)
            case self.gBtnUnlink, tk.EventType.ButtonRelease, 1:
                self.unlink(file[0] for file in self.vFiles.values() if file[2] == LinkStatus.Linked)
            case self.gDirTree, tk.EventType.ButtonRelease, 3:
                self.gDirTree.selection_set(self.gDirTree.identify_row(event.y))
                selected = self.get_select_file()
                if selected is not None:
                    self.mTree.entryconfig('链接', command=lambda *_: self.link([selected[0]]), state=tk.NORMAL if selected[2] == LinkStatus.CanLink else tk.DISABLED)
                    self.mTree.entryconfig('取消链接', command=lambda *_: self.unlink([selected[0]]), state=tk.NORMAL if selected[2] == LinkStatus.Linked else tk.DISABLED)
                    self.mTree.post(event.x_root, event.y_root)
            case self.gLblDirTotal, tk.EventType.ButtonRelease, 1:
                self.gLblDirTotal.setvar('show_num', not self.gLblDirTotal.getvar('show_num'))
                self.refresh_dir_total()
            case _:
                print(event, args)

    def active(self):
        self.scan_entry(True)

    def scan_entry(self, silent: bool = False):
        self.vEntries = []
        self.gSltEntry.configure(values=[])
        self.gSltEntry.set('')

        self.vCanLink.set(False)
        self.vCanUnlink.set(False)
        self.gDirTree.delete(*self.gDirTree.get_children())

        base_path = Path(self.vInpDir.get()).absolute()
        self.vInpDir.set(str(base_path))

        try:
            self.vEntries = find_app_entries(base_path)
            self.gSltEntry.configure(values=[f"{app_entry.relative_to(base_path)} v{electron_version}-{electron_arch}" for app_entry, electron_arch, electron_version in self.vEntries])
            self.gSltEntry.current(0)
            self.scan_dir(silent)
        except TargetError as e:
            if not silent:
                self.error_msg(str(e))
        except ScanError as e:
            if not silent:
                self.error_msg(str(e))

    def scan_dir(self, silent: bool = False):
        self.vCanLink.set(False)
        self.vCanUnlink.set(False)
        self.gDirTree.delete(*self.gDirTree.get_children())

        base_path = Path(self.vInpDir.get()).absolute()
        self.vInpDir.set(str(base_path))

        self.vFiles = {}
        self.refresh_dir_total()

        hide_linked = self.vChkHideLinked.get()

        if self.gSltEntry.current() == -1:
            return
        app_entry, electron_arch, electron_version = self.vEntries[self.gSltEntry.current()]

        try:
            for path, depth, link_status in get_files_link_status(base_path, app_entry, electron_arch, electron_version):
                is_root = path.parent == base_path
                is_dir = link_status == LinkStatus.IsDir
                if is_dir:
                    self.vFiles[str(path)] = path, 0, link_status
                else:
                    self.vFiles[str(path)] = path, path.stat().st_size, link_status
                if hide_linked and link_status == LinkStatus.Linked:
                    continue
                self.gDirTree.insert('' if is_root else str(path.parent.absolute()), 'end', values=('    ' * depth + path.name, '' if is_dir else str_size(path.stat().st_size), link_status.value), iid=str(path.absolute()), open=True, tags=link_status.value)
            self.refresh_dir_total()
            if any(file[2] == LinkStatus.CanLink for file in self.vFiles.values()):
                self.vCanLink.set(True)
            if any(file[2] == LinkStatus.Linked for file in self.vFiles.values()):
                self.vCanUnlink.set(True)
        except TargetError as e:
            if not silent:
                self.error_msg(str(e))
        except RepoError as e:
            if not silent:
                self.error_msg(str(e))
                self.window.gTabRepo.select_repo_args(to_drive(app_entry.drive), electron_version, electron_arch)
                self.gTabs.select(1)

    def get_select_file(self):
        selected = self.gDirTree.selection()
        if len(selected) > 0:
            return self.vFiles[selected[0]]
        else:
            return None

    def refresh_dir_total(self):
        show_num = self.gLblDirTotal.getvar('show_num')
        total: Counter[LinkStatus] = Counter()
        for path, size, link_status in self.vFiles.values():
            total[link_status] += 1 if show_num else size
        self.gLblDirTotal.configure(
            text=
            f"已链接 {total[LinkStatus.Linked]} 个, "
            f"可链接 {total[LinkStatus.CanLink]} 个, "
            f"内容不一致 {total[LinkStatus.NoMatch]} 个, "
            f"无目标 {total[LinkStatus.NoTarget]} 个"
            if show_num else
            f"已链接 {str_size(total[LinkStatus.Linked])}, "
            f"可链接 {str_size(total[LinkStatus.CanLink])}, "
            f"内容不一致 {str_size(total[LinkStatus.NoMatch])}, "
            f"无目标 {str_size(total[LinkStatus.NoTarget])}"
        )

    def link(self, files: Iterable[Path]):
        link(*self.vEntries[self.gSltEntry.current()], files=files)
        self.scan_dir()

    def unlink(self, files: Iterable[Path]):
        unlink(self.vEntries[self.gSltEntry.current()][0], files=files)
        self.scan_dir()
