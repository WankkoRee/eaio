import tkinter as tk
from tkinter import ttk

from eaio import __fullname__
from eaio.entry.gui.tab_app import TabApp
from eaio.entry.gui.tab_repo import TabRepo
from eaio.entry.gui.tab_log import TabLog


class Eaio(tk.Tk):
    gTabs: ttk.Notebook
    gTabApp: TabApp
    gTabRepo: TabRepo
    gTabLog: TabLog

    def __init__(self):
        super().__init__()
        self.set_window()
        self.create_body()

    def set_window(self):
        width = 640
        height = 480
        self.title(__fullname__)
        self.geometry(f'{width}x{height}+{(self.winfo_screenwidth() - width) // 2}+{(self.winfo_screenheight() - height) // 2}')
        self.resizable(width=False, height=False)

    def create_body(self):
        self.gTabs = ttk.Notebook(self)
        self.gTabs.bind("<<NotebookTabChanged>>", self.event)

        self.gTabApp = TabApp(self.gTabs, self)
        self.gTabs.add(self.gTabApp, text="应用管理")

        self.gTabRepo = TabRepo(self.gTabs, self)
        self.gTabs.add(self.gTabRepo, text="仓库管理")

        self.gTabLog = TabLog(self.gTabs, self)
        self.gTabs.add(self.gTabLog, text="运行日志")

        self.gTabs.pack(fill=tk.BOTH, expand=True)

    def event(self, event: tk.Event, *args):
        match event.widget, event.type, event.num:
            case self.gTabs, tk.EventType.VirtualEvent, _:
                self.gTabs.nametowidget(self.gTabs.select()).active()
            case _:
                print(event, args)
