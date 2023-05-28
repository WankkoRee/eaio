import tkinter as tk
from tkinter import ttk

from eaio.entry.gui.tab import Tab
from eaio.util.utils import log


class TabLog(Tab):
    gTxtLog: tk.Text
    gTxtLogVScroll: ttk.Scrollbar
    gTxtLogHScroll: ttk.Scrollbar
    mTxtLog: tk.Menu

    vSeek = 0

    def create(self):
        row0 = ttk.Frame(self)
        row0.pack(padx=4, pady=(4, 4), fill=tk.BOTH, expand=True)

        self.gTxtLog = tk.Text(row0, wrap=tk.NONE)
        self.gTxtLog.bind("<Key>", lambda e: "break")  # readonly
        self.gTxtLog.bind('<ButtonRelease-3>', self.event)
        self.gTxtLog.grid(row=0, column=0, sticky=tk.NSEW)

        self.gTxtLogVScroll = ttk.Scrollbar(row0, command=self.gTxtLog.yview, orient=tk.VERTICAL)
        self.gTxtLogVScroll.grid(row=0, column=1, sticky=tk.NS)
        self.gTxtLogHScroll = ttk.Scrollbar(row0, command=self.gTxtLog.xview, orient=tk.HORIZONTAL)
        self.gTxtLogHScroll.grid(row=1, column=0, sticky=tk.EW)
        self.gTxtLog.configure(yscrollcommand=self.gTxtLogVScroll.set, xscrollcommand=self.gTxtLogHScroll.set)

        self.mTxtLog = tk.Menu(row0, tearoff=0)
        self.mTxtLog.add_command(label="清空", command=lambda *_: self.gTxtLog.delete('1.0', tk.END))

        row0.grid_rowconfigure(0, weight=1)
        row0.grid_columnconfigure(0, weight=1)

    def event(self, event: tk.Event, *args):
        match event.widget, event.type, event.num:
            case self.gTxtLog, tk.EventType.ButtonRelease, 3:
                self.mTxtLog.post(event.x_root, event.y_root)
            case _:
                print(event, args)

    def active(self):
        log.seek(self.vSeek)
        for line in log.readlines():
            self.gTxtLog.insert('1.0', line)
        self.vSeek = log.tell()
