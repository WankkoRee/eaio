import tkinter as tk
from abc import ABCMeta, abstractmethod
from tkinter import ttk, messagebox


class Tab(ttk.Frame, metaclass=ABCMeta):
    def __init__(self, tabs: ttk.Notebook, window: tk.Tk):
        super().__init__(tabs)
        self.gTabs = tabs
        self.window = window
        self.create()

    @abstractmethod
    def create(self):
        pass

    @abstractmethod
    def event(self, event: tk.Event, *args):
        match event.widget, event.type, event.num:
            case _:
                print(event, args)

    @abstractmethod
    def active(self):
        pass

    def error_msg(self, msg: str):
        messagebox.showerror("出了点问题", msg, parent=self)
