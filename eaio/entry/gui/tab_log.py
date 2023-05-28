import tkinter as tk

from eaio.entry.gui.tab import Tab


class TabLog(Tab):

    def create(self):
        ...

    def event(self, event: tk.Event, *args):
        match event.widget, event.type, event.num:
            case _:
                print(event, args)

    def active(self):
        ...
