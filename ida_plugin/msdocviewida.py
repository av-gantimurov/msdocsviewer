"""
Author: Alexander Hanel
Version: 1.1
Purpose: Microsoft Document (sdk-api & Driver) document viewer for IDA.
Updates:
    * Version 1.0   - Release
    * Version 1.1   - Fixed issues with opening and closing widget
"""

from pathlib import Path

import idaapi
from idaapi import PluginForm
from PyQt5 import QtWidgets

# Path to the Markdown docs. Folder should start with
API_MD = r"!!CHANGE ME!!"

# global variables used to track initialization/creation of the forms.
started = False
frm = None


def remove_function_prefix(name: str) -> str:
    prefixes = [idaapi.FUNC_IMPORT_PREFIX, "cs:", "ds:", "j_"]
    for prefix in prefixes:
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def get_selected_api_name() -> str:
    """
    get selected item and extract function name from it
    via https://github.com/idapython/src/blob/e1c108a7df4b5d80d14d8b0c14ae73b924bff6f4/Scripts/msdnapihelp.py#L48
    return: api name as string
    """
    v = idaapi.get_current_viewer()
    highlight = idaapi.get_highlight(v)
    if not highlight:
        # print("No identifier was highlighted")
        return None

    name, _ = highlight

    # remove common prefixes
    name = remove_function_prefix(name)

    # select function call in decompiler view
    pos = name.find("(")
    if pos != -1:
        name = name[:pos]

    return name


class MSDN(PluginForm):

    def __init__(self, api_doc_path: str):
        self._doc_path = Path(api_doc_path)

    def OnCreate(self, form) -> None:
        """
        defines widget layout
        """
        self.parent = self.FormToPyQtWidget(form)
        self.main_layout = QtWidgets.QVBoxLayout()
        self.markdown_viewer_label = QtWidgets.QLabel()
        self.markdown_viewer_label.setText("API MSDN Docs")
        self.markdown_viewer = QtWidgets.QTextEdit()
        self.markdown_viewer.setReadOnly(True)
        self.main_layout.addWidget(self.markdown_viewer)
        self.parent.setLayout(self.main_layout)
        self.load_markdown()

    def load_markdown(self) -> None:
        """
        gets api and load corresponding (if present) api markdown
        """
        api_name = get_selected_api_name()
        if not api_name:
            api_markdown = "#### Invalid Address Selected"
            self.markdown_viewer.setMarkdown(api_markdown)
            return
        md_path = self._doc_path / (api_name + ".md")
        if md_path.exists():
            api_markdown = md_path.read_text()
        else:
            api_markdown = "#### docs for %s could not be found" % api_name
        self.markdown_viewer.setMarkdown(api_markdown)

    def OnClose(self, form) -> None:
        """
        Called when the widget is closed
        """
        global frm
        global started
        del frm
        started = False


class MSDNPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MOD
    comment = "API MSDN Docs"
    help = "Plugin for viewing API MSDN Doc about selected function"
    wanted_name = "API MSDN Docs"
    wanted_hotkey = "Ctrl-Shift-Z"

    def init(self, api_doc_path: str):
        self.options = (
            PluginForm.WOPN_MENU
            | PluginForm.WOPN_ONTOP
            | PluginForm.WOPN_RESTORE
            | PluginForm.WOPN_PERSIST
            | PluginForm.WCLS_CLOSE_LATER
        )
        self._doc_path = api_doc_path
        return idaapi.PLUGIN_KEEP

    def run(self, arg) -> None:
        global started
        global frm
        if not started:
            # API_MD
            if not Path(self._doc_path).exists():
                print(
                    f"ERROR: {self._doc_path} directory could not be found. "
                    "Make sure to execute python run_me_first.py."
                )
            frm = MSDN()
            frm.Show(
                f"MSDN API Docs: hotkey: {self.wanted_hotkey}", options=self.options
            )
            started = True
        else:
            frm.load_markdown()

    def term(self) -> None:
        pass


# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return MSDNPlugin(API_MD)
