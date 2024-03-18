"""
Author: Alexander Hanel
Version: 1.1
Purpose: Microsoft Document (sdk-api & Driver) document viewer for IDA.
Updates:
    * Version 1.0   - Release
    * Version 1.1   - Fixed issues with opening and closing widget
"""

import json
from pathlib import Path

import idaapi
from idaapi import PluginForm
from PyQt5 import QtWidgets

# Path to the Markdown docs. Folder should start with
API_MD = r"!!CHANGE ME!!"

CONF_FILE = Path(__file__).with_suffix(".json")
CONF = {}
if CONF_FILE.exists():
    with open(CONF_FILE) as cf:
        CONF = json.load(cf)

if "documentation_path" in CONF:
    API_MD = CONF["documentation_path"]


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


def save_conf(doc_path: str) -> None:
    # doc_path = str(doc_path)
    # for line in fileinput.input(__file__, inplace=True):
    #     if line.startswith("API_MD ="):
    #         line = f'API_MD = r"{doc_path:r}"'

    #     print(f"{fileinput.filelineno()} {line}", end="")
    global CONF
    CONF["documentation_path"] = doc_path
    with open(CONF_FILE, "w") as cf:
        json.dump(CONF, cf, ensure_ascii=False, indent=2, default=str)


class MSDN(PluginForm):
    comment = "API MSDN Docs"

    def __init__(self, api_doc_path: str):
        super().__init__()
        api_doc_path = Path(api_doc_path)
        if not api_doc_path.is_dir():
            idaapi.warning(
                f"Plugin '{self.comment}' requires documentation directory "
                "to be set correctly.\n"
                f"'API_MD' now is '{API_MD}'.\n"
                f"Select any file in documentation directory in next ask dialog "
                "and directory will be saved for future times."
            )
            api_doc_path = idaapi.ask_file(False, "", "Select any docfile in folder")
            if Path(api_doc_path).is_file():
                api_doc_path = Path(api_doc_path).parent
                save_conf(api_doc_path)
                idaapi.msg(f"API_MD fixed to '{api_doc_path}'")
        self._doc_path = api_doc_path

    def OnCreate(self, form) -> None:
        """
        defines widget layout
        """
        self.parent = self.FormToPyQtWidget(form)
        self.main_layout = QtWidgets.QVBoxLayout()
        self.markdown_viewer_label = QtWidgets.QLabel()
        self.markdown_viewer_label.setText(self.comment)
        self.markdown_viewer = QtWidgets.QTextEdit()
        self.markdown_viewer.setReadOnly(True)
        self.main_layout.addWidget(self.markdown_viewer)
        self.parent.setLayout(self.main_layout)
        # self.load_markdown()

    def get_api_name(self) -> str:
        api_name = get_selected_api_name()
        # self.markdown_viewer_label.setText(
        if not api_name:
            api_name = idaapi.ask_str("", 0, "MSDN API")
        return api_name

    def get_api_file(self, api_name: str) -> Path:
        for path in self._doc_path.rglob(api_name + "*.md"):
            return path
        return None

        # return self._doc_path / (api_name + ".md")

    def load_markdown(self) -> None:
        """
        gets api and load corresponding (if present) api markdown
        """
        api_name = self.get_api_name()

        if not api_name:
            return

        md_path = self.get_api_file(api_name)
        if md_path and md_path.exists():
            api_markdown = md_path.read_text()
        else:
            api_markdown = "#### docs for %s could not be found" % api_name

        self.markdown_viewer.setMarkdown(api_markdown)


class MSDNPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MOD
    comment = "API MSDN Docs"
    help = "Plugin for viewing API MSDN Doc about selected function"
    wanted_name = "API MSDN Docs"
    wanted_hotkey = "Ctrl-Shift-F"

    _frm = None

    def __init__(self, api_doc_path: str = API_MD):
        super().__init__()
        self._doc_path = api_doc_path

    def init(self):
        self.options = (
            PluginForm.WOPN_MENU
            | PluginForm.WOPN_ONTOP
            | PluginForm.WOPN_RESTORE
            | PluginForm.WOPN_PERSIST
            | PluginForm.WCLS_CLOSE_LATER
        )
        return idaapi.PLUGIN_KEEP

    def run(self, arg) -> None:
        if not self._frm:
            self._frm = MSDN(self._doc_path)

        self._frm.Show(
            f"MSDN API Docs: hotkey: {self.wanted_hotkey}", options=self.options
        )
        self._frm.load_markdown()

    def term(self) -> None:
        pass


# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return MSDNPlugin()
