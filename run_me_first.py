"""
Author: Alexander Hanel
Purpose: index the sdk-api and driver directory to parse yaml/mardown data and rename files to the api name
Requirements: pyyaml
Updates:
    * Version 1.0 Release
    * Version 1.1 Updated driver repo, added error handling for parsing  
    * Version 2.0  
        - fixed Python path slash #6 found by phdphuc
        - fixed [Bug] Incorrect md parsing logic #5 found by FuzzySecurity 
        - added debug logging to see parsed files as mentioned in issue #6 by phdphuc
        - added command line arguments 
        - added option to overwrite and regenerate api doc directory 
        - added functionality to flag functions that might have not been parsed correctly
        - replaced print output with logging.INFO
    * Version 2.1
        - code cleanup
        - logging params passed via arguments
        - clean markdown content before saving
"""

import argparse
import logging
import pathlib
import re
import shutil

import yaml

SDK_API_DIR = "sdk-api"
SDK_DOCS_DIR = "sdk-api-src"
DRIVER_SDK_API_DIR = "windows-driver-docs-ddi"
DRIVER_SDK_DOCS_DIR = "wdk-ddi-src"
CONTENT_DIR = "content"
NEW_API_DIR = "apis_md"


class FunctionFileDoc(object):
    IGNORED_NAMES = frozenset(
        [
            "Write",
            "WinUSB",
            "WIA",
            "WFP",
            "USB",
            "Universal",
            "UFX",
            "UEFI",
            "Testing",
            "Serial",
            "Root",
            "Querying",
            "Port",
            "Overview",
            "Native",
            "Can",
            "Calling",
            "Call",
            "Bring",
            "Battery",
            "AddTarget",
            "AddPoint",
            "AddLink",
            "Access",
            "IRP",
            "How",
            "Internet",
            "IPsec",
            "Language",
        ]
    )
    SKIP_NAME_CHARSET = ("+", "=", "()", "!", "::")

    def __init__(self, filepath: str):
        self._filepath = filepath
        with open(self._filepath, "r", errors="ignore") as infile:
            data = infile.read()

        parts = data.split("---")
        self.meta = yaml.safe_load(parts[1])  # Front Matter
        self.content = "---".join(parts[2:])  # Markdown content

    def verify(self) -> bool:
        name = self.name
        if name in self.IGNORED_NAMES:
            logging.debug(f"function name {name} in ignore list in {self._filepath}")
            return False

        if any([x in name for x in self.SKIP_NAME_CHARSET]):
            logging.debug(f"invalid function name {name} in {self._filepath}")
            return False

        return True

    def dump(self, filepath: str, clean_markdown: bool = True, force: bool = False):
        if not force and not self.verify():
            raise ValueError(f"invalid file format in {self._filepath}")

        with open(filepath, "w") as handle:
            content = (
                self._clean_markdown(self.content) if clean_markdown else self.content
            )
            handle.write(content)

    @staticmethod
    def _clean_markdown(text: str):
        # remove <a>, <div> tags
        text = re.sub(r"\</?(a|div)[^\>]*\>", "", text)

        # '## -description' -> '## Description'
        text = re.sub(
            r"# -(.+)", lambda match: f"# {match.group(1).capitalize()}", text
        )

        text = re.sub(r"# ([^\s]+) function", r"# \1", text)

        # remove "See also" links section
        text = re.sub(r"## See-also[^#]+", "", text, re.MULTILINE)

        # remove multiple enters and unnecessary spacing
        text = text.replace("\n\n\n", "\n\n").strip(" \n\r")

        return text

    @property
    def name(self):
        title = self.meta.get("title")
        if title is None:
            logging.debug(f"title is not present in {self._filepath}")
            return ValueError

        match = re.search("([^\s]+) function", title)
        if not match:
            logging.debug(f"unsupported title format in {self._filepath}")
            return ValueError

        return match.group(1).replace("\\", "")


def parse_file(filepath: str):
    try:
        unit = FunctionFileDoc(filepath)
        filename = unit.name + ".md"
        path = pathlib.Path(NEW_API_DIR) / filename
        unit.dump(str(path))
    except Exception as e:
        logging.debug(f"failed to process {filepath}: {e}")
        return None


def parse_from_directory(dirpath: str):
    path = pathlib.Path(dirpath)

    if not path.exists() or not path.is_dir():
        logging.warning(f"{path} directory could not be found")
        logging.warning("try: git submodule update --recursive")
        logging.warning(f"skipping {path}")
        return False

    for filepath in path.rglob("*.md"):
        if not filepath.name.startswith("_"):
            parse_file(filepath)


def create_output_directory(dirpath: str, force: bool = False):
    path = pathlib.Path(dirpath)
    if path.exists():
        if not force:
            logging.error(f"The directory {path} is already present, use --overwrite")
            exit(-1)

        logging.info(f"deleting and overwriting {path} directory")
        shutil.rmtree(str(path))

    logging.info(f"creating {path.name} directory at {path.absolute()}")
    path.mkdir(parents=True, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description="msdocviewer parser component")
    parser.add_argument(
        "-l",
        "--log",
        help="Log all parsing errors to debug-parser.log",
        default=None,
    )
    parser.add_argument(
        "-o",
        "--overwrite",
        help="overwrite apis_md directory",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-d",
        "--debug",
        help="Print lots of debugging statements",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.INFO,
    )

    args = parser.parse_args()
    logging.basicConfig(
        filename=args.log,
        level=args.loglevel,
        format="%(levelname)s - %(message)s",
    )

    create_output_directory(NEW_API_DIR, force=args.overwrite)
    logging.info("starting the parsing, this can take a few minutes")

    docset_paths = [
        str(pathlib.Path(SDK_API_DIR).absolute() / SDK_DOCS_DIR / CONTENT_DIR),
        str(
            pathlib.Path(DRIVER_SDK_API_DIR).absolute()
            / DRIVER_SDK_DOCS_DIR
            / CONTENT_DIR
        ),
    ]

    for path in docset_paths:
        logging.info(f"parsing {path}")
        parse_from_directory(path)
        logging.info(f"parsing {path} completed")

    logging.info("finished parsing")
    API_MD_target_path = pathlib.Path(NEW_API_DIR).absolute()
    logging.info(
        f'if using IDA set API_MD variable to "{API_MD_target_path}" in idaplugin/msdocviewida.py'
    )


if __name__ == "__main__":
    main()
