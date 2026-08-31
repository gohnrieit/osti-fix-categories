#!/usr/bin/env python3
"""Regression checks for Patch Manager Categories (N) and Win7 overlay patches.

Run against a gearmulator tree after the overlay has been copied onto it:
  python3 scripts/check_categories_fixes.py /path/to/gearmulator
"""
from __future__ import annotations

import pathlib
import sys


def must_contain(path: pathlib.Path, needle: str) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    if needle not in text:
        raise SystemExit(f"FAIL {path}: missing {needle!r}")


def must_not_contain(path: pathlib.Path, needle: str) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    if needle in text:
        raise SystemExit(f"FAIL {path}: still contains {needle!r}")


class SearchRequest:
    """Mirrors SearchRequest::operator== after the overlay fix."""

    def __init__(self, **kwargs):
        self.name = kwargs.get("name", "")
        self.tags = kwargs.get("tags", ())
        self.source_node = kwargs.get("source_node")
        self.patch = kwargs.get("patch")
        self.source_type = kwargs.get("source_type", "Invalid")
        self.any_tag_of_type = kwargs.get("any_tag_of_type", frozenset())
        self.no_tag_of_type = kwargs.get("no_tag_of_type", frozenset())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SearchRequest):
            return NotImplemented
        return (
            self.name == other.name
            and self.tags == other.tags
            and self.source_node == other.source_node
            and self.patch == other.patch
            and self.source_type == other.source_type
            and self.any_tag_of_type == other.any_tag_of_type
            and self.no_tag_of_type == other.no_tag_of_type
        )

    def is_valid(self) -> bool:
        return bool(
            self.name
            or self.tags
            or self.source_node
            or self.patch
            or self.source_type != "Invalid"
            or self.any_tag_of_type
            or self.no_tag_of_type
        )


def test_search_request_equality() -> None:
    empty = SearchRequest()
    categories = SearchRequest(any_tag_of_type=frozenset({"Category"}))
    if empty == categories:
        raise SystemExit("FAIL: Categories anyTagOfType search compared equal to empty request")
    if not categories.is_valid():
        raise SystemExit("FAIL: Categories anyTagOfType-only request treated as invalid")
    if empty.is_valid():
        raise SystemExit("FAIL: empty SearchRequest should be invalid")
    same = SearchRequest(any_tag_of_type=frozenset({"Category"}))
    if categories != same:
        raise SystemExit("FAIL: identical anyTagOfType requests should compare equal")
    print("OK search-request equality / isValid")


def check_tree(root: pathlib.Path) -> None:
    db = root / "source/jucePluginLib/patchdb/db.cpp"
    search = root / "source/jucePluginLib/patchdb/search.cpp"
    treeitem = root / "source/jucePluginEditorLib/patchmanager/treeitem.cpp"
    juce = root / "source/juce.cmake"
    base = root / "base.cmake"

    must_not_contain(db, "8 * 1024 * 1024")
    must_contain(db, "512) * 1024 * 1024")
    must_contain(search, "anyTagOfType == _r.anyTagOfType")
    must_contain(search, "noTagOfType == _r.noTagOfType")
    must_contain(search, "!anyTagOfType.empty()")
    must_contain(treeitem, "countText")
    must_contain(treeitem, "centredRight")
    must_contain(juce, "JUCE_WIN_PER_MONITOR_DPI_AWARE=0")
    must_not_contain(juce, "JUCE_WIN_PER_MONITOR_DPI_AWARE=1")
    must_contain(base, "_WIN32_WINNT=0x0601")
    must_contain(base, "WINVER=0x0601")
    must_contain(base, "SUBSYSTEM:WINDOWS,6.01")
    must_contain(base, 'CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded')
    print(f"OK overlay patches in {root}")


def main() -> None:
    test_search_request_equality()
    if len(sys.argv) > 1:
        check_tree(pathlib.Path(sys.argv[1]))
    else:
        overlay = pathlib.Path(__file__).resolve().parents[1] / "overlay"
        if overlay.is_dir():
            check_tree(overlay)
        print("note: pass a gearmulator tree path to check the applied overlay")


if __name__ == "__main__":
    main()
