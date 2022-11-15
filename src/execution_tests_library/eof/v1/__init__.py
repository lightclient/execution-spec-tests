"""
EVM Object Format Version 1 Libary to generate bytecode for testing purposes
"""
from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional

from ...code import Code, code_to_bytes
from ..constants import EOF_HEADER_TERMINATOR, EOF_MAGIC

VERSION_NUMBER = bytes.fromhex("01")
VERSION_MAX_SECTION_KIND = 3


class SectionKind(IntEnum):
    """
    Enum class of V1 valid section kind values
    """

    CODE = 1
    DATA = 2
    TYPE = 3


@dataclass(kw_only=True)
class Section:
    """
    Class that represents a section in an EOF V1 container.
    """

    data: Code | str | bytes | None = None
    """
    Data to be contained by this section.
    Can be code, another EOF container or any other abstract data.
    """
    custom_size: int | None = None
    """
    Size value to be used in the header.
    If set to None, the header is built with length of the data.
    """
    kind: SectionKind | int
    """
    Kind of section that is represented by this object.
    Can be any `int` outside of the values defined by `SectionKind`
    for testing purposes.
    """

    def get_header(self) -> bytes:
        """
        Get formatted header for this section according to its contents.
        """
        size = self.custom_size
        if size is None:
            if self.data is None:
                raise Exception(
                    "Attempted to build header without section data"
                )
            size = len(code_to_bytes(self.data))
        return self.kind.to_bytes(1, byteorder="big") + size.to_bytes(
            2, byteorder="big"
        )


@dataclass(kw_only=True)
class Container(Code):
    """
    Class that represents an EOF V1 container.
    """

    sections: List[Section]
    """
    List of sections in the container
    """
    custom_magic: Optional[int] = None
    """
    Custom magic value used to override the mandatory EOF value for testing
    purposes.
    """
    custom_version: Optional[int] = None
    """
    Custom version value used to override the mandatory EOF V1 value
    for testing purposes.
    """
    custom_terminator: Optional[bytes] = None
    """
    Custom terminator bytes used to terminate the header.
    """
    extra: Optional[bytes] = None
    """
    Extra data to be appended at the end of the container, which will
    not be considered part of any of the sections, for testing purposes.
    """
    name: Optional[str] = None

    def assemble(self) -> bytes:
        """
        Converts the EOF V1 Container into bytecode.
        """
        c = bytes.fromhex("EF")

        c += (
            EOF_MAGIC
            if self.custom_magic is None
            else self.custom_magic.to_bytes(1, "big")
        )

        c += (
            VERSION_NUMBER
            if self.custom_version is None
            else self.custom_version.to_bytes(1, "big")
        )

        # Add headers
        for s in self.sections:
            c += s.get_header()

        # Add header terminator
        if self.custom_terminator is not None:
            c += self.custom_terminator
        else:
            c += EOF_HEADER_TERMINATOR

        # Add section bodies
        for s in self.sections:
            c += code_to_bytes(s.data if s.data is not None else "0x")

        # Add extra (garbage)
        if self.extra is not None:
            c += self.extra

        return c
