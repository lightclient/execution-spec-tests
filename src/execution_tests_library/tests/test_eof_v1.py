"""
Test suite for `code.eof.v1` module.
"""
import pytest

from ..eof.v1 import Container, Section, SectionKind


@pytest.mark.parametrize(
    ["container", "hex"],
    [
        # Single code section
        (
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data="0x00",
                    ),
                ],
            ),
            "ef00 01 01 0001 00 00",
        ),
        # Single data section
        (
            Container(
                sections=[
                    Section(
                        kind=SectionKind.DATA,
                        data="0x00",
                    ),
                ],
            ),
            "ef00 01 02 0001 00 00",
        ),
        # Custom invalid section
        (
            Container(
                sections=[
                    Section(
                        kind=0xFE,
                        data="0x00",
                    ),
                ],
            ),
            "ef00 01 fe 0001 00 00",
        ),
        # Multiple sections
        (
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data="0x0e",
                    ),
                    Section(
                        kind=SectionKind.DATA,
                        data="0x0f",
                    ),
                ],
            ),
            "ef00 01 01 0001 02 0001 00 0e 0f",
        ),
        # Invalid Magic
        (
            Container(
                custom_magic=0xFE,
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data="0x00",
                    ),
                ],
            ),
            "effe 01 01 0001 00 00",
        ),
        # Invalid Version
        (
            Container(
                custom_version=0x02,
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data="0x00",
                    ),
                ],
            ),
            "ef00 02 01 0001 00 00",
        ),
        # Section Invalid size Version
        (
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data="0x00",
                        custom_size=0xFFFF,
                    ),
                ],
            ),
            "ef00 01 01 ffff 00 00",
        ),
        # Nested EOF
        (
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data=Container(
                            sections=[
                                Section(
                                    kind=SectionKind.CODE,
                                    data="0x01",
                                )
                            ],
                        ),
                    ),
                ],
            ),
            "ef00 01 01 0008 00 ef00 01 01 0001 00 01",
        ),
        # Incomplete code section
        (
            Container(
                sections=[
                    Section(
                        custom_size=0x02,
                        kind=SectionKind.CODE,
                        data="0x",
                    ),
                ],
            ),
            "ef00 01 01 0002 00",
        ),
        # Trailing bytes after code section
        (
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data="0x600000",
                    ),
                ],
                extra=bytes.fromhex("deadbeef"),
            ),
            "ef00 01 01 0003 00 600000 deadbeef",
        ),
        # Multiple code sections
        (
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data="0x600000",
                    ),
                    Section(
                        kind=SectionKind.CODE,
                        data="0x600000",
                    ),
                ],
                name="multiple_code_sections",
            ),
            "ef00 01 01 0003 01 0003 00 600000 600000",
        ),
        # No section terminator
        (
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data="0x600000",
                    ),
                ],
                custom_terminator=bytes(),
            ),
            "ef00 01 01 0003 600000",
        ),
        # No section terminator 2
        (
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data="0x",
                        custom_size=3,
                    ),
                ],
                custom_terminator=bytes(),
            ),
            "ef00 01 01 0003",
        ),
    ],
)
def test_eof_v1_assemble(container: Container, hex: str):
    """
    Test `ethereum_test.types.code`.
    """
    assert container.assemble() == bytes.fromhex(hex.replace(" ", ""))
