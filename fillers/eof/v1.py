"""
Test EVM Object Format Version 1
"""
from enum import Enum
from typing import List, Optional, Tuple

from execution_tests_library import (
    Account,
    Code,
    Environment,
    StateTest,
    TestAddress,
    Transaction,
    Yul,
    generate_initcode,
    test_from,
    to_address,
)
from execution_tests_library.eof import LATEST_EOF_VERSION
from execution_tests_library.eof.v1 import (
    VERSION_MAX_SECTION_KIND,
    Container,
    Section,
    SectionKind,
)

# Fork can be later changed to "Shanghai" on inclusion.
# For now, EIPs are used.
EOF_FORK_NAME = "Shanghai"

EIP_EOF = 3540
EIP_CODE_VALIDATION = 3670
EIP_STATIC_RELATIVE_JUMPS = 4200
EIP_EOF_FUNCTIONS = 4750
EIP_EOF_STACK_VALIDATION = 5450

V1_EOF_EIPS = [
    EIP_EOF,
    EIP_CODE_VALIDATION,
    EIP_STATIC_RELATIVE_JUMPS,
    EIP_EOF_FUNCTIONS,
    # EIP_EOF_STACK_VALIDATION, Not implemented yet
]


class Opcode:
    byte: bytes
    byte_int: int
    popped_stack_items: int
    pushed_stack_items: int
    min_stack_height: int
    data_portion_length: int = 0

    def __init__(
        self,
        opcode: Optional["Opcode"] = None,
        *,
        byte: int = 0,
        popped_stack_items: int = 0,
        pushed_stack_items: int = 0,
        min_stack_height: Optional[int] = None,
        data_portion_length: int = 0,
    ):
        if opcode is not None:
            self.byte_int = opcode.byte_int
            self.byte = opcode.byte
            self.popped_stack_items = opcode.popped_stack_items
            self.pushed_stack_items = opcode.pushed_stack_items
            self.min_stack_height = opcode.min_stack_height
            self.data_portion_length = opcode.data_portion_length

        else:
            self.byte_int = byte
            self.byte = bytes([byte])
            self.popped_stack_items = popped_stack_items
            self.pushed_stack_items = pushed_stack_items
            if min_stack_height is not None:
                self.min_stack_height = min_stack_height
            else:
                self.min_stack_height = popped_stack_items
            self.data_portion_length = data_portion_length

    def hex(self) -> str:
        return self.byte.hex()


class OPCODES(Opcode, Enum):
    """
    Lists all valid opcodes within an EOF V1 container on `EOF_FORK_NAME`
    """

    STOP = Opcode(
        byte=0x00,
    )
    ADD = Opcode(
        byte=0x01,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    MUL = Opcode(
        byte=0x02,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    SUB = Opcode(
        byte=0x03,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    DIV = Opcode(
        byte=0x04,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    SDIV = Opcode(
        byte=0x05,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    MOD = Opcode(
        byte=0x06,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    SMOD = Opcode(
        byte=0x07,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    ADDMOD = Opcode(
        byte=0x08,
        popped_stack_items=3,
        pushed_stack_items=1,
    )
    MULMOD = Opcode(
        byte=0x09,
        popped_stack_items=3,
        pushed_stack_items=1,
    )
    EXP = Opcode(
        byte=0x0A,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    SIGNEXTEND = Opcode(
        byte=0x0B,
        popped_stack_items=2,
        pushed_stack_items=1,
    )

    LT = Opcode(
        byte=0x10,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    GT = Opcode(
        byte=0x11,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    SLT = Opcode(
        byte=0x12,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    SGT = Opcode(
        byte=0x13,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    EQ = Opcode(
        byte=0x14,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    ISZERO = Opcode(
        byte=0x15,
        popped_stack_items=1,
        pushed_stack_items=1,
    )
    AND = Opcode(
        byte=0x16,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    OR = Opcode(
        byte=0x17,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    XOR = Opcode(
        byte=0x18,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    NOT = Opcode(
        byte=0x19,
        popped_stack_items=1,
        pushed_stack_items=1,
    )
    BYTE = Opcode(
        byte=0x1A,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    SHL = Opcode(
        byte=0x1B,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    SHR = Opcode(
        byte=0x1C,
        popped_stack_items=2,
        pushed_stack_items=1,
    )
    SAR = Opcode(
        byte=0x1D,
        popped_stack_items=2,
        pushed_stack_items=1,
    )

    SHA3 = Opcode(
        byte=0x20,
        popped_stack_items=2,
        pushed_stack_items=1,
    )

    ADDRESS = Opcode(
        byte=0x30,
        pushed_stack_items=1,
    )
    BALANCE = Opcode(
        byte=0x31,
        popped_stack_items=1,
        pushed_stack_items=1,
    )
    ORIGIN = Opcode(
        byte=0x32,
        pushed_stack_items=1,
    )
    CALLER = Opcode(
        byte=0x33,
        pushed_stack_items=1,
    )
    CALLVALUE = Opcode(
        byte=0x34,
        pushed_stack_items=1,
    )
    CALLDATALOAD = Opcode(
        byte=0x35,
        popped_stack_items=1,
        pushed_stack_items=1,
    )
    CALLDATASIZE = Opcode(
        byte=0x36,
        pushed_stack_items=1,
    )
    CALLDATACOPY = Opcode(
        byte=0x37,
        popped_stack_items=3,
    )
    CODESIZE = Opcode(
        byte=0x38,
        pushed_stack_items=1,
    )
    CODECOPY = Opcode(
        byte=0x39,
        popped_stack_items=3,
    )
    GASPRICE = Opcode(
        byte=0x3A,
        pushed_stack_items=1,
    )
    EXTCODESIZE = Opcode(
        byte=0x3B,
        popped_stack_items=1,
        pushed_stack_items=1,
    )
    EXTCODECOPY = Opcode(
        byte=0x3C,
        popped_stack_items=4,
    )
    RETURNDATASIZE = Opcode(
        byte=0x3D,
        pushed_stack_items=1,
    )
    RETURNDATACOPY = Opcode(
        byte=0x3E,
        popped_stack_items=3,
    )
    EXTCODEHASH = Opcode(
        byte=0x3F,
        popped_stack_items=1,
        pushed_stack_items=1,
    )

    BLOCKHASH = Opcode(
        byte=0x40,
        popped_stack_items=1,
        pushed_stack_items=1,
    )
    COINBASE = Opcode(
        byte=0x41,
        pushed_stack_items=1,
    )
    TIMESTAMP = Opcode(
        byte=0x42,
        pushed_stack_items=1,
    )
    NUMBER = Opcode(
        byte=0x43,
        pushed_stack_items=1,
    )
    PREVRANDAO = Opcode(
        byte=0x44,
        pushed_stack_items=1,
    )
    GASLIMIT = Opcode(
        byte=0x45,
        pushed_stack_items=1,
    )
    CHAINID = Opcode(
        byte=0x46,
        pushed_stack_items=1,
    )
    SELFBALANCE = Opcode(
        byte=0x47,
        pushed_stack_items=1,
    )
    BASEFEE = Opcode(
        byte=0x48,
        pushed_stack_items=1,
    )

    POP = Opcode(
        byte=0x50,
        popped_stack_items=1,
    )
    MLOAD = Opcode(
        byte=0x51,
        popped_stack_items=1,
        pushed_stack_items=1,
    )
    MSTORE = Opcode(
        byte=0x52,
        popped_stack_items=2,
    )
    MSTORE8 = Opcode(
        byte=0x53,
        popped_stack_items=2,
    )
    SLOAD = Opcode(
        byte=0x54,
        popped_stack_items=1,
        pushed_stack_items=1,
    )
    SSTORE = Opcode(
        byte=0x55,
        popped_stack_items=2,
    )
    JUMP = Opcode(
        byte=0x56,
        popped_stack_items=1,
    )
    JUMPI = Opcode(
        byte=0x57,
        popped_stack_items=2,
    )
    PC = Opcode(
        byte=0x58,
        pushed_stack_items=1,
    )
    MSIZE = Opcode(
        byte=0x59,
        pushed_stack_items=1,
    )
    GAS = Opcode(
        byte=0x5A,
        pushed_stack_items=1,
    )
    JUMPDEST = Opcode(
        byte=0x5B,
    )
    RJUMP = Opcode(
        byte=0x5C,
        data_portion_length=2,
    )
    RJUMPI = Opcode(
        byte=0x5D,
        popped_stack_items=1,
        data_portion_length=2,
    )
    CALLF = Opcode(
        byte=0xB0,
        min_stack_height=0,  # This requirement is actually variable
        data_portion_length=2,
    )
    RETF = Opcode(
        byte=0xB1,
        min_stack_height=0,  # This requirement is actually variable
    )

    PUSH0 = Opcode(
        byte=0x5F,
        pushed_stack_items=1,
    )
    PUSH1 = Opcode(
        byte=0x60,
        pushed_stack_items=1,
        data_portion_length=1,
    )
    PUSH2 = Opcode(
        byte=0x61,
        pushed_stack_items=1,
        data_portion_length=2,
    )
    PUSH3 = Opcode(
        byte=0x62,
        pushed_stack_items=1,
        data_portion_length=3,
    )
    PUSH4 = Opcode(
        byte=0x63,
        pushed_stack_items=1,
        data_portion_length=4,
    )
    PUSH5 = Opcode(
        byte=0x64,
        pushed_stack_items=1,
        data_portion_length=5,
    )
    PUSH6 = Opcode(
        byte=0x65,
        pushed_stack_items=1,
        data_portion_length=6,
    )
    PUSH7 = Opcode(
        byte=0x66,
        pushed_stack_items=1,
        data_portion_length=7,
    )
    PUSH8 = Opcode(
        byte=0x67,
        pushed_stack_items=1,
        data_portion_length=8,
    )
    PUSH9 = Opcode(
        byte=0x68,
        pushed_stack_items=1,
        data_portion_length=9,
    )
    PUSH10 = Opcode(
        byte=0x69,
        pushed_stack_items=1,
        data_portion_length=10,
    )
    PUSH11 = Opcode(
        byte=0x6A,
        pushed_stack_items=1,
        data_portion_length=11,
    )
    PUSH12 = Opcode(
        byte=0x6B,
        pushed_stack_items=1,
        data_portion_length=12,
    )
    PUSH13 = Opcode(
        byte=0x6C,
        pushed_stack_items=1,
        data_portion_length=13,
    )
    PUSH14 = Opcode(
        byte=0x6D,
        pushed_stack_items=1,
        data_portion_length=14,
    )
    PUSH15 = Opcode(
        byte=0x6E,
        pushed_stack_items=1,
        data_portion_length=15,
    )
    PUSH16 = Opcode(
        byte=0x6F,
        pushed_stack_items=1,
        data_portion_length=16,
    )
    PUSH17 = Opcode(
        byte=0x70,
        pushed_stack_items=1,
        data_portion_length=17,
    )
    PUSH18 = Opcode(
        byte=0x71,
        pushed_stack_items=1,
        data_portion_length=18,
    )
    PUSH19 = Opcode(
        byte=0x72,
        pushed_stack_items=1,
        data_portion_length=19,
    )
    PUSH20 = Opcode(
        byte=0x73,
        pushed_stack_items=1,
        data_portion_length=20,
    )
    PUSH21 = Opcode(
        byte=0x74,
        pushed_stack_items=1,
        data_portion_length=21,
    )
    PUSH22 = Opcode(
        byte=0x75,
        pushed_stack_items=1,
        data_portion_length=22,
    )
    PUSH23 = Opcode(
        byte=0x76,
        pushed_stack_items=1,
        data_portion_length=23,
    )
    PUSH24 = Opcode(
        byte=0x77,
        pushed_stack_items=1,
        data_portion_length=24,
    )
    PUSH25 = Opcode(
        byte=0x78,
        pushed_stack_items=1,
        data_portion_length=25,
    )
    PUSH26 = Opcode(
        byte=0x79,
        pushed_stack_items=1,
        data_portion_length=26,
    )
    PUSH27 = Opcode(
        byte=0x7A,
        pushed_stack_items=1,
        data_portion_length=27,
    )
    PUSH28 = Opcode(
        byte=0x7B,
        pushed_stack_items=1,
        data_portion_length=28,
    )
    PUSH29 = Opcode(
        byte=0x7C,
        pushed_stack_items=1,
        data_portion_length=29,
    )
    PUSH30 = Opcode(
        byte=0x7D,
        pushed_stack_items=1,
        data_portion_length=30,
    )
    PUSH31 = Opcode(
        byte=0x7E,
        pushed_stack_items=1,
        data_portion_length=31,
    )
    PUSH32 = Opcode(
        byte=0x7F,
        pushed_stack_items=1,
        data_portion_length=32,
    )

    DUP1 = Opcode(
        byte=0x80,
        pushed_stack_items=1,
        min_stack_height=1,
    )
    DUP2 = Opcode(
        byte=0x81,
        pushed_stack_items=1,
        min_stack_height=2,
    )
    DUP3 = Opcode(
        byte=0x82,
        pushed_stack_items=1,
        min_stack_height=3,
    )
    DUP4 = Opcode(
        byte=0x83,
        pushed_stack_items=1,
        min_stack_height=4,
    )
    DUP5 = Opcode(
        byte=0x84,
        pushed_stack_items=1,
        min_stack_height=5,
    )
    DUP6 = Opcode(
        byte=0x85,
        pushed_stack_items=1,
        min_stack_height=6,
    )
    DUP7 = Opcode(
        byte=0x86,
        pushed_stack_items=1,
        min_stack_height=7,
    )
    DUP8 = Opcode(
        byte=0x87,
        pushed_stack_items=1,
        min_stack_height=8,
    )
    DUP9 = Opcode(
        byte=0x88,
        pushed_stack_items=1,
        min_stack_height=9,
    )
    DUP10 = Opcode(
        byte=0x89,
        pushed_stack_items=1,
        min_stack_height=10,
    )
    DUP11 = Opcode(
        byte=0x8A,
        pushed_stack_items=1,
        min_stack_height=11,
    )
    DUP12 = Opcode(
        byte=0x8B,
        pushed_stack_items=1,
        min_stack_height=12,
    )
    DUP13 = Opcode(
        byte=0x8C,
        pushed_stack_items=1,
        min_stack_height=13,
    )
    DUP14 = Opcode(
        byte=0x8D,
        pushed_stack_items=1,
        min_stack_height=14,
    )
    DUP15 = Opcode(
        byte=0x8E,
        pushed_stack_items=1,
        min_stack_height=15,
    )
    DUP16 = Opcode(
        byte=0x8F,
        pushed_stack_items=1,
        min_stack_height=16,
    )

    SWAP1 = Opcode(
        byte=0x90,
        min_stack_height=2,
    )
    SWAP2 = Opcode(
        byte=0x91,
        min_stack_height=3,
    )
    SWAP3 = Opcode(
        byte=0x92,
        min_stack_height=4,
    )
    SWAP4 = Opcode(
        byte=0x93,
        min_stack_height=5,
    )
    SWAP5 = Opcode(
        byte=0x94,
        min_stack_height=6,
    )
    SWAP6 = Opcode(
        byte=0x95,
        min_stack_height=7,
    )
    SWAP7 = Opcode(
        byte=0x96,
        min_stack_height=8,
    )
    SWAP8 = Opcode(
        byte=0x97,
        min_stack_height=9,
    )
    SWAP9 = Opcode(
        byte=0x98,
        min_stack_height=10,
    )
    SWAP10 = Opcode(
        byte=0x99,
        min_stack_height=11,
    )
    SWAP11 = Opcode(
        byte=0x9A,
        min_stack_height=12,
    )
    SWAP12 = Opcode(
        byte=0x9B,
        min_stack_height=13,
    )
    SWAP13 = Opcode(
        byte=0x9C,
        min_stack_height=14,
    )
    SWAP14 = Opcode(
        byte=0x9D,
        min_stack_height=15,
    )
    SWAP15 = Opcode(
        byte=0x9E,
        min_stack_height=16,
    )
    SWAP16 = Opcode(
        byte=0x9F,
        min_stack_height=17,
    )

    LOG0 = Opcode(
        byte=0xA0,
        popped_stack_items=2,
    )
    LOG1 = Opcode(
        byte=0xA1,
        popped_stack_items=3,
    )
    LOG2 = Opcode(
        byte=0xA2,
        popped_stack_items=4,
    )
    LOG3 = Opcode(
        byte=0xA3,
        popped_stack_items=5,
    )
    LOG4 = Opcode(
        byte=0xA4,
        popped_stack_items=6,
    )

    TLOAD = Opcode(
        byte=0xB3,
        popped_stack_items=1,
        pushed_stack_items=1,
    )
    TSTORE = Opcode(
        byte=0xB4,
        popped_stack_items=2,
    )

    CREATE = Opcode(
        byte=0xF0,
        popped_stack_items=3,
        pushed_stack_items=1,
    )
    CALL = Opcode(
        byte=0xF1,
        popped_stack_items=7,
        pushed_stack_items=1,
    )
    CALLCODE = Opcode(
        byte=0xF2,
        popped_stack_items=7,
        pushed_stack_items=1,
    )
    RETURN = Opcode(
        byte=0xF3,
        popped_stack_items=2,
    )
    DELEGATECALL = Opcode(
        byte=0xF4,
        popped_stack_items=6,
        pushed_stack_items=1,
    )
    CREATE2 = Opcode(
        byte=0xF5,
        popped_stack_items=4,
        pushed_stack_items=1,
    )

    STATICCALL = Opcode(
        byte=0xFA,
        popped_stack_items=6,
        pushed_stack_items=1,
    )

    REVERT = Opcode(
        byte=0xFD,
        popped_stack_items=2,
    )

    INVALID = Opcode(
        byte=0xFE,
    )

    SELFDESTRUCT = Opcode(
        byte=0xFF,
        popped_stack_items=1,
    )


# Helper functions
def relative_jump(relative_offset: int, conditional: bool = False) -> bytes:
    relative_offset_bytes = relative_offset.to_bytes(
        length=2, byteorder="big", signed=True
    )
    if conditional:
        return OPCODES.RJUMPI.byte + relative_offset_bytes
    return OPCODES.RJUMP.byte + relative_offset_bytes


ALL_VALID_CONTAINERS: List[Code | Container] = [
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
        ],
        name="single_code_section",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
            Section(
                kind=SectionKind.DATA,
                data="0x00",
            ),
        ],
        name="single_code_single_data_section",
    ),
]

# Source: EIP-3540
ALL_INVALID_CONTAINERS: List[Code | Container] = [
    Code(
        bytecode=bytes.fromhex("EF"),
        name="incomplete_magic",
    ),
    Code(
        bytecode=bytes.fromhex("EF00"),
        name="no_version",
    ),
    Container(
        custom_magic=0x01,
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
        ],
        name="invalid_magic_01",
    ),
    Container(
        custom_magic=0xFF,
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
        ],
        name="invalid_magic_ff",
    ),
    Container(
        custom_version=0x00,
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
        ],
        name="invalid_version_zero",
    ),
    Container(
        custom_version=LATEST_EOF_VERSION + 1,
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
        ],
        name="invalid_version_low",
    ),
    Container(
        custom_version=0xFF,
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
        ],
        name="invalid_version_high",
    ),
    Code(
        bytecode=bytes.fromhex("EF0001"),
        name="no_version",
    ),
    Container(
        sections=[],
        name="no_sections",
    ),
    Code(
        bytecode=bytes.fromhex("EF000101"),
        name="no_code_section_size",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.DATA,
                data="0x00",
            ),
        ],
        name="no_code_section",
    ),
    Code(
        bytecode=bytes.fromhex("EF00010100"),
        name="code_section_size_incomplete",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x",
                custom_size=3,
            ),
        ],
        custom_terminator=bytes(),
        name="no_section_terminator_1",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x600000",
            ),
        ],
        custom_terminator=bytes(),
        name="no_section_terminator_2",
    ),
    Container(
        sections=[
            Section(
                custom_size=0x01,
                kind=SectionKind.CODE,
                data="0x",
            ),
        ],
        name="no_code_section_contents",
    ),
    Container(
        sections=[
            Section(
                custom_size=0x02,
                kind=SectionKind.CODE,
                data="0x00",
            ),
        ],
        name="incomplete_code_section_contents",
    ),
    Container(
        sections=[
            Section(
                custom_size=0x02,
                kind=SectionKind.CODE,
                data="0x00",
            ),
        ],
        name="incomplete_code_section_contents",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x600000",
            ),
        ],
        extra=bytes.fromhex("deadbeef"),
        name="trailing_bytes_after_code_section",
    ),
    Container(  # Breaks with EIP-4750
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
        name="code_sections_above_1024",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x",
            ),
        ],
        name="empty_code_section",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x",
            ),
            Section(
                kind=SectionKind.DATA,
                data="0xDEADBEEF",
            ),
        ],
        name="empty_code_section_with_non_empty_data",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.DATA,
                data="0xDEADBEEF",
            ),
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
        ],
        name="data_section_preceding_code_section",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.DATA,
                data="0xDEADBEEF",
            ),
        ],
        name="data_section_without_code_section",
    ),
    Code(
        bytecode=bytes.fromhex("EF000101000202"),
        name="no_data_section_size",
    ),
    Code(
        bytecode=bytes.fromhex("EF00010100020200"),
        name="data_section_size_incomplete",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x020004",
            ),
        ],
        custom_terminator=bytes(),
        name="no_section_terminator_3",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x600000",
            ),
            Section(
                kind=SectionKind.DATA,
                data="0xAABBCCDD",
            ),
        ],
        custom_terminator=bytes(),
        name="no_section_terminator_4",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x600000",
            ),
            Section(
                kind=SectionKind.DATA,
                data="",
                custom_size=1,
            ),
        ],
        name="no_data_section_contents",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x600000",
            ),
            Section(
                kind=SectionKind.DATA,
                data="0xAABBCC",
                custom_size=4,
            ),
        ],
        name="data_section_contents_incomplete",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x600000",
            ),
            Section(
                kind=SectionKind.DATA,
                data="0xAABBCCDD",
            ),
        ],
        extra=bytes.fromhex("ee"),
        name="trailing_bytes_after_data_section",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x600000",
            ),
            Section(
                kind=SectionKind.DATA,
                data="0xAABBCC",
            ),
            Section(
                kind=SectionKind.DATA,
                data="0xAABBCC",
            ),
        ],
        name="multiple_data_sections",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
            Section(
                kind=SectionKind.DATA,
                data="0xAA",
            ),
            Section(
                kind=SectionKind.DATA,
                data="0xAA",
            ),
        ],
        name="multiple_code_and_data_sections_1",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
            Section(
                kind=SectionKind.DATA,
                data="0xAA",
            ),
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
            Section(
                kind=SectionKind.DATA,
                data="0xAA",
            ),
        ],
        name="multiple_code_and_data_sections_2",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
            Section(
                kind=SectionKind.DATA,
                data="0x",
            ),
        ],
        name="empty_data_section",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
            Section(
                kind=VERSION_MAX_SECTION_KIND + 1,
                data="0x01",
            ),
        ],
        name="unknown_section_1",
    ),
    Container(
        sections=[
            Section(
                kind=VERSION_MAX_SECTION_KIND + 1,
                data="0x01",
            ),
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
        ],
        name="unknown_section_2",
    ),
    Container(
        sections=[
            Section(
                kind=SectionKind.CODE,
                data="0x00",
            ),
            Section(
                kind=VERSION_MAX_SECTION_KIND + 1,
                data="0x",
            ),
        ],
        name="empty_unknown_section_2",
    ),
]

if EIP_CODE_VALIDATION in V1_EOF_EIPS:
    VALID_TERMINATING_OPCODES = [
        OPCODES.STOP,
        OPCODES.RETURN,
        OPCODES.REVERT,
        OPCODES.INVALID,
        OPCODES.SELFDESTRUCT,
    ]

    if EIP_EOF_FUNCTIONS in V1_EOF_EIPS:
        VALID_TERMINATING_OPCODES.append(OPCODES.RETF)

    for valid_opcode in VALID_TERMINATING_OPCODES:
        test_bytecode = bytes()
        if valid_opcode.min_stack_height > 0:
            # We need to push some items onto the stack so the code is valid
            # even with stack validation
            for i in range(valid_opcode.min_stack_height):
                test_bytecode += OPCODES.ORIGIN.byte
        test_bytecode += valid_opcode.byte
        ALL_VALID_CONTAINERS.append(
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data=test_bytecode,
                    ),
                    Section(
                        kind=SectionKind.DATA,
                        data="0x00",
                    ),
                ],
                name=f"valid_terminating_opcode_{valid_opcode.name.lower()}",
            ),
        )

    # Create a list of all opcodes that are not valid terminating opcodes
    INVALID_TERMINATING_OPCODES = [
        bytes([i])
        for i in range(256)
        if i not in [x.byte_int for x in VALID_TERMINATING_OPCODES]
    ]
    # Create containers where each invalid terminating opcode is located at the
    # end of the bytecode
    for invalid_opcode in INVALID_TERMINATING_OPCODES:
        ALL_INVALID_CONTAINERS.append(
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data=invalid_opcode,
                    ),
                    Section(
                        kind=SectionKind.DATA,
                        data="0x00",
                    ),
                ],
                name=f"invalid_terminating_opcode_0x{invalid_opcode.hex()}",
            ),
        )

    # Create a list of all invalid opcodes not assigned on EOF_V1
    INVALID_OPCODES = [
        bytes([i])
        for i in range(256)
        if i not in [x.byte_int for x in OPCODES]
    ]
    # Create containers containing a valid terminating opcode, but the
    # invalid opcode somewhere in the bytecode
    for invalid_opcode in INVALID_OPCODES:
        ALL_INVALID_CONTAINERS.append(
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data=invalid_opcode + OPCODES.STOP.byte,
                    ),
                    Section(
                        kind=SectionKind.DATA,
                        data="0x00",
                    ),
                ],
                name=f"invalid_terminating_opcode_0x{invalid_opcode.hex()}",
            ),
        )

    # Create a list of all valid opcodes that require data portion immediately
    # after
    VALID_DATA_PORTION_OPCODES = [
        op for op in OPCODES if op.data_portion_length > 0
    ]
    # Create an invalid EOF container where the data portion of a valid opcode
    # is truncated or terminates the bytecode
    for data_portion_opcode in VALID_DATA_PORTION_OPCODES:
        # No data portion
        ALL_INVALID_CONTAINERS.append(
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data=data_portion_opcode.byte,
                    ),
                    Section(
                        kind=SectionKind.DATA,
                        data="0x00",
                    ),
                ],
                name=f"valid_truncated_opcode_{data_portion_opcode.name}_"
                + "no_data",
            ),
        )
        if data_portion_opcode.data_portion_length > 1:
            # Single byte as data portion
            ALL_INVALID_CONTAINERS.append(
                Container(
                    sections=[
                        Section(
                            kind=SectionKind.CODE,
                            data=data_portion_opcode.byte + OPCODES.STOP.byte,
                        ),
                        Section(
                            kind=SectionKind.DATA,
                            data="0x00",
                        ),
                    ],
                    name=f"valid_truncated_opcode_{data_portion_opcode.name}_"
                    + "one_byte",
                ),
            )
        # Data portion complete but terminates the bytecode
        ALL_INVALID_CONTAINERS.append(
            Container(
                sections=[
                    Section(
                        kind=SectionKind.CODE,
                        data=data_portion_opcode.byte
                        + (
                            OPCODES.STOP.byte
                            * data_portion_opcode.data_portion_length
                        ),
                    ),
                    Section(
                        kind=SectionKind.DATA,
                        data="0x00",
                    ),
                ],
                name=f"valid_truncated_opcode_{data_portion_opcode.name}_"
                + "terminating",
            ),
        )

    if EIP_STATIC_RELATIVE_JUMPS in V1_EOF_EIPS:

        valid_codes: List[Tuple[bytes, str]] = [
            (
                relative_jump(0) + OPCODES.STOP.byte,
                "zero_relative_jump",
            ),
            (
                relative_jump(-3) + OPCODES.STOP.byte,
                "minus_three_relative_jump",
            ),
            (
                relative_jump(1)
                + OPCODES.STOP.byte
                + OPCODES.JUMPDEST.byte
                + OPCODES.STOP.byte,
                "one_relative_jump_to_jumpdest",
            ),
            (
                relative_jump(1) + OPCODES.STOP.byte + OPCODES.STOP.byte,
                "one_relative_jump_to_stop",
            ),
        ]

        invalid_codes: List[Tuple[bytes, str]] = [
            (
                relative_jump(-1) + OPCODES.STOP.byte,
                "minus_one_relative_jump",
            ),
            (
                relative_jump(-2) + OPCODES.STOP.byte,
                "minus_two_relative_jump",
            ),
            (
                relative_jump(1)
                + OPCODES.PUSH0.byte
                + OPCODES.STOP.byte
                + OPCODES.STOP.byte,
                "one_relative_jump_to_push_data",
            ),
            (
                relative_jump(1) + OPCODES.STOP.byte,
                "one_relative_jump_outside_of_code",
            ),
            (
                relative_jump(-4) + OPCODES.STOP.byte,
                "minus_4_relative_jump_outside_of_code",
            ),
        ]

        for valid_code in valid_codes:
            ALL_VALID_CONTAINERS.append(
                Container(
                    sections=[
                        Section(
                            kind=SectionKind.CODE,
                            data=valid_code[0],
                        ),
                        Section(
                            kind=SectionKind.DATA,
                            data="0x00",
                        ),
                    ],
                    name=f"valid_rjump_{valid_code[1]}",
                ),
            )

        for invalid_code in invalid_codes:
            ALL_INVALID_CONTAINERS.append(
                Container(
                    sections=[
                        Section(
                            kind=SectionKind.CODE,
                            data=invalid_code[0],
                        ),
                        Section(
                            kind=SectionKind.DATA,
                            data="0x00",
                        ),
                    ],
                    name=f"valid_rjump_{invalid_code[1]}",
                ),
            )

        if EIP_EOF_STACK_VALIDATION in V1_EOF_EIPS:
            # TODO: Invalid due to stack underflow on relative jump
            pass
else:
    pass

# TODO: Add test case for relative jumps on legacy code


@test_from(EOF_FORK_NAME)
def test_legacy_initcode_valid_eof_v1_contract(_):
    """
    Test creating various types of valid EOF V1 contracts using legacy
    initcode and a contract creating transaction.
    """
    created_contract_address = "0x6295ee1b4f6dd65047762f924ecd367c17eabf8f"

    env = Environment()

    pre = {
        TestAddress: Account(balance=1000000000000000000000, nonce=0),
    }

    post = {created_contract_address: Account()}
    tx = Transaction(
        nonce=0,
        to=None,
        gas_limit=100000000,
        gas_price=10,
        protected=False,
    )

    for container in ALL_VALID_CONTAINERS:

        initcode = generate_initcode(container)
        tx.data = initcode
        post[created_contract_address].code = container
        yield StateTest(
            env=env, pre=pre, post=post, txs=[tx], name=container.name
        )


@test_from(EOF_FORK_NAME)
def test_legacy_initcode_invalid_eof_v1_contract_tx(_):
    """
    Test creating various types of invalid EOF V1 contracts using legacy
    initcode and a contract creating transaction.
    """
    created_contract_address = "0x6295ee1b4f6dd65047762f924ecd367c17eabf8f"

    env = Environment()

    pre = {
        TestAddress: Account(balance=1000000000000000000000, nonce=0),
    }

    post = {
        created_contract_address: Account.NONEXISTENT,
    }

    tx = Transaction(
        nonce=0,
        to=None,
        gas_limit=100000000,
        gas_price=10,
        protected=False,
    )

    for container in ALL_INVALID_CONTAINERS:
        initcode = generate_initcode(container)
        tx.data = initcode
        print("filling test for "+container)
        yield StateTest(
            env=env, pre=pre, post=post, txs=[tx], name=container.name
        )


@test_from(EOF_FORK_NAME)
def test_legacy_initcode_invalid_eof_v1_contract_create(_):
    """
    Test creating various types of invalid EOF V1 contracts using legacy
    initcode and the CREATE opcode.
    """
    created_contract_address = "0x86132f9bd4d7b5149b5ba325154a9ba997a5109b"

    env = Environment()

    create_initcode_from_calldata = Yul(
        """
        {
            calldatacopy(0, 0, calldatasize())
            let result := create(0, 0, calldatasize())
            sstore(result, 1)
        }
        """
    )
    pre = {
        TestAddress: Account(
            balance=1000000000000000000000,
            nonce=0,
        ),
        to_address(0x100): Account(
            code=create_initcode_from_calldata,
        ),
    }

    post = {
        to_address(0x100): Account(
            storage={
                0: 1,
            }
        ),
        created_contract_address: Account.NONEXISTENT,
    }

    tx = Transaction(
        nonce=0,
        to=to_address(0x100),
        gas_limit=100000000,
        gas_price=10,
        protected=False,
    )

    for container in ALL_INVALID_CONTAINERS:
        initcode = generate_initcode(container)
        tx.data = initcode
        yield StateTest(
            env=env, pre=pre, post=post, txs=[tx], name=container.name
        )
