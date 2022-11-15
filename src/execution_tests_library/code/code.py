"""
Code object that is an interface to different
assembler/compiler backends.
"""
from dataclasses import dataclass
from re import sub
from typing import Optional, Union


@dataclass(kw_only=True)
class Code:
    """
    Generic code object.
    """

    bytecode: Optional[bytes] = None
    """
    bytes array that represents the bytecode of this object.
    """
    name: Optional[str] = None
    """
    Name used to described this code.
    Usually used to add extra information to a test case.
    """

    def assemble(self) -> bytes:
        """
        Transform the Code object into bytes.
        Normally will be overriden by the classes that inherit this class.
        """
        if self.bytecode is None:
            return bytes()
        else:
            return self.bytecode

    def __add__(self, other: Union[str, bytes, "Code"]) -> "Code":
        """
        Adds two code objects together, by converting both to bytes first.
        """
        return Code(bytecode=(code_to_bytes(self) + code_to_bytes(other)))

    def __radd__(self, other: Union[str, bytes, "Code"]) -> "Code":
        """
        Adds two code objects together, by converting both to bytes first.
        """
        return Code(bytecode=(code_to_bytes(other) + code_to_bytes(self)))


def code_to_bytes(code: str | bytes | Code) -> bytes:
    """
    Converts multiple types into bytecode.
    """
    if code is None:
        raise Exception("Cannot convert `None` code to bytes")

    if isinstance(code, Code):
        return code.assemble()

    if type(code) is bytes:
        return code

    if type(code) is str:
        # We can have a hex representation of bytecode with spaces for
        # readability
        code = sub(r"\s+", "", code)
        if code.startswith("0x"):
            return bytes.fromhex(code[2:])
        return bytes.fromhex(code)

    raise Exception("invalid type for `code`")


def code_to_hex(code: str | bytes | Code) -> str:
    """
    Converts multiple types into a bytecode hex string.
    """
    if code is None:
        raise Exception("Cannot convert `None` code to hex")

    if isinstance(code, Code):
        return "0x" + code.assemble().hex()

    if type(code) is bytes:
        return "0x" + code.hex()

    if type(code) is str:
        # We can have a hex representation of bytecode with spaces for
        # readability
        code = sub(r"\s+", "", code)
        if code.startswith("0x"):
            return code
        return "0x" + code

    raise Exception("invalid type for `code`")


def generate_initcode(code: str | bytes | Code) -> Code:
    """
    Generate legacy initcode that inits a contract with the specified code
    """
    code_bytes = code_to_bytes(code)

    initcode = bytearray()
    # PUSH2: length=<bytecode length>
    initcode.append(0x61)
    initcode += len(code_bytes).to_bytes(length=2, byteorder="big")
    # PUSH1: offset=0
    initcode.append(0x60)
    initcode.append(0x00)
    # DUP2
    initcode.append(0x81)
    # PUSH1: initcode_length=11 (constant)
    initcode.append(0x60)
    initcode.append(0x0B)
    # DUP3
    initcode.append(0x82)
    # CODECOPY: destinationOffset=0, offset=0, length
    initcode.append(0x39)
    # RETURN: offset=0, length
    initcode.append(0xF3)
    return Code(bytecode=bytes(initcode + code_bytes))
