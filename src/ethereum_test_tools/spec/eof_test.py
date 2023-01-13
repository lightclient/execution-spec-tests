"""
Test format for testing EOF parsing and validation.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

class EOFValidationError(str, Enum):
    UnexpectedEOF = "UnexpectedEOF"
    InvalidMagic = "InvalidMagic"
    InvaildVersion = "InvaildVersion"
    MissingTypeHeader = "MissingTypeHeader"
    InvalidTypeSize = "InvalidTypeSize"
    MissingCodeHeader = "MissingCodeHeader"
    InvalidCodeHeader = "InvalidCodeHeader"
    MissingDataHeader = "MissingDataHeader"
    MissingTerminator = "MissingTerminator"
    TooManyInputs = "TooManyInputs"
    TooManyOutputs = "TooManyOutputs"
    TooLargeMaxStackHeight = "TooLargeMaxStackHeight"
    InvalidSection0Type = "InvalidSection0Type"
    InvalidCodeSize = "InvalidCodeSize"
    InvalidContainerSize = "InvalidContainerSize"
    UndefinedInstruction = "UndefinedInstruction"
    TruncatedImmediate = "TruncatedImmediate"
    InvalidSectionArgument = "InvalidSectionArgument"
    InvalidJumpDest = "InvalidJumpDest"
    ConflictingStack = "ConflictingStack"
    InvalidBranchCount = "InvalidBranchCount"
    StackUnderflow = "StackUnderflow"
    StackOverflow = "StackOverflow"
    InvalidOutputs = "InvalidOutputs"
    InvalidMaxStackHeight = "InvalidMaxStackHeight"
    InvalidCodeTermination = "InvalidCodeTermination"
    UnreachableCode = "UnreachableCode"

@dataclass(kw_only=True)
class EOFValidationTest:
    """
    Represents an EOF test.
    """

    code: bytes
    error: Optional[EOFValidationError]
    name: str
