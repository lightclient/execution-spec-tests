"""
Test EOF
"""

from typing import List, Tuple

from ethereum_test_tools import (
    Account,
    Block,
    BlockchainTest,
    Initcode,
    TestAddress,
    Transaction,
    compute_create_address,
    test_from,
)
from ethereum_test_tools.vm.opcode import Opcodes as Op

EOF_FORK = "shanghai"

def make_eof(types: List[Tuple[int, int, int]], code: List[bytes], data: bytes = bytes()):
    out = bytearray([0xef, 0x00])
    out.append(0x01) # version

    out.append(0x01) # kind: type
    out.extend((len(types)*4).to_bytes(2, 'big'))

    out.append(0x02) # kind: code
    for c in code:
        out.extend(len(c).to_bytes(2, 'big'))

    out.append(0x03) # kind: data
    out.extend(len(data).to_bytes(2, 'big'))

    # type section
    for ty in types:
        out.extend(ty[0].to_bytes(1, 'big')) # inputs
        out.extend(ty[1].to_bytes(1, 'big')) # outputs
        out.extend(ty[2].to_bytes(2, 'big')) # max_stack_height

    # code sections
    for c in code:
        out.extend(c)

    # data section
    out.extend(data)

    return bytes(out)

@test_from(EOF_FORK)
def test_eof_invalid_container(_):
    pre = {TestAddress: Account(balance=1000000000000000000000)}

    container = make_eof([(0,0,0)], [Op.STOP])
    #  container[3] = 0x02 # set version to 2

    initcode = Initcode(
        deploy_code=container,
        name="max_size_ones_initcode",
    )

    tx = Transaction(
        to=None,
        nonce=0,
        gas_price=10,
        gas_limit=60000,
        data=initcode.assemble(),
    )

    blocks = [Block(txs=[tx])]

    created_contract_address = compute_create_address(TestAddress, 0)

    post = {
        TestAddress: Account(balance=999999999999999400000),
        created_contract_address: Account(balance=0),
    }

    yield BlockchainTest(pre=pre, post=post, blocks=blocks)
