"""
Test EIP-3651: Warm COINBASE
EIP: https://eips.ethereum.org/EIPS/eip-3651
Source tests: https://github.com/ethereum/tests/pull/1082
"""
from typing import Dict

from ethereum_test_tools import (
    Account,
    CodeGasMeasure,
    Environment,
    StateTest,
    TestAddress,
    Transaction,
    Yul,
    is_fork,
    test_from,
    to_address,
    to_hash,
)
from ethereum_test_tools.vm.opcode import Opcodes as Op


@test_from(fork="merged")
def test_warm_coinbase_call_out_of_gas(fork):
    """
    Test warm coinbase.
    """
    env = Environment(
        coinbase="0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
        difficulty=0x20000,
        gas_limit=10000000000,
        number=1,
        timestamp=1000,
    )

    caller_code = Yul(
        """
        {
           // Depending on the called contract here, the subcall will perform
           // another call/delegatecall/staticcall/callcode that will only
           // succeed if coinbase is considered warm by default
           // (post-Shanghai).
           let calladdr := calldataload(0)

           // Amount of gas required to make a call to a warm account.
           // Calling a cold account with this amount of gas results in
           // exception.
           let callgas := 100

           switch calladdr
           case 0x100 {
             // Extra: COINBASE + 6xPUSH1 + DUP6 + 2xPOP
             callgas := add(callgas, 27)
           }
           case 0x200 {
             // Extra: COINBASE + 6xPUSH1 + DUP6 + 2xPOP
             callgas := add(callgas, 27)
           }
           case 0x300 {
             // Extra: COINBASE + 5xPUSH1 + DUP6 + 2xPOP
             callgas := add(callgas, 24)
           }
           case 0x400 {
             // Extra: COINBASE + 5xPUSH1 + DUP6 + 2xPOP
             callgas := add(callgas, 24)
           }
           // Call and save result
           sstore(0, call(callgas, calladdr, 0, 0, 0, 0, 0))
        }
        """
    )

    call_code = Yul(
        """
        {
           let cb := coinbase()
           pop(call(0, cb, 0, 0, 0, 0, 0))
        }
        """
    )

    callcode_code = Yul(
        """
        {
           let cb := coinbase()
           pop(callcode(0, cb, 0, 0, 0, 0, 0))
        }
        """
    )

    delegatecall_code = Yul(
        """
        {
           let cb := coinbase()
           pop(delegatecall(0, cb, 0, 0, 0, 0))
        }
        """
    )

    staticcall_code = Yul(
        """
        {
           let cb := coinbase()
           pop(staticcall(0, cb, 0, 0, 0, 0))
        }
        """
    )

    pre = {
        TestAddress: Account(balance=1000000000000000000000),
        "0xcccccccccccccccccccccccccccccccccccccccc": Account(
            code=caller_code
        ),
        to_address(0x100): Account(code=call_code),
        to_address(0x200): Account(code=callcode_code),
        to_address(0x300): Account(code=delegatecall_code),
        to_address(0x400): Account(code=staticcall_code),
    }

    for i, data in enumerate(
        [to_hash(x) for x in range(0x100, 0x400 + 1, 0x100)]
    ):

        tx = Transaction(
            ty=0x0,
            data=data,
            chain_id=0x0,
            nonce=0,
            to="0xcccccccccccccccccccccccccccccccccccccccc",
            gas_limit=100000000,
            gas_price=10,
            protected=False,
        )

        post = {}

        if is_fork(fork=fork, which="shanghai"):
            post["0xcccccccccccccccccccccccccccccccccccccccc"] = Account(
                storage={
                    # On shanghai and beyond, calls with only 100 gas to
                    # coinbase will succeed.
                    0: 1,
                }
            )
        else:
            post["0xcccccccccccccccccccccccccccccccccccccccc"] = Account(
                storage={
                    # Before shanghai, calls with only 100 gas to
                    # coinbase will fail.
                    0: 0,
                }
            )

        yield StateTest(env=env, pre=pre, post=post, txs=[tx])


@test_from(fork="merged")
def test_warm_coinbase_gas_usage(fork):
    """
    Test gas usage of different opcodes assuming warm coinbase.
    """
    env = Environment(
        coinbase="0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
        difficulty=0x20000,
        gas_limit=10000000000,
        number=1,
        timestamp=1000,
    )

    # List of opcodes that are affected by
    gas_measured_opcodes: Dict[str, CodeGasMeasure] = {
        "EXTCODESIZE": CodeGasMeasure(
            code=Op.COINBASE + Op.EXTCODESIZE,
            overhead_cost=2,
            extra_stack_items=1,
        ),
        "EXTCODECOPY": CodeGasMeasure(
            code=Op.PUSH1(0x00) * 3 + Op.COINBASE + Op.EXTCODECOPY,
            overhead_cost=2 + 3 + 3 + 3,
        ),
        "EXTCODEHASH": CodeGasMeasure(
            code=Op.COINBASE + Op.EXTCODEHASH,
            overhead_cost=2,
            extra_stack_items=1,
        ),
        "BALANCE": CodeGasMeasure(
            code=Op.COINBASE + Op.BALANCE,
            overhead_cost=2,
            extra_stack_items=1,
        ),
        "CALL": CodeGasMeasure(
            code=Op.PUSH1(0x00) * 5 + Op.COINBASE + Op.PUSH1(0xFF) + Op.CALL,
            overhead_cost=3 + 2 + 3 + 3 + 3 + 3 + 3,
            extra_stack_items=1,
        ),
        "CALLCODE": CodeGasMeasure(
            code=Op.PUSH1(0x00) * 5
            + Op.COINBASE
            + Op.PUSH1(0xFF)
            + Op.CALLCODE,
            overhead_cost=3 + 2 + 3 + 3 + 3 + 3 + 3,
            extra_stack_items=1,
        ),
        "DELEGATECALL": CodeGasMeasure(
            code=Op.PUSH1(0x00) * 4
            + Op.COINBASE
            + Op.PUSH1(0xFF)
            + Op.DELEGATECALL,
            overhead_cost=3 + 2 + 3 + 3 + 3 + 3,
            extra_stack_items=1,
        ),
        "STATICCALL": CodeGasMeasure(
            code=Op.PUSH1(0x00) * 4
            + Op.COINBASE
            + Op.PUSH1(0xFF)
            + Op.STATICCALL,
            overhead_cost=3 + 2 + 3 + 3 + 3 + 3,
            extra_stack_items=1,
        ),
    }

    for opcode in gas_measured_opcodes:
        measure_address = to_address(0x100)
        pre = {
            TestAddress: Account(balance=1000000000000000000000),
            measure_address: Account(
                code=gas_measured_opcodes[opcode],
            ),
        }

        if is_fork(fork, "shanghai"):
            expected_gas = 100  # Warm account access cost after EIP-3651
        else:
            expected_gas = 2600  # Cold account access cost before EIP-3651

        post = {
            measure_address: Account(
                storage={
                    0x00: expected_gas,
                }
            )
        }
        tx = Transaction(
            ty=0x0,
            chain_id=0x0,
            nonce=0,
            to=measure_address,
            gas_limit=100000000,
            gas_price=10,
            protected=False,
        )

        yield StateTest(
            env=env,
            pre=pre,
            post=post,
            txs=[tx],
            name="warm_coinbase_opcode_" + opcode.lower(),
        )
