// SPDX-License-Identifier: MIT
pragma solidity ^0.4.19;

// HZ-015: does a stipend payout really refuse a contract recipient?
//
// No forge-std, because the verified WETH9 source is solc 0.4.19 and a modern test
// library would force a second compiler into the same build. Cheatcodes are called
// through a hand-written interface, every call is made *by the recipient* so the
// recipient is msg.sender, and 0.4.19 has no two-argument require, so the checks are
// bare asserts and the test names carry the intent.
import "../src/WETH9.sol";

interface Vm {
    function deal(address, uint256) external;
    function prank(address) external;
}

contract EmptyFallback {
    function() payable public {}
}

contract CostlyFallback {
    uint256 public written;
    function() payable public { written = written + 1; }   // one sstore: far past 2300 gas
}

contract NoFallback {
    uint256 public x = 1;
}

contract WethStipend {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    WETH9 weth = new WETH9();

    function setUp() public {
        // the value forwarded into deposit() comes out of the caller's balance, and the
        // caller here is this test contract
        vm.deal(address(this), 10 ether);
    }

    // prank makes `who` the msg.sender of the next call the test makes, and a low-level
    // call from here is that call, so the recipient is the caller into WETH and a revert
    // still comes back as a bool (0.4 has no try/catch)
    function depositAs(address who) internal returns (bool) {
        vm.deal(who, 1 ether);          // with prank the value leaves the recipient's balance
        vm.prank(who);
        return address(weth).call.value(1 ether)(bytes4(keccak256("deposit()")));
    }

    function withdrawAs(address who) internal returns (bool) {
        vm.prank(who);
        return address(weth).call(bytes4(keccak256("withdraw(uint256)")), uint256(1 ether));
    }

    function wrapThenWithdraw(address who) internal returns (bool withdrew, bool wrapped) {
        wrapped = depositAs(who) && weth.balanceOf(who) == 1 ether;
        withdrew = withdrawAs(who);
    }

    function test_anEoaRecipientIsPaid() public {
        address eoa = address(0xE0A);
        bool withdrew;
        bool wrapped;
        (withdrew, wrapped) = wrapThenWithdraw(eoa);
        assert(wrapped);                      // the deposit wraps
        assert(withdrew);                     // an eoa is paid
        assert(eoa.balance == 1 ether);       // and actually receives the value
    }

    function test_aContractWithNoPayableFallbackReverts() public {
        NoFallback target = new NoFallback();
        bool withdrew;
        bool wrapped;
        (withdrew, wrapped) = wrapThenWithdraw(address(target));
        assert(wrapped);                      // the deposit wraps
        assert(!withdrew);                    // the payout reverts: no payable fallback
        assert(weth.balanceOf(address(target)) == 1 ether);   // so the wrapped balance stays put
    }

    function test_aFallbackThatWritesStorageReverts() public {
        CostlyFallback target = new CostlyFallback();
        bool withdrew;
        bool wrapped;
        (withdrew, wrapped) = wrapThenWithdraw(address(target));
        assert(wrapped);                      // the deposit wraps
        assert(!withdrew);                    // one sstore exhausts the 2300 gas stipend
        assert(target.written() == 0);        // and the write never lands
    }

    function test_anEmptyFallbackIsPaidWhichIsWhatProvesItIsTheStipend() public {
        EmptyFallback target = new EmptyFallback();
        bool withdrew;
        bool wrapped;
        (withdrew, wrapped) = wrapThenWithdraw(address(target));
        assert(wrapped);                      // the deposit wraps
        assert(withdrew);                     // contracts are not the problem; gas is
        assert(target.balance == 1 ether);    // and it receives the value
    }
}
