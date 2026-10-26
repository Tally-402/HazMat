// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// Same-block contention for AG-001. Earlier probes always put a warp between the
// competing transactions; here both land in one block, in both orders.
import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ClausDealEscrow} from "../src/ClausDealEscrow.sol";

contract ArgusProbeSameBlock is Test {
    ClausDealEscrow escrow;
    address buyer = address(0xA11CE);
    address worker = address(0xB0B);
    address stranger = address(0xDEAD);
    uint256 signerKey = 0x12345;
    bytes32 project = keccak256("owned-project");
    bytes32 terms = keccak256("fixed agreement");
    uint256 constant PRICE = 0.1 ether;
    uint32 constant RUNS = 3;
    bytes32 constant SALT = keccak256("plan-salt");

    function setUp() public {
        escrow = new ClausDealEscrow(address(this), vm.addr(signerKey), 1 ether, 5 ether);
        escrow.setFundingEnabled(true);
        vm.deal(buyer, 20 ether);
    }

    function disputedDealPastTheWindow() internal returns (bytes32 deal) {
        vm.prank(buyer);
        bytes32 planId = escrow.createPlan{value: PRICE * RUNS}(SALT, project, terms, worker, PRICE, RUNS,
            60, 1 hours, uint64(block.timestamp + 5 days));
        vm.prank(buyer);
        deal = escrow.runPlan(planId, 0);
        vm.startPrank(worker);
        escrow.claim(deal);
        escrow.deliver(deal, keccak256("delivered"));
        vm.stopPrank();
        vm.prank(buyer);
        escrow.dispute(deal, keccak256("reason"));
        vm.warp(uint256(escrow.getDeal(deal).resolutionDue) + 1);
    }

    /// Both orders inside one block, no warp between them.
    function test_AB1_oneBlock_strangerTimeoutFirstDeniesTheBuyer() public {
        bytes32 deal = disputedDealPastTheWindow();
        uint256 ts = block.timestamp;
        uint256 bn = block.number;
        vm.prank(stranger);
        escrow.settleExpired(deal);
        assertEq(block.timestamp, ts, "same timestamp");
        assertEq(block.number, bn, "same block");
        assertEq(escrow.credits(worker), 0, "worker paid nothing");
        vm.prank(buyer);
        vm.expectRevert(ClausDealEscrow.WrongState.selector);
        escrow.accept(deal);
    }

    function test_AB2_oneBlock_buyerAcceptFirstPaysInFull() public {
        bytes32 deal = disputedDealPastTheWindow();
        uint256 ts = block.timestamp;
        vm.prank(buyer);
        escrow.accept(deal);
        assertEq(block.timestamp, ts);
        assertEq(escrow.credits(worker), PRICE, "worker paid in full");
        vm.prank(stranger);
        vm.expectRevert(ClausDealEscrow.WrongState.selector);
        escrow.settleExpired(deal);
        assertEq(escrow.credits(worker), PRICE, "outcome fixed by ordering alone");
    }

    /// The arbiter's late signature is dead in the same block as the timeout.
    function test_AB3_oneBlock_lateArbiterSignatureLosesToo() public {
        bytes32 deal = disputedDealPastTheWindow();
        bytes32 evidence = keccak256("evidence");
        bytes memory sig = resolution(deal, PRICE, evidence, uint64(block.timestamp + 2 days));
        vm.prank(stranger);
        escrow.settleExpired(deal);
        vm.expectRevert(ClausDealEscrow.WrongState.selector);
        escrow.resolve(deal, PRICE, evidence, uint64(block.timestamp + 2 days), sig);
    }

    /// At exactly resolutionDue the timeout and the signature never overlap, so
    /// the arbitrated path is exclusive and only `accept` is concurrent.
    function test_AB4_atTheBoundaryTimestampTheSignatureStillWins() public {
        vm.prank(buyer);
        bytes32 planId = escrow.createPlan{value: PRICE * RUNS}(SALT, project, terms, worker, PRICE, RUNS,
            60, 1 hours, uint64(block.timestamp + 5 days));
        vm.prank(buyer);
        bytes32 deal = escrow.runPlan(planId, 0);
        vm.startPrank(worker);
        escrow.claim(deal);
        escrow.deliver(deal, keccak256("delivered"));
        vm.stopPrank();
        vm.prank(buyer);
        escrow.dispute(deal, keccak256("reason"));
        vm.warp(uint256(escrow.getDeal(deal).resolutionDue));   // exactly at the deadline
        vm.prank(stranger);
        vm.expectRevert(ClausDealEscrow.WrongState.selector);
        escrow.settleExpired(deal);
        bytes32 evidence = keccak256("evidence");
        uint64 expiry = uint64(block.timestamp + 1 days);
        escrow.resolve(deal, PRICE / 2, evidence, expiry, resolution(deal, PRICE / 2, evidence, expiry));
        assertEq(escrow.credits(worker), PRICE / 2, "the signature still works at the boundary");
    }

    function resolution(bytes32 deal, uint256 amount, bytes32 evidence, uint64 expiry)
        internal view returns (bytes memory)
    {
        bytes32 domain = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("ClausDealEscrow"), keccak256("1"), block.chainid, address(escrow)));
        bytes32 hash = keccak256(abi.encodePacked(hex"1901", domain,
            keccak256(abi.encode(escrow.RESOLUTION_TYPEHASH(), deal, amount, evidence, expiry))));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, hash);
        return abi.encodePacked(r, s, v);
    }
}
