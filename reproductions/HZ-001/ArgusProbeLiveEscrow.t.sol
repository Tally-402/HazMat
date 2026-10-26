// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// AG-001 ported onto the LIVE twin: ClausTokenDealEscrow is deployed on mainnet
// and its published source is verified byte-identical. Parameters below are the
// live ones read from chain: maximumDeal 1e22, maximumPrincipal 1e23.
import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ClausTokenDealEscrow} from "../src/ClausTokenDealEscrow.sol";

contract LiveUnit is ERC20 {
    constructor() ERC20("Claus", "CLAUS") {}
    function mint(address to, uint256 n) external { _mint(to, n); }
}

contract ArgusProbeLiveEscrow is Test {
    ClausTokenDealEscrow escrow;
    LiveUnit token;
    address buyer = address(0xA11CE);
    address worker = address(0xB0B);
    address stranger = address(0xDEAD);
    uint256 signerKey = 0x12345;
    bytes32 project = keccak256("owned-project");
    bytes32 terms = keccak256("fixed agreement");
    uint256 constant PRICE = 10_000e18;      // live maximumDeal
    uint256 constant CAPACITY = 100_000e18;  // live maximumPrincipal

    function setUp() public {
        token = new LiveUnit();
        escrow = new ClausTokenDealEscrow(address(token), address(this), vm.addr(signerKey), PRICE, CAPACITY);
        escrow.setFundingEnabled(true);
        token.mint(buyer, CAPACITY);
        vm.prank(buyer);
        token.approve(address(escrow), CAPACITY);
    }

    function disputedDeal() internal returns (bytes32 id) {
        vm.prank(buyer);
        id = escrow.createDeal(keccak256("s"), project, terms, worker, PRICE, uint64(block.timestamp + 2 days));
        vm.startPrank(worker);
        escrow.claim(id);
        escrow.deliver(id, keccak256("output"));
        vm.stopPrank();
        vm.prank(buyer);
        escrow.dispute(id, keccak256("reason"));
        vm.warp(uint256(escrow.getDeal(id).resolutionDue) + 1);
    }

    /// Control: past the window the buyer's accept still pays the worker in full.
    function test_LIVE1_control_acceptAfterTheWindowPaysInFull() public {
        bytes32 id = disputedDeal();
        vm.prank(buyer);
        escrow.accept(id);
        assertEq(escrow.credits(worker), PRICE, "full price credited");
        assertLe(PRICE, escrow.maximumDeal(), "bound is the live deal ceiling");
    }

    /// A stranger's one transaction, zero capital, pays the worker nothing.
    function test_LIVE2_strangerTimeoutPaysZeroAndKillsTheBuyersAccept() public {
        bytes32 id = disputedDeal();
        uint256 gas = gasleft();
        vm.prank(stranger);
        escrow.settleExpired(id);
        uint256 used = gas - gasleft();
        assertEq(escrow.credits(worker), 0, "worker loses the whole price");
        vm.prank(buyer);
        vm.expectRevert(ClausTokenDealEscrow.WrongState.selector);
        escrow.accept(id);
        console.log("LIVE2 attacker gas", used, "victim loss units", PRICE / 1e18);
    }

    /// Same block, opposite order, opposite outcome.
    function test_LIVE3_sameBlock_orderDecides() public {
        bytes32 id = disputedDeal();
        uint256 ts = block.timestamp;
        vm.prank(buyer);
        escrow.accept(id);
        assertEq(block.timestamp, ts, "same block");
        assertEq(escrow.credits(worker), PRICE, "buyer first: full payment");
        vm.prank(stranger);
        vm.expectRevert(ClausTokenDealEscrow.WrongState.selector);
        escrow.settleExpired(id);
    }
}
