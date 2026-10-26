// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// H6: what happens to value that arrives outside the accounting paths.
import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ClausDealEscrow} from "../src/ClausDealEscrow.sol";
import {ClausTokenDealEscrow} from "../src/ClausTokenDealEscrow.sol";

contract StrayToken is ERC20 {
    constructor() ERC20("Stray", "STR") {}
    function mint(address to, uint256 n) external { _mint(to, n); }
}

contract ArgusProbeStrayFunds is Test {
    ClausDealEscrow eth;
    ClausTokenDealEscrow token;
    StrayToken stray;
    address buyer = address(0xA11CE);
    address worker = address(0xB0B);
    uint256 signerKey = 0x12345;
    bytes32 project = keccak256("owned-project");
    bytes32 terms = keccak256("fixed agreement");

    function setUp() public {
        eth = new ClausDealEscrow(address(this), vm.addr(signerKey), 1 ether, 5 ether);
        eth.setFundingEnabled(true);
        vm.deal(buyer, 20 ether);
        stray = new StrayToken();
        token = new ClausTokenDealEscrow(address(stray), address(this), vm.addr(signerKey), 1 ether, 5 ether);
        token.setFundingEnabled(true);
        stray.mint(buyer, 1000 ether);
        vm.prank(buyer);
        stray.approve(address(token), 20 ether);
    }

    function ethDeal(uint256 salt) internal returns (bytes32 id) {
        vm.prank(buyer);
        id = eth.createDeal{value: 1 ether}(bytes32(salt), project, terms, worker, uint64(block.timestamp + 2 days));
        vm.startPrank(worker);
        eth.claim(id);
        eth.deliver(id, keccak256("output"));
        vm.stopPrank();
    }

    /// A bare transfer to the ETH escrow fails: no receive(), no fallback().
    function test_H6a_bareEthTransferIsRejected() public {
        (bool ok,) = address(eth).call{value: 1 ether}("");
        assertEq(ok, false, "bare transfer fails");
        assertEq(address(eth).balance, 0, "nothing landed");
    }

    /// Forced ETH lands, appears in no accounting total, and outlives a full lifecycle.
    function test_H6b_forcedEthIsUnaccountedAndStranded() public {
        vm.deal(address(eth), 1 ether);
        bytes32 id = ethDeal(1);
        vm.prank(buyer);
        eth.accept(id);
        vm.prank(worker);
        eth.withdraw(1 ether, payable(worker));
        assertEq(worker.balance, 1 ether, "worker paid exactly the deal");
        assertEq(eth.totalLocked(), 0);
        assertEq(eth.totalCredits(), 0);
        assertEq(address(eth).balance, 1 ether, "forced ETH still stranded");
        console.log("stranded wei after a complete lifecycle", address(eth).balance);
    }

    /// Tokens need no receive(): a direct transfer lands and is equally stranded.
    function test_H6c_directTokenTransferIsUnaccountedAndStranded() public {
        vm.prank(buyer);
        stray.transfer(address(token), 500 ether);
        vm.prank(buyer);
        bytes32 id = token.createDeal(bytes32(uint256(1)), project, terms, worker, 1 ether, uint64(block.timestamp + 2 days));
        vm.startPrank(worker);
        token.claim(id);
        token.deliver(id, keccak256("output"));
        vm.stopPrank();
        vm.prank(buyer);
        token.accept(id);
        vm.prank(worker);
        token.withdraw(1 ether, payable(worker));
        assertEq(stray.balanceOf(worker), 1 ether, "worker paid exactly the deal");
        assertEq(token.totalLocked(), 0);
        assertEq(token.totalCredits(), 0);
        assertEq(stray.balanceOf(address(token)), 500 ether, "donated tokens still stranded");
        console.log("stranded tokens after a complete lifecycle", stray.balanceOf(address(token)) / 1 ether);
    }
}
