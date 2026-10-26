// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// W1: re-authorizing a live, unrevoked session id in place (generation + 1).
// Their suite only re-authorizes a fresh id after revocation.
import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ClausProjectWallet} from "../src/ClausProjectWallet.sol";

contract ArgusProbeWallet is Test {
    uint256 constant OWNER_KEY = 0xB0B;
    uint256 constant SESSION_KEY = 0xA11CE;
    bytes32 constant SESSION = keccak256("provider-payment-session");
    address constant RECIPIENT = address(0xBEEF);
    address constant STRANGER = address(0xF00D);
    ClausProjectWallet wallet;

    function setUp() public {
        vm.warp(1800000000);
        wallet = new ClausProjectWallet(vm.addr(OWNER_KEY));
        vm.deal(address(wallet), 10 ether);
    }

    function sig(uint256 key, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash);
        return abi.encodePacked(r, s, v);
    }

    function session(uint64 generation) internal view returns (ClausProjectWallet.SessionAuthorization memory) {
        return ClausProjectWallet.SessionAuthorization(SESSION, vm.addr(SESSION_KEY), address(0), RECIPIENT,
            1 ether, 2 ether, uint64(block.timestamp), uint64(block.timestamp + 1 days), generation,
            uint64(block.timestamp + 1 hours));
    }

    function payment(uint64 generation, uint256 nonce) internal view returns (ClausProjectWallet.Payment memory) {
        return ClausProjectWallet.Payment(SESSION, generation, address(0), RECIPIENT, 1 ether,
            keccak256(abi.encode(nonce)), nonce, uint64(block.timestamp + 1 hours));
    }

    function grant(uint64 generation) internal {
        ClausProjectWallet.SessionAuthorization memory s = session(generation);
        wallet.authorizeSession(s, sig(OWNER_KEY, wallet.sessionDigest(s)));
    }

    function spentOf() internal view returns (uint128 v) { (,,,,, v,,,) = wallet.sessions(SESSION); }
    function totalOf() internal view returns (uint128 v) { (,,,, v,,,,) = wallet.sessions(SESSION); }
    function generationOf() internal view returns (uint64 v) { (,,,,,,,, v) = wallet.sessions(SESSION); }

    function pay(ClausProjectWallet.Payment memory p) internal {
        wallet.pay(p, sig(SESSION_KEY, wallet.paymentDigest(p)));
    }

    /// Control: with no renewal, the session's total is a hard stop.
    function test_W1_control_totalIsAHardStopWithoutRenewal() public {
        grant(1);
        pay(payment(1, 1));
        pay(payment(1, 2));
        assertEq(spentOf(), 2 ether);
        ClausProjectWallet.Payment memory third = payment(1, 3);
        bytes memory signature = sig(SESSION_KEY, wallet.paymentDigest(third));
        vm.expectRevert(ClausProjectWallet.InvalidPayment.selector);
        wallet.pay(third, signature);
    }

    /// An in-place renewal is accepted on a live id and silently zeroes `spent`.
    function test_W1a_inPlaceRenewalResetsTheSpendCapUnderTheSameId() public {
        grant(1);
        pay(payment(1, 1));
        pay(payment(1, 2));
        assertEq(RECIPIENT.balance, 2 ether, "cap of 2 ether consumed");
        // Same id, generation 2, same terms and recipient, owner-signed.
        ClausProjectWallet.SessionAuthorization memory renewal = session(2);
        bytes memory signature = sig(OWNER_KEY, wallet.sessionDigest(renewal));
        vm.prank(STRANGER);
        wallet.authorizeSession(renewal, signature);
        assertEq(generationOf(), 2, "generation advanced in place");
        assertEq(spentOf(), 0, "spend counter reset");
        assertEq(totalOf(), 2 ether, "budget still reads 2 ether");
        pay(payment(2, 3));
        assertEq(RECIPIENT.balance, 3 ether, "3 ether paid by a session whose total reads 2 ether");
    }

    /// A previously signed payment dies the moment a stranger applies the renewal.
    function test_W1b_renewalKillsPaymentsSignedUnderTheOldGeneration() public {
        grant(1);
        ClausProjectWallet.Payment memory legacy = payment(1, 1);
        bytes memory legacySignature = sig(SESSION_KEY, wallet.paymentDigest(legacy));
        ClausProjectWallet.SessionAuthorization memory renewal = session(2);
        bytes memory authSignature = sig(OWNER_KEY, wallet.sessionDigest(renewal));
        vm.prank(STRANGER);
        wallet.authorizeSession(renewal, authSignature);
        vm.expectRevert(ClausProjectWallet.InvalidPayment.selector);
        wallet.pay(legacy, legacySignature);
        // the same payment set is fine if the renewal is never applied
        assertEq(RECIPIENT.balance, 0, "nothing paid under either generation");
        pay(payment(2, 2));
        assertEq(RECIPIENT.balance, 1 ether);
    }
}
