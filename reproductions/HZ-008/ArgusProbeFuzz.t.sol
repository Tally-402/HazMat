// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// Fuzz campaign. Their own suite carries one fuzz test; mine carried none.
import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ClausProjectWallet} from "../src/ClausProjectWallet.sol";
import {ClausNativeVault} from "../src/ClausNativeVault.sol";
import {ClausReadonlyProject} from "../src/ClausReadonlyProject.sol";
import {ClausApprovalExecutor} from "../src/ClausApprovalExecutor.sol";
import {ProbeModule64} from "./ArgusProbeGenAndGas.t.sol";

/// F1: is `total` a lifetime cap? Fuzzed over any number of generations, no.
contract ArgusProbeFuzzWallet is Test {
    uint256 constant OWNER_KEY = 0xB0B;
    uint256 constant SESSION_KEY = 0xA11CE;
    bytes32 constant SESSION = keccak256("provider-payment-session");
    address constant RECIPIENT = address(0xBEEF);
    address constant STRANGER = address(0xF00D);
    ClausProjectWallet wallet;
    uint256 nonce;

    function setUp() public {
        vm.warp(1800000000);
        wallet = new ClausProjectWallet(vm.addr(OWNER_KEY));
        vm.deal(address(wallet), 50 ether);
    }

    function sig(uint256 key, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash);
        return abi.encodePacked(r, s, v);
    }

    function session(uint64 generation) internal view returns (ClausProjectWallet.SessionAuthorization memory) {
        return ClausProjectWallet.SessionAuthorization(SESSION, vm.addr(SESSION_KEY), address(0), RECIPIENT,
            1 ether, 1 ether, uint64(block.timestamp), uint64(block.timestamp + 1 days), generation,
            uint64(block.timestamp + 1 hours));
    }

    function payment(uint64 generation) internal returns (ClausProjectWallet.Payment memory p) {
        p = ClausProjectWallet.Payment(SESSION, generation, address(0), RECIPIENT, 1 ether,
            keccak256(abi.encode(++nonce)), nonce, uint64(block.timestamp + 1 hours));
    }

    function spentOf() internal view returns (uint128 v) { (,,,,, v,,,) = wallet.sessions(SESSION); }

    function testFuzzF1_everyGenerationIsAFreshAllowance(uint8 generations) public {
        generations = uint8(bound(generations, 1, 5));
        for (uint64 g = 1; g <= generations; ++g) {
            ClausProjectWallet.SessionAuthorization memory s = session(g);
            bytes memory authSig = sig(OWNER_KEY, wallet.sessionDigest(s));
            if (g == 1) wallet.authorizeSession(s, authSig);
            else { vm.prank(STRANGER); wallet.authorizeSession(s, authSig); }   // in place, no revocation
            ClausProjectWallet.Payment memory p = payment(g);
            wallet.pay(p, sig(SESSION_KEY, wallet.paymentDigest(p)));
            assertEq(spentOf(), 1 ether, "allowance fully consumed");
            // the cap binds inside the generation
            ClausProjectWallet.Payment memory overflow = payment(g);
            bytes memory overflowSig = sig(SESSION_KEY, wallet.paymentDigest(overflow));
            vm.expectRevert(ClausProjectWallet.InvalidPayment.selector);
            wallet.pay(overflow, overflowSig);
        }
        assertEq(RECIPIENT.balance, uint256(1 ether) * generations, "cumulative paid exceeds the stated total");
    }
}

/// F2: does deposit accounting ever exceed the balance, or vice versa?
contract ArgusProbeFuzzVault is Test {
    ClausNativeVault vault;

    function setUp() public {
        ClausReadonlyProject p = new ClausReadonlyProject(bytes32(uint256(9)),
            address(new ProbeModule64()), abi.encode(true, type(uint256).max));
        vault = new ClausNativeVault(address(p));
        vm.deal(address(this), 100 ether);
    }

    /// P1: the precompile address range is live code, not inert space.
    function test_P1_precompileRecipientsAreNotInert() public {
        vault.deposit{value: 1 ether}();
        uint256 failures;
        for (uint160 a = 1; a <= 0x10; ++a) {
            address cand = address(a);
            try vault.withdraw(1, payable(cand)) { }
            catch { ++failures; console.log("withdraw failed to", cand); }
        }
        assertEq(failures > 0, true, "at least one precompile recipient refuses empty calldata");
        assertEq(vault.totalPrincipal(), 1 ether - (0x10 - failures), "principal only left on success");
        console.log("failures in 0x01..0x10", failures);
    }

    function testFuzzF2_conservationHoldsAndSurplusStaysOutside(uint96 amount, uint96 forced) public {
        amount = uint96(bound(amount, 1, 5 ether));
        forced = uint96(bound(forced, 0, 3 ether));
        vm.deal(address(vault), forced);
        vault.deposit{value: amount}();
        assertEq(vault.totalPrincipal(), amount, "principal tracked exactly");
        assertEq(address(vault).balance, uint256(amount) + forced, "balance is principal plus surplus");
        assertEq(address(vault).balance - vault.totalPrincipal(), forced, "surplus constant");
        vault.withdraw(amount, payable(address(0xABCD)));   // not a precompile
        assertEq(vault.totalPrincipal(), 0);
        assertEq(address(vault).balance, forced, "accounting never touches the surplus");
    }
}

/// F3: how far does the predictable-generation property generalise?
contract ArgusProbeFuzzRevalidation is Test {
    ClausApprovalExecutor executor;
    ClausReadonlyProject target;
    ProbeModule64 first;
    ProbeModule64 second;
    uint256 constant CLAUS_KEY = 0xA11CE;
    uint256 constant OWNER_KEY = 0xB0B;
    bytes32 ID;
    bytes32 constant SALT = keccak256("fuzz-project");

    function signature(uint256 key, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash);
        return abi.encodePacked(r, s, v);
    }

    function setUp() public {
        vm.warp(1800000000);
        executor = new ClausApprovalExecutor(vm.addr(CLAUS_KEY), address(this), 2 days);
        first = new ProbeModule64();
        second = new ProbeModule64();
        ID = executor.projectKey(vm.addr(OWNER_KEY), SALT);
        ClausApprovalExecutor.Registration memory r = ClausApprovalExecutor.Registration(
            ID, vm.addr(OWNER_KEY), SALT, address(first), address(first).codehash, keccak256("init"),
            keccak256("mandate"), keccak256("policy"), 1 hours, 0, uint64(block.timestamp + 1 days));
        target = ClausReadonlyProject(executor.registerProject(r, "init",
            signature(OWNER_KEY, executor.registrationDigest(r))));
    }

    function testFuzzF3_anyNumberOfPauseCancelCyclesRevalidatesOnePreSignedGeneration(uint8 cycles) public {
        cycles = uint8(bound(cycles, 1, 8));
        uint64 futureGeneration = uint64(1 + 2 * uint256(cycles));
        ClausApprovalExecutor.Approval memory a = ClausApprovalExecutor.Approval(ID, block.chainid,
            address(executor), address(target), 1, address(first).codehash, address(second),
            address(second).codehash, keccak256("second"), keccak256("deps"), keccak256("evidence"),
            keccak256("policy"), 1, 1, futureGeneration, keccak256("mandate"), 1,
            uint64(block.timestamp), uint64(block.timestamp + 7 days));
        bytes memory sig = signature(CLAUS_KEY, executor.approvalDigest(a));
        // signed before any pause exists
        vm.expectRevert(ClausApprovalExecutor.InvalidApproval.selector);
        executor.queue(a, sig);
        for (uint256 i; i < cycles; ++i) {
            executor.scheduleSignerRecovery(vm.addr(0xBEEF));
            executor.cancelSignerRecovery();
        }
        assertEq(executor.clausGeneration(), futureGeneration, "generation lands exactly on the signed value");
        executor.queue(a, sig);
        vm.warp(executor.readyAt(executor.approvalDigest(a)) + 1);
        executor.execute(a, "second", sig);
        assertEq(target.implementation(), address(second));
    }
}
