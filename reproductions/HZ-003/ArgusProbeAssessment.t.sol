// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// Pins several items from the specimen's own release assessment, each of which
// had prose and a scratch-file citation but no test in the reviewed suite.
import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ClausApprovalExecutor} from "../src/ClausApprovalExecutor.sol";
import {ClausReadonlyProject} from "../src/ClausReadonlyProject.sol";
import {ClausNativeVault} from "../src/ClausNativeVault.sol";
import {ProbeModule64} from "./ArgusProbeGenAndGas.t.sol";

contract ArgusProbeExecutorEdges is Test {
    ClausApprovalExecutor executor;
    ClausReadonlyProject target;
    ProbeModule64 first;
    ProbeModule64 second;
    uint256 constant CLAUS_KEY = 0xA11CE;
    uint256 constant OWNER_KEY = 0xB0B;
    address constant STRANGER = address(0xF00D);
    bytes32 ID;
    bytes32 constant SALT = keccak256("edge-project");
    bytes32 constant MANDATE = keccak256("mandate");
    bytes32 constant POLICY = keccak256("policy");

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
        target = _register(ID, vm.addr(OWNER_KEY), SALT, address(first), 1 hours, 0);
    }

    function _register(bytes32 id, address owner, bytes32 salt, address impl, uint64 delay, uint256 nonce)
        internal returns (ClausReadonlyProject p)
    {
        ClausApprovalExecutor.Registration memory r = ClausApprovalExecutor.Registration(
            id, owner, salt, impl, impl.codehash, keccak256("init"), MANDATE, POLICY, delay, nonce,
            uint64(block.timestamp + 1 days));
        p = ClausReadonlyProject(executor.registerProject(r, "init", signature(OWNER_KEY, executor.registrationDigest(r))));
    }

    function minDelayOf(bytes32 id) internal view returns (uint64 v) { (,,,, v,,,) = executor.projects(id); }

    function approval(uint64 clausGeneration) internal view returns (ClausApprovalExecutor.Approval memory a) {
        a = ClausApprovalExecutor.Approval(ID, block.chainid, address(executor), address(target), 1,
            address(first).codehash, address(second), address(second).codehash, keccak256("second"),
            keccak256("deps"), keccak256("evidence"), POLICY, 1, 1, clausGeneration, MANDATE, 1,
            uint64(block.timestamp), uint64(block.timestamp + 7 days));
    }

    /// A1: cancelSignerRecovery needs no pending recovery, yet invalidates every
    /// queued approval network-wide.
    function test_A1_cancelWithNoPendingRecoveryKillsAQueuedApproval() public {
        ClausApprovalExecutor.Approval memory a = approval(1);
        bytes memory sig = signature(CLAUS_KEY, executor.approvalDigest(a));
        executor.queue(a, sig);
        assertEq(executor.readyAt(executor.approvalDigest(a)) != 0, true, "queued");
        executor.cancelSignerRecovery();                       // nothing was pending
        assertEq(executor.clausGeneration(), 2);
        vm.warp(block.timestamp + 1 hours + 1);
        vm.expectRevert(ClausApprovalExecutor.InvalidApproval.selector);
        executor.execute(a, "second", sig);
    }

    /// A2: finishSignerRecovery is permissionless, so a stranger completes the
    /// rotation and a ready approval dies with it.
    function test_A2_permissionlessFinishRotatesBeforeTheOwnerCanCancel() public {
        ClausApprovalExecutor.Approval memory a = approval(1);
        bytes memory sig = signature(CLAUS_KEY, executor.approvalDigest(a));
        executor.scheduleSignerRecovery(vm.addr(0xBEEF));
        vm.warp(block.timestamp + 2 days + 1);
        vm.prank(STRANGER);
        executor.finishSignerRecovery();
        assertEq(executor.clausSigner(), vm.addr(0xBEEF), "rotated by a stranger");
        executor.cancelSignerRecovery();                        // too late to undo
        assertEq(executor.clausSigner(), vm.addr(0xBEEF), "cancel does not restore the key");
        vm.expectRevert(ClausApprovalExecutor.InvalidApproval.selector);
        executor.execute(a, "second", sig);
    }

    /// A3: a pending owner proposal suspends upgrades and has no expiry.
    function test_A3_pendingOwnerProposalSuspendsUpgradesIndefinitely() public {
        ClausApprovalExecutor.Approval memory a = approval(1);
        bytes memory sig = signature(CLAUS_KEY, executor.approvalDigest(a));
        vm.prank(vm.addr(OWNER_KEY));
        executor.proposeProjectOwner(ID, address(0xBEEF));
        vm.warp(block.timestamp + 1 hours + 1);
        vm.expectRevert(ClausApprovalExecutor.InvalidApproval.selector);
        executor.execute(a, "second", sig);
        vm.warp(block.timestamp + 5 days);                      // approval still unexpired
        vm.expectRevert(ClausApprovalExecutor.InvalidApproval.selector);
        executor.execute(a, "second", sig);
        // A zero-address proposal is the documented cancel path. It lifts the
        // pending flag, but it bumps the authority generation again, so the
        // approval signed under generation 1 stays dead and must be re-signed.
        vm.prank(vm.addr(OWNER_KEY));
        executor.proposeProjectOwner(ID, address(0));
        assertEq(executor.pendingProjectOwners(ID), address(0), "proposal cancelled");
        vm.expectRevert(ClausApprovalExecutor.InvalidApproval.selector);
        executor.execute(a, "second", sig);
        ClausApprovalExecutor.Approval memory revived = a;
        revived.authorityGeneration = 3;
        revived.nonce = 2;
        bytes memory revivedSig = signature(CLAUS_KEY, executor.approvalDigest(revived));
        executor.queue(revived, revivedSig);
        bytes32 rHash = executor.approvalDigest(revived);
        console.log("queued hash readyAt", executor.readyAt(rHash));
        console.log("now at queue", block.timestamp);
        console.log("minDelay", minDelayOf(ID));
        console.log("pending owner", executor.pendingProjectOwners(ID));
        vm.warp(executor.readyAt(rHash) + 1);
        assertEq(block.timestamp >= executor.readyAt(rHash), true, "past the queue delay");
        assertEq(block.timestamp < revived.expiresAt, true, "approval unexpired");
        executor.execute(revived, "second", revivedSig);
        assertEq(target.implementation(), address(second), "only a re-signed approval executes");
    }

    /// A4: MIN_UPGRADE_DELAY is zero, so the lower-bound check is dead, and the
    /// constructor accepts the same address for both privileged roles.
    function test_A4_deadDelayLowerBoundAndCollapsedRoles() public {
        assertEq(executor.MIN_UPGRADE_DELAY(), 0);
        bytes32 id2 = executor.projectKey(vm.addr(OWNER_KEY), keccak256("zero-delay"));
        _register(id2, vm.addr(OWNER_KEY), keccak256("zero-delay"), address(first), 0, 1);
        (,,,, uint64 minDelay,,,) = executor.projects(id2);
        assertEq(minDelay, 0, "zero delay accepted, lower bound never trips");
        ClausApprovalExecutor collapsed = new ClausApprovalExecutor(vm.addr(CLAUS_KEY), vm.addr(CLAUS_KEY), 1 days);
        assertEq(collapsed.clausSigner(), collapsed.recoveryOwner(), "one address, two roles");
    }

    /// A6: an oversized caller input is reported as an oversized configuration.
    function test_A6_projectMisreportsAnOversizedInput() public {
        vm.expectRevert(ClausReadonlyProject.OversizedConfiguration.selector);
        target.evaluate(new bytes(8193));
    }

    /// A7: the executor itself is accepted by registerProject and rejected later
    /// by the project, so the error is InvalidModule, not InvalidRegistration.
    function test_A7_executorAsImplementationFailsWithTheWrongError() public {
        bytes32 id3 = executor.projectKey(vm.addr(OWNER_KEY), keccak256("self-impl"));
        ClausApprovalExecutor.Registration memory r = ClausApprovalExecutor.Registration(
            id3, vm.addr(OWNER_KEY), keccak256("self-impl"), address(executor), address(executor).codehash,
            keccak256("init"), MANDATE, POLICY, 1 hours, 2, uint64(block.timestamp + 1 days));
        bytes memory sig = signature(OWNER_KEY, executor.registrationDigest(r));
        vm.expectRevert(ClausReadonlyProject.InvalidModule.selector);
        executor.registerProject(r, "init", sig);
    }
}

contract ArgusProbeVaultEdges is Test {
    ClausNativeVault vault;

    function setUp() public {
        ClausReadonlyProject p = new ClausReadonlyProject(bytes32(uint256(7)),
            address(new ProbeModule64()), abi.encode(true, type(uint256).max));
        vault = new ClausNativeVault(address(p));
        vm.deal(address(this), 10 ether);
    }

    /// A5: receive() routes through deposit(), which needs far more than the
    /// 2,300-gas stipend of transfer()/send().
    function test_A5_aStipendPushCannotDeposit() public {
        vm.expectRevert();
        payable(address(vault)).transfer(1 ether);
        assertEq(address(vault).balance, 0, "nothing landed");
        (bool ok,) = address(vault).call{value: 1 ether}("");
        assertEq(ok, true, "an explicit call works");
        assertEq(vault.principal(address(this)), 1 ether);
    }

    /// A8: ETH forced into the vault is outside every total and stays there.
    function test_A8_forcedEtherIsUnaccountedAndUnwithdrawable() public {
        vm.deal(address(vault), 1 ether);
        (bool ok,) = address(vault).call{value: 1 ether}("");
        assertEq(ok, true);
        assertEq(vault.totalPrincipal(), 1 ether, "only the deposit is accounted");
        assertEq(address(vault).balance, 2 ether);
        vault.withdraw(1 ether, payable(address(0xAB)));
        assertEq(vault.totalPrincipal(), 0);
        assertEq(address(vault).balance, 1 ether, "forced ETH has no exit");
        console.log("forced wei still held", address(vault).balance);
    }
}
