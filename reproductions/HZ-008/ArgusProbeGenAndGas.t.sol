// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// Independent reproduction of two items from the specimen's own release
// assessment whose cited verification file (test/scratch/Leads.t.sol) is not in
// the reviewed suite.
import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ClausApprovalExecutor} from "../src/ClausApprovalExecutor.sol";
import {ClausReadonlyProject} from "../src/ClausReadonlyProject.sol";
import {ClausNativeVault} from "../src/ClausNativeVault.sol";

contract ProbeModule {
    function evaluate(bytes calldata, bytes calldata) external pure returns (bytes memory) { return "ok"; }
}

/// Vault side: the outer 250,000-gas envelope against a growing configuration.
contract ProbeModule64 {
    function evaluate(bytes calldata, bytes calldata) external pure returns (bytes memory) {
        return abi.encode(true, type(uint256).max);
    }
}

contract ArgusProbeVaultConfigGas is Test {
    function test_AG002_vaultDeniesACorrectPolicyWithALargeConfiguration() public {
        uint256[7] memory sizes = [uint256(0), 1024, 2048, 3072, 3520, 4096, 8192];
        for (uint256 i; i < sizes.length; ++i) {
            ClausReadonlyProject p = new ClausReadonlyProject(bytes32(uint256(900 + i)),
                address(new ProbeModule64()), new bytes(sizes[i]));
            ClausNativeVault vault = new ClausNativeVault(address(p));
            address user = address(uint160(0x3000 + i));
            vm.deal(user, 10 ether);
            bool admitted;
            vm.prank(user);
            try vault.deposit{value: 1 ether}() { admitted = true; } catch { admitted = false; }
            console.log(admitted ? "admitted" : "denied  ", "config bytes", sizes[i]);
            if (sizes[i] == 0) assertEq(admitted, true, "64-byte config is admitted");
        }
    }
}

/// Executor side: recovery cancellation and a pre-signed predictable generation.
contract ArgusProbeRecoveryGeneration is Test {
    ClausApprovalExecutor executor;
    ClausReadonlyProject target;
    ProbeModule first;
    ProbeModule second;
    uint256 constant CLAUS_KEY = 0xA11CE;
    uint256 constant OWNER_KEY = 0xB0B;
    bytes32 ID;
    bytes32 constant SALT = keccak256("test-project");
    bytes32 constant MANDATE = keccak256("test-mandate");
    bytes32 constant POLICY = keccak256("test-policy");

    function signature(uint256 key, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash);
        return abi.encodePacked(r, s, v);
    }

    function setUp() public {
        vm.warp(1800000000);
        executor = new ClausApprovalExecutor(vm.addr(CLAUS_KEY), address(this), 2 days);
        ID = executor.projectKey(vm.addr(OWNER_KEY), SALT);
        first = new ProbeModule();
        second = new ProbeModule();
        ClausApprovalExecutor.Registration memory r = ClausApprovalExecutor.Registration(
            ID, vm.addr(OWNER_KEY), SALT, address(first), address(first).codehash, keccak256("first"),
            MANDATE, POLICY, 1 hours, 0, uint64(block.timestamp + 1 days));
        target = ClausReadonlyProject(executor.registerProject(r, "first", signature(OWNER_KEY, executor.registrationDigest(r))));
    }

    function approval(uint64 clausGeneration) internal view returns (ClausApprovalExecutor.Approval memory a) {
        a = ClausApprovalExecutor.Approval(ID, block.chainid, address(executor), address(target), 1,
            address(first).codehash, address(second), address(second).codehash, keccak256("second"),
            keccak256("fixed-dependencies"), keccak256("actual-review-evidence"), POLICY, 1, 1, clausGeneration,
            MANDATE, 1, uint64(block.timestamp), uint64(block.timestamp + 7 days));
    }

    function test_AG003_preSignedFutureGenerationSurvivesAScheduleAndCancel() public {
        assertEq(executor.clausGeneration(), 1);
        // Signed now, for a generation that does not exist yet.
        ClausApprovalExecutor.Approval memory a = approval(3);
        bytes memory sig = signature(CLAUS_KEY, executor.approvalDigest(a));
        // Control: the generation check is live, so it cannot be queued yet.
        vm.expectRevert(ClausApprovalExecutor.InvalidApproval.selector);
        executor.queue(a, sig);
        // Schedule, then cancel: two predictable increments, signer unchanged.
        executor.scheduleSignerRecovery(vm.addr(0xBEEF));
        assertEq(executor.clausGeneration(), 2);
        executor.cancelSignerRecovery();
        assertEq(executor.clausGeneration(), 3);
        assertEq(executor.clausSigner(), vm.addr(CLAUS_KEY), "the key was never rotated");
        // The pre-signed material is valid again.
        executor.queue(a, sig);
        vm.warp(block.timestamp + 1 hours + 1);
        executor.execute(a, "second", sig);
        assertEq(target.implementation(), address(second), "pre-signed approval executed after cancellation");
        console.log("cancellation did not invalidate the pre-signed approval");
    }

    function test_AG003_control_scheduleAloneLeavesTheSignatureInvalid() public {
        ClausApprovalExecutor.Approval memory a = approval(3);
        bytes memory sig = signature(CLAUS_KEY, executor.approvalDigest(a));
        executor.scheduleSignerRecovery(vm.addr(0xBEEF));   // generation 2 only
        assertEq(executor.clausGeneration(), 2);
        vm.expectRevert(ClausApprovalExecutor.InvalidApproval.selector);
        executor.queue(a, sig);
    }
}
