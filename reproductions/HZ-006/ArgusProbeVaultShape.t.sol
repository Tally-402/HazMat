// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// H4: the exact return encoding and the size bounds, project layer and vault layer.
import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ClausReadonlyProject} from "../src/ClausReadonlyProject.sol";
import {ClausVaultAdmission} from "../src/ClausVaultAdmission.sol";
import {ClausNativeVault} from "../src/ClausNativeVault.sol";

/// Returns a payload of 64 + configuration.length bytes, first word 1.
contract PayloadModule {
    function evaluate(bytes calldata configuration, bytes calldata) external pure returns (bytes memory) {
        uint256 pad = configuration.length;
        bytes memory payload = new bytes(64 + pad);
        assembly ("memory-safe") {
            mstore(add(payload, 32), 1)
            mstore(add(payload, 64), not(0))
        }
        // The ABI wrapper adds the 64-byte header, so return the payload itself.
        return payload;
    }
}

/// Returns a raw, non-canonical header: offset 32, length 119, 160 bytes total.
contract LyingHeaderModule {
    function evaluate(bytes calldata, bytes calldata) external pure returns (bytes memory) {
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, 32)
            mstore(add(p, 32), 119)
            return(p, 160)
        }
    }
}

/// Correct 64-byte shape, tunable work.
contract WorkModule {
    function evaluate(bytes calldata configuration, bytes calldata) external pure returns (bytes memory) {
        uint256 rounds = abi.decode(configuration, (uint256));
        uint256 acc = 1;
        for (uint256 i; i < rounds; ++i) { acc = uint256(keccak256(abi.encode(acc, i))); }
        return abi.encode(acc != 0, type(uint256).max);
    }
}

contract ArgusProbeVaultShape is Test {
    function project(address module, bytes memory config) internal returns (ClausReadonlyProject) {
        return new ClausReadonlyProject(bytes32(uint256(1)), module, config);
    }

    /// 8192 payload is exactly legal: 64 + 8192 == the 8256 bound.
    function test_H4a_projectAdmitsAPayloadOfExactly8192() public {
        ClausReadonlyProject p = project(address(new PayloadModule()), new bytes(8128));
        bytes memory out = p.evaluate(hex"");
        assertEq(out.length, 8192, "max payload admitted");
    }

    /// One payload byte over and the module's returndata is already past the bound.
    function test_H4b_onePayloadByteOverIsRejected() public {
        ClausReadonlyProject p = project(address(new PayloadModule()), new bytes(8129));
        vm.expectRevert(ClausReadonlyProject.OversizedResult.selector);
        p.evaluate(hex"");
    }

    /// A module can return a well-formed but non-canonical header.
    function test_H4c_nonCanonicalAbiHeaderIsRejected() public {
        ClausReadonlyProject p = project(address(new LyingHeaderModule()), "");
        vm.expectRevert(ClausReadonlyProject.InvalidResult.selector);
        p.evaluate(hex"");
    }

    /// Control: the shipped admission module works as a vault policy, end to end.
    function test_H4d_shippedAdmissionModuleIsAViablePolicy() public {
        ClausReadonlyProject p = project(address(new ClausVaultAdmission()), abi.encode(true, type(uint256).max));
        ClausNativeVault vault = new ClausNativeVault(address(p));
        address user = address(0xC0FFEE);
        vm.deal(user, 10 ether);
        vm.prank(user);
        vault.deposit{value: 1 ether}();
        assertEq(vault.principal(user), 1 ether, "shipped policy admits a deposit");
    }

    /// A correct project whose module returns 288 bytes is denied by the vault's shape rule.
    function test_H4e_largeOutputModuleIsDeniedByTheShippedShapeRule() public {
        ClausReadonlyProject p = project(address(new PayloadModule()), new bytes(224));
        bytes memory input = abi.encode(address(0xC0FFEE), uint256(1 ether), uint256(1 ether));
        assertEq(p.evaluate(input).length, 288, "project happily returns 288 bytes");
        ClausNativeVault vault = new ClausNativeVault(address(p));
        address user = address(0xBEEF);
        vm.deal(user, 10 ether);
        vm.prank(user);
        vm.expectRevert(ClausNativeVault.DepositDenied.selector);
        vault.deposit{value: 1 ether}();
    }

    /// Where the gas envelope actually binds for a correct-shape policy.
    function test_H4f_gasEnvelopeForACorrectShapePolicy() public {
        uint256[7] memory levels = [uint256(0), 250, 500, 600, 750, 1000, 4000];
        for (uint256 i; i < levels.length; ++i) {
            ClausReadonlyProject p = new ClausReadonlyProject(bytes32(uint256(100 + i)),
                address(new WorkModule()), abi.encode(levels[i]));
            ClausNativeVault vault = new ClausNativeVault(address(p));
            address user = address(uint160(0x1000 + i));
            vm.deal(user, 10 ether);
            bool admitted;
            vm.prank(user);
            try vault.deposit{value: 1 ether}() { admitted = true; } catch { admitted = false; }
            console.log(admitted ? "admitted" : "denied", "rounds", levels[i]);
            if (levels[i] == 0) assertEq(admitted, true, "trivial work is never denied");
            if (levels[i] == 500) assertEq(admitted, true, "500 rounds admitted");
            if (levels[i] == 1000) assertEq(admitted, false, "1000 rounds exhausted the cap");
        }
    }
}
