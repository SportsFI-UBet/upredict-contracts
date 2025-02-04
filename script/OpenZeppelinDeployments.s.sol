// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { UpgradeScripts } from "upgrade-scripts/UpgradeScripts.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { ERC1967Proxy as OZERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice Specialization for UpgradeScripts that works with our contracts
/// @dev Specifically using OpenZeppelin's Proxy and UUPS implementation
contract OpenZeppelinDeployments is UpgradeScripts {
    function upgradeProxy(address proxy, address newImplementation) internal override {
        UUPSUpgradeable(proxy).upgradeToAndCall(newImplementation, new bytes(0));
    }

    function getDeployProxyCode(address implementation, bytes memory initCall)
        internal
        pure
        override
        returns (bytes memory)
    {
        return abi.encodePacked(type(OZERC1967Proxy).creationCode, abi.encode(implementation, initCall));
    }
}
