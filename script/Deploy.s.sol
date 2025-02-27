// solhint-disable one-contract-per-file
// solhint-disable custom-errors
// solhint-disable ordering
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// import { console2 } from "forge-std/console2.sol";

import { WeightedParimutuelMarkets } from "../contracts/WeightedParimutuelMarkets.sol";
import { TestERC20 } from "../contracts/testnet/Token.sol";
import { OpenZeppelinDeployments } from "./OpenZeppelinDeployments.s.sol";

// environment variables for parameters to script
string constant ADMIN_ADDRESS = "ADMIN_ADDRESS";
string constant EXTERNAL_ADDRESS_CONFIG_PATH = "EXTERNAL_ADDRESS_CONFIG_PATH";

abstract contract DeployBase is OpenZeppelinDeployments {
    address public admin;

    constructor() {
        admin = vm.envAddress(ADMIN_ADDRESS);
    }

    function loadExternalAddressConfigFromJson(string memory filepath) public view returns (bytes memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/", filepath);
        string memory json = vm.readFile(path);
        return vm.parseJson(json);
    }

    function setUpContracts() internal virtual;

    function run() external virtual {
        startBroadcastIfNotDryRun();

        // run the setup scripts
        setUpContracts();

        // we don't need broadcast from here on
        tryStopBroadcast();

        // console.log and store these in `deployments/{chainid}/deploy-latest.json` (if not in dry-run)
        storeLatestDeployments();
    }
}

contract Deploy is DeployBase {
    WeightedParimutuelMarkets public parimutuelMarkets;

    function setUpContracts() internal virtual override {
        {
            bytes memory constructorArgs = abi.encode(admin);
            address implementation = setUpContract("WeightedParimutuelMarkets", constructorArgs, "", false);
            parimutuelMarkets = WeightedParimutuelMarkets(implementation);
        }
    }
}

contract DeployTestnet is Deploy {
    TestERC20 public token;

    function setUpContracts() internal override {
        Deploy.setUpContracts();

        {
            address implementation = setUpContract("TestERC20", "", "", false);
            token = TestERC20(implementation);
        }
    }
}
