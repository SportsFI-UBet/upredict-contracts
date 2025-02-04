// solhint-disable one-contract-per-file
// solhint-disable custom-errors
// solhint-disable ordering
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// import { console2 } from "forge-std/console2.sol";

import { Markets } from "../contracts/Markets.sol";
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

contract DeployEthereum is DeployBase {
    Markets public markets;

    function setUpContracts() internal override {
        {
            address implementation = setUpContract("Markets", "", "", false);
            markets = Markets(implementation);
        }
    }
}
