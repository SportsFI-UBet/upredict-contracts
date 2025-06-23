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
    function loadExternalAddressConfigFromJson(string memory filepath) public view returns (bytes memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/", filepath);
        string memory json = vm.readFile(path);
        return vm.parseJson(json);
    }

    function setUpContracts(address admin) internal virtual;

    function run() external virtual {
        address admin = vm.envAddress(ADMIN_ADDRESS);

        mainnetConfirmation = 1750710033;

        startBroadcastIfNotDryRun();

        // run the setup scripts
        setUpContracts(admin);

        // we don't need broadcast from here on
        tryStopBroadcast();

        // console.log and store these in `deployments/{chainid}/deploy-latest.json` (if not in dry-run)
        storeLatestDeployments();
    }
}

contract Deploy is DeployBase {
    WeightedParimutuelMarkets public markets;

    function setUpContracts(address admin) internal virtual override {
        {
            bytes memory constructorArgs = abi.encode(admin);
            address implementation = setUpContract("WeightedParimutuelMarkets", constructorArgs, "", false);
            markets = WeightedParimutuelMarkets(implementation);
        }
    }
}

contract DeployTestnet is Deploy {
    TestERC20 public erc20;

    function setUpContracts(address admin) internal virtual override {
        Deploy.setUpContracts(admin);

        {
            address implementation = setUpContract("TestERC20", "", "", false);
            erc20 = TestERC20(implementation);
        }
    }
}

contract DeployLocalTestnet is DeployTestnet {
    /**
     * Another instance of markets to test more than one instance
     */
    WeightedParimutuelMarkets public otherMarkets;

    function setUpContracts(address admin) internal override {
        DeployTestnet.setUpContracts(admin);

        {
            bytes memory constructorArgs = abi.encode(admin);
            address implementation =
                setUpContract("WeightedParimutuelMarkets", constructorArgs, "WeightedParimutuelMarkets2", false);
            otherMarkets = WeightedParimutuelMarkets(implementation);
        }
    }
}
