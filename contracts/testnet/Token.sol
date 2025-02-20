// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TestERC20 is ERC20 {
    constructor() ERC20("TEST", "TEST") { }

    function mint(address account, uint256 value) external {
        return _mint(account, value);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }
}
