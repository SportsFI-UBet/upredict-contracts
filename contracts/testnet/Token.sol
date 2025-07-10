// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TestERC20 is ERC20 {
    uint8 private immutable DECIMALS;

    constructor(uint8 _decimals, string memory name) ERC20(name, name) {
        DECIMALS = _decimals;
    }

    function mint(address account, uint256 value) external {
        return _mint(account, value);
    }

    function decimals() public view override returns (uint8) {
        return DECIMALS;
    }
}
