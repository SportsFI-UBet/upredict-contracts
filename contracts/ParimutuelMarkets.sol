// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import { UD60x18, ud60x18, unwrap } from "@prb/math/UD60x18.sol";

import { MarketsBase } from "./MarketsBase.sol";
import {
    BetRequest,
    RequestCommitment,
    MarketCommitment,
    ResultCommitment,
    MarketBlob,
    ResultBlob,
    BetBlob
} from "./Commitments.sol";

contract ParimutuelMarkets is MarketsBase {
    struct MarketInfo {
        address creator;
        /**
         * When a market is considered done
         */
        uint256 deadlineBlock;
        /**
         * Non-sequential market id decided off-chain
         */
        uint256 marketId;
        uint256 numOutcomes;
    }

    struct ResultInfo {
        uint256 winningOption;
        /**
         * multiplier of the amount to get the reward on top of the original amount
         */
        UD60x18 normalization;
    }

    struct BetHiddenInfo {
        MarketCommitment marketCommitment;
        uint256 option;
        /**
         * random salt to ensure hash cannot be predicted
         */
        uint256 salt;
    }

    uint128 public betLowerLimit;
    uint128 public betUpperLimit;

    error MarketsBetRequestOutsideLimits(RequestCommitment requestCommitment, uint256 amount);

    constructor(address admin) MarketsBase(admin) {
        betUpperLimit = type(uint128).max;
    }

    function setLimits(uint256 _betLowerLimit, uint256 _betUpperLimit) external onlyRole(DEFAULT_ADMIN_ROLE) {
        betLowerLimit = uint128(_betLowerLimit);
        betUpperLimit = uint128(_betUpperLimit);
    }

    function _verifyRequest(BetRequest calldata request, RequestCommitment requestCommitment) internal view override {
        if (request.amount < betLowerLimit || request.amount > betUpperLimit) {
            revert MarketsBetRequestOutsideLimits(requestCommitment, request.amount);
        }
    }

    function _verifyResult(
        MarketCommitment marketCommitment,
        MarketBlob calldata marketBlob,
        ResultCommitment resultCommitment,
        ResultBlob calldata resultBlob
    ) internal view override {
        MarketInfo memory marketInfo = abi.decode(marketBlob.data, (MarketInfo));
        if (marketInfo.deadlineBlock < block.number) {
            revert MarketsResultTooEarly(marketCommitment, block.number);
        }

        ResultInfo memory resultInfo = abi.decode(resultBlob.data, (ResultInfo));
        if (resultInfo.winningOption >= marketInfo.numOutcomes) {
            revert MarketsInvalidResult(marketCommitment, resultCommitment);
        }
    }

    function _getPayout(
        MarketBlob calldata,
        ResultBlob calldata resultBlob,
        BetRequest calldata request,
        BetBlob calldata betBlob
    ) internal pure override returns (IERC20 token, address to, uint256 amount) {
        BetHiddenInfo memory hiddenInfo = abi.decode(betBlob.data, (BetHiddenInfo));
        ResultInfo memory resultInfo = abi.decode(resultBlob.data, (ResultInfo));

        // TODO: any more sanity checks?

        // TODO: move token and to out?
        token = request.token;
        to = request.from;
        if (hiddenInfo.option == resultInfo.winningOption) {
            // TODO: take care of fees
            amount = request.amount + unwrap(ud60x18(request.amount) * resultInfo.normalization);
        }
    }
}
