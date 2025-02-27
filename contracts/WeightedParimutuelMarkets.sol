// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";

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

contract WeightedParimutuelMarkets is MarketsBase {
    struct MarketInfo {
        /**
         * Account that created this market
         */
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
        /**
         * The option that should get part of the losing pot
         */
        uint256 winningOption;
        /**
         * Sum of all collateral staked for losing options
         */
        uint256 losingTotalPot;
        /**
         * Sum of all bet weights for winning options
         */
        uint256 winningTotalWeight;
    }

    struct BetHiddenInfo {
        MarketCommitment marketCommitment;
        uint256 option;
        /**
         * Custom weight assigned to this bet by the backend. To replicate
         * Parimutuel betting, this weight would equal the bet amount.
         */
        uint256 betWeight;
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
        require(
            request.amount >= betLowerLimit && request.amount <= betUpperLimit,
            MarketsBetRequestOutsideLimits(requestCommitment, request.amount)
        );
    }

    function _verifyResult(
        MarketCommitment marketCommitment,
        MarketBlob calldata marketBlob,
        ResultCommitment resultCommitment,
        ResultBlob calldata resultBlob
    ) internal view override {
        MarketInfo memory marketInfo = abi.decode(marketBlob.data, (MarketInfo));
        require(marketInfo.deadlineBlock >= block.number, MarketsResultTooEarly(marketCommitment, block.number));

        ResultInfo memory resultInfo = abi.decode(resultBlob.data, (ResultInfo));
        require(
            resultInfo.winningOption < marketInfo.numOutcomes, MarketsInvalidResult(marketCommitment, resultCommitment)
        );
        // TODO: how to ensure that no divide by zero, but also handle the case where there is no winner
        // In a prediction market, if no-one bets on the winning result, noone gets the money?
        require(resultInfo.winningTotalWeight > 0, MarketsInvalidResult(marketCommitment, resultCommitment));
    }

    function _getPayout(
        MarketBlob calldata marketBlob,
        ResultBlob calldata resultBlob,
        BetRequest calldata request,
        BetBlob calldata betBlob
    ) internal pure override returns (uint256 amount, address creator) {
        BetHiddenInfo memory hiddenInfo = abi.decode(betBlob.data, (BetHiddenInfo));
        ResultInfo memory resultInfo = abi.decode(resultBlob.data, (ResultInfo));

        // TODO: any more sanity checks?

        creator = abi.decode(marketBlob.data, (MarketInfo)).creator;
        if (hiddenInfo.option == resultInfo.winningOption) {
            amount = request.amount
                + Math.mulDiv(hiddenInfo.betWeight, resultInfo.losingTotalPot, resultInfo.winningTotalWeight);
        }
    }
}
