// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

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
         * A bitmask with what outcome indices have won. Allows ties, and
         * explicit refund results.
         */
        uint256 winningOutcomeMask;
        /**
         * Sum of all collateral staked for losing outcome
         */
        uint256 losingTotalPot;
        /**
         * Sum of all bet weights for bets with the winning outcome
         */
        uint256 winningTotalWeight;
        /**
         * The market for which this result applies to
         */
        MarketCommitment marketCommitment;
    }

    struct BetHiddenInfo {
        MarketCommitment marketCommitment;
        uint256 outcome;
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
    ) internal view override returns (uint256 losingTotalPot) {
        MarketInfo memory marketInfo = abi.decode(marketBlob.data, (MarketInfo));
        require(marketInfo.deadlineBlock < block.number, MarketsResultTooEarly(marketCommitment, block.number));

        ResultInfo memory resultInfo = abi.decode(resultBlob.data, (ResultInfo));
        losingTotalPot = resultInfo.losingTotalPot;

        // Cannot have more than 256 outcomes, so we can use bitmasks
        require(marketInfo.numOutcomes > 0, MarketsInvalidMarket(marketCommitment));
        require(marketInfo.numOutcomes < 257, MarketsInvalidMarket(marketCommitment));
        // Prevent "everyone loses" result.
        require(resultInfo.winningOutcomeMask > 0, MarketsInvalidResult(marketCommitment, resultCommitment));
        // Prevent win mask being outside known outcome indices.
        // Weird bit-twiddling to account for 256 outcomes
        uint256 fullMask = (1 << (marketInfo.numOutcomes - 1));
        fullMask |= (fullMask - 1);
        require(resultInfo.winningOutcomeMask <= (fullMask), MarketsInvalidResult(marketCommitment, resultCommitment));
        // Prevent divide by 0
        require(resultInfo.winningTotalWeight > 0, MarketsInvalidResult(marketCommitment, resultCommitment));
    }

    function _getPayout(
        MarketBlob calldata marketBlob,
        ResultBlob calldata resultBlob,
        BetRequest calldata request,
        BetBlob calldata betBlob
    )
        internal
        pure
        override
        returns (uint256 winningPotAmount, uint256 losingPotAmount, uint256 marketDeadlineBlock, address creator)
    {
        MarketInfo memory marketInfo = abi.decode(marketBlob.data, (MarketInfo));
        BetHiddenInfo memory hiddenInfo = abi.decode(betBlob.data, (BetHiddenInfo));
        ResultInfo memory resultInfo = abi.decode(resultBlob.data, (ResultInfo));

        marketDeadlineBlock = marketInfo.deadlineBlock;

        creator = abi.decode(marketBlob.data, (MarketInfo)).creator;
        uint256 betOutcomeMask = (1 << hiddenInfo.outcome);
        if ((betOutcomeMask & resultInfo.winningOutcomeMask) != 0) {
            winningPotAmount = request.amount;
            losingPotAmount =
                Math.mulDiv(hiddenInfo.betWeight, resultInfo.losingTotalPot, resultInfo.winningTotalWeight);
        }
    }

    function _getMarketFromResult(ResultBlob calldata resultBlob) internal pure override returns (MarketCommitment) {
        ResultInfo memory resultInfo = abi.decode(resultBlob.data, (ResultInfo));
        return resultInfo.marketCommitment;
    }

    function _getMarketFromBet(BetBlob calldata betBlob) internal pure override returns (MarketCommitment) {
        BetHiddenInfo memory betInfo = abi.decode(betBlob.data, (BetHiddenInfo));
        return betInfo.marketCommitment;
    }
}
