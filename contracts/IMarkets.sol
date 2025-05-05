// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {
    BetRequest,
    RequestCommitment,
    MarketCommitment,
    ResultCommitment,
    MarketBlob,
    ResultBlob,
    BetBlob
} from "./Commitments.sol";

interface IMarkets {
    /**
     * A batch distribution request to distribute operator fees as they see fit
     */
    struct FeeDistributionRequest {
        IERC20 token;
        address[] users;
        uint256[] amounts;
    }

    event MarketsFeesChanged(uint16 creatorFeeDecimal, uint16 operatorFeeDecimal);

    event MarketsBetPlaced(BetRequest request);
    /**
     * Exceptional event that should not occur if backend has no bugs
     */
    event MarketsBetWasPlacedAfterResult(
        MarketCommitment indexed marketCommitment, RequestCommitment requestCommitment
    );
    event MarketsResultRevealed(MarketCommitment indexed marketCommitment, ResultCommitment resultCommitment);
    event MarketsRefundIssued(
        RequestCommitment indexed requestCommitment,
        MarketCommitment marketCommitment,
        IERC20 indexed token,
        address indexed user,
        uint256 payout
    );
    event MarketsBetRevealed(
        RequestCommitment indexed requestCommitment,
        MarketCommitment marketCommitment,
        IERC20 indexed token,
        address indexed user,
        uint256 payout
    );
    /**
     * Fees collected from a bet redeem. This event is DEPRECATED because it is missing the requestCommitment
     */
    event MarketsBetFeeCollected(
        MarketCommitment indexed marketCommitment,
        IERC20 indexed token,
        address indexed creator,
        uint256 creatorFee,
        uint256 operatorFee
    );
    /**
     * Fees collected from a bet redeem.
     */
    event MarketsBetFeeCollectedWithRequest(
        RequestCommitment requestCommitment,
        MarketCommitment indexed marketCommitment,
        IERC20 indexed token,
        address indexed creator,
        uint256 creatorFee,
        uint256 operatorFee
    );

    /**
     * Place a bet according to the request, signed offchain by the backend.
     * @param request the publicly visible bet details
     * @param betSignature the bet has to be signed by a priveleged entity
     */
    function placeBet(BetRequest calldata request, bytes calldata betSignature) external;

    /**
     * If market has not settled in time, user can request a full refund.
     */
    function requestRefund(BetRequest calldata request, BetBlob calldata betBlob)
        external
        returns (IERC20 token, address to, uint256 amount);

    /**
     * Record a market result that can be used during bet reveal to give payouts. Note that if the `marketBlob` is known, anyone can enter the result.
     */
    function revealMarketResult(
        MarketBlob calldata marketBlob,
        ResultBlob calldata resultBlob,
        bytes calldata resultSignature
    ) external;

    /**
     * Reveal a bet to claim any payout
     */
    function revealBet(
        MarketBlob calldata marketBlob,
        ResultBlob calldata resultBlob,
        BetRequest calldata request,
        BetBlob calldata betBlob
    ) external returns (IERC20 token, address to, uint256 amount);

    /**
     * Reveal multiple bets for a particular market
     */
    function batchRevealBet(
        MarketBlob calldata marketBlob,
        ResultBlob calldata resultBlob,
        BetRequest[] calldata requests,
        BetBlob[] calldata betBlobs
    ) external;

    function withdrawCreatorFees(IERC20[] calldata tokens, address[] calldata users) external;

    function distributeOperatorFees(FeeDistributionRequest[] calldata requests) external;
}
