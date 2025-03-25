// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import { RequestCommitment, BetCommitment, MarketCommitment, ResultCommitment } from "./Commitments.sol";

interface MarketsErrors {
    error MarketsWrongSender(address sender);
    error MarketsWrongContract(address marketsContract);
    error MarketsInvalidUserNonce(address user, uint256 expectedNonce, uint256 nonce);
    error MarketsSubmissionTooLate(uint256 submissionDeadline, uint256 currentBlock);
    error MarketsRefundTooEarly(RequestCommitment requestCommitment, uint256 refundStartBlock, uint256 currentBlock);

    error MarketsResultAlreadyRevealed(MarketCommitment marketCommitment, ResultCommitment resultCommitment);
    error MarketsResultTooEarly(MarketCommitment marketCommitment, uint256 blockNumber);
    error MarketsInvalidMarket(MarketCommitment marketCommitment);
    error MarketsInvalidResult(MarketCommitment marketCommitment, ResultCommitment resultCommitment);
    error MarketsInvalidBetRequest(
        RequestCommitment requestCommmitment, BetCommitment expectedCommitment, BetCommitment invalidCommitment
    );

    error MarketsInconsistentResult(MarketCommitment marketCommitment, ResultCommitment resultCommitment);
    error MarketsBetDoesntExist(RequestCommitment requestCommitment);
    error MarketsInvalidRevealBet();
    error MarketsInvalidBatchRevealBet();

    /**
     * Operator trying to remove more fees than available
     */
    error MarketsNotEnoughOperatorFees(IERC20 token, uint256 available, uint256 requested);
    error MarketsCannotWithdrawOperatorFees();
    error MarketsFeeDistributionRequestInvalid();
}
