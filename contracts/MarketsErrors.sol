// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { RequestCommitment, BetCommitment, MarketCommitment, ResultCommitment } from "./Commitments.sol";

interface MarketsErrors {
    error MarketsWrongSender(address sender);
    error MarketsInvalidUserNonce(address user, uint256 expectedNonce, uint256 nonce);

    error MarketsResultAlreadyRevealed(MarketCommitment marketCommitment, ResultCommitment resultCommitment);
    error MarketsResultTooEarly(MarketCommitment marketCommitment, uint256 blockNumber);
    error MarketsInvalidResult(MarketCommitment marketCommitment, ResultCommitment resultCommitment);
    error MarketsInvalidBetRequest(
        RequestCommitment requestCommmitment, BetCommitment expectedCommitment, BetCommitment invalidCommitment
    );

    error MarketsInconsistentResult(MarketCommitment marketCommitment, ResultCommitment resultCommitment);
}
