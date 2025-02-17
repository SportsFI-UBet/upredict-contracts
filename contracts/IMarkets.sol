// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import { MarketCommitment, ResultCommitment, BetCommitment, MarketBlob, ResultBlob, BetBlob } from "./Commitments.sol";

interface IMarkets {
    struct BetRequest {
        // TODO: implementation version? Make sure it matches the contract implementation
        IERC20 token;
        uint96 amount;
        address from; // who is making the bet
        uint96 nonce; // user nonce to prevent replay attack
        /**
         * block deadline when user can submit bet (needed?)
         */
        uint256 submissionDeadlineBlock;
    }

    event MarketsBetPlaced(BetRequest bet, BetCommitment betCommitment);
    event MarketsResultRevealed(MarketCommitment indexed marketCommitment, ResultCommitment resultCommitment);
    event MarketsBetRevealed(
        BetCommitment indexed betCommitment,
        MarketCommitment marketCommitment,
        IERC20 indexed token,
        address indexed user,
        uint256 payout
    );

    /**
     * Place a bet according to the request, signed offchain by the backend.
     * @param bet the publicly visible bet details
     * @param betCommitment commitment for the hidden portion of bet information
     */
    function placeBet(BetRequest calldata bet, BetCommitment betCommitment) external;

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
    function revealBet(MarketBlob calldata marketBlob, ResultBlob calldata resultBlob, BetBlob calldata betBlob)
        external
        returns (IERC20 token, address to, uint256 amount);
}
