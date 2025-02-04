// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Context } from "@openzeppelin/contracts/utils/Context.sol";

type MarketHash is bytes32;
/** Hash used to identify a bet by a user */
type BetHash is bytes32;

// TODO: ERC2771 Context? for metatx
// TODO: Access control?
contract Markets is Context{
    using SafeERC20 for IERC20;
    /** Market information that gets hashed to get its id */
    struct MarketInfo {
        address creator;
        uint256 deadline; // TODO: block or timestamp?
        /** Non-sequential market id decided off-chain */
        uint256 marketId;
    }

    // TODO: call it BetBlob?
    struct BetHiddenInfo {
        /**
         * Market hash corresponds to the hash of market information structure. Is
         * not be sequential, so marketId cannot be guessed. Also some values
         * that apply for the whole market can be efficiently verified at reveal
         * time by revealing the market struct
         */
        MarketHash marketHash;
        uint256 option;
        /** random salt to ensure hash cannot be predicted */
        uint256 salt;
    }

    // TODO: shrink field sizes and encodePacked?
    struct BetRequest {
        // TODO: ERC20 permit?

        IERC20 token;
        address from; // who is making the bet
        uint256 amount;
        uint256 nonce; // needed?
        /** block deadline when user can submit bet (needed?) */
        uint256 submissionDeadlineBlock;
        /** hash of the blob associated with the hidden information of the bet */
        uint256 blobHash;
        // TODO: need signature of backend as a proof the bet is valid
    }
    
    /** Stored on the blockchain to reference during reveal phase */
    struct BetInfo {
        // TODO: not sure what is needed here beside the fact that "it exists"
        uint256 amount;
    }

    struct RevealedBet {

        BetHiddenInfo hiddenInfo;
    }

    /** State that can be used to break up a large reveal into several transactions */
    struct RevealState {
       // TODO: some kind of hash?
       uint256 step;
    }

    // TODO: If we store MarketHash, the marketId can still be hidden.
    // - Makes it easier to track bets for the same market, without knowing which exact market it is
    mapping(MarketHash => RevealState) revealStates;
    mapping(BetHash => BetInfo) bets;

    // some storage for market results when they are revealed? Could just be
    // used during reveal and not stored at all


    function placeBet(BetRequest calldata bet) external {
        bet.token.safeTransferFrom(_msgSender(), address(this), bet.amount);

        // TODO:
        // Need to prevent bets to be entered past the market deadline without revealing the deadline or the market.
        // - if we sign the blob with some specific private key and do ecrecover, we can make backend arbiter of bets.
        //   Therefore need to store AccessControl permissions for addresses
        //   recovered through ecrecover. Can enable several signers to sign
    }

    // TODO: this is how we "prove" all the bets have been entered.
    // - Can be hard to ensure no bets are intentionally ignored by backend. Can just leave out bets for same market.
    // - Can be hard to know which bet is the _last_ bet in the chain for a market
    //
    // TODO: during the reveal step, each bet has a potential payout. Either 0,
    // or some non-zero amount.  In the general case we would have to go through
    // all bets twice - once to reveal and calculate aggregates, and once to do
    // payouts based on aggregates
    function reveal(MarketInfo calldata market, RevealedBet[] calldata bets) external {
        // TODO: allow splitting reveal
        for (uint256 i = 0; i < bets.length; i++) {
            // TODO: hash each bet and look it up


        }
    }
}
