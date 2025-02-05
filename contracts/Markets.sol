// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Context } from "@openzeppelin/contracts/utils/Context.sol";

/**
 * Some implementation defined blob describing hidden info of a market
 */
struct MarketBlob {
    bytes data;
}
/**
 * Market commitment corresponds to some hash of the market information
 * structure. Is not be sequential, so marketId cannot be guessed. Also some
 * values that apply for the whole market can be efficiently verified at reveal
 * time by revealing the market struct
 */

type MarketCommitment is bytes32;

/**
 * Implementation defined blob for the market result, that can be used during
 * bet reveal to give user payout
 */
struct ResultBlob {
    bytes data;
}

type ResultCommitment is bytes32;

/**
 * Some implementation defined blob describing hidden info of bet
 */
struct BetBlob {
    bytes data;
}

type BetCommitment is bytes32;

interface MarketsErrors {
    error MarketsInvalidUserNonce(uint256 nonce);
    error MarketsResultAlreadyRevealed(MarketCommitment marketCommitment, ResultCommitment resultCommitment);
}

// TODO: ERC2771 Context? for metatx
// TODO: Access control
abstract contract MarketsBase is Context, MarketsErrors {
    using SafeERC20 for IERC20;

    // TODO: Is packing worth it? Measure gas cost
    struct BetRequest {
        // TODO: ERC20 permit?
        IERC20 token;
        uint96 amount;
        address from; // who is making the bet
        uint96 nonce; // user nonce to prevent replay attack
        /**
         * block deadline when user can submit bet (needed?)
         */
        uint256 submissionDeadlineBlock;
        // TODO: refund deadline?
        /**
         * a commitment for hidden information of bet. Can be hash of the blob associated with the bet
         */
        BetCommitment commitment;
    }

    /**
     * Stored on the blockchain to reference during reveal phase
     */
    struct BetInfo {
        // TODO: not sure what is needed here beside the fact that "it exists"
        uint256 amount;
    }

    /**
     * Addresses that are trusted to sign bet requests
     */
    bytes32 public constant BET_SIGNATURE_ROLE = keccak256("BET_SIGNATURE_ROLE");
    /**
     * Addresses that are trusted to sign market results
     */
    bytes32 public constant RESULT_SIGNATURE_ROLE = keccak256("RESULT_SIGNATURE_ROLE");

    // TODO: If we store MarketHash, the marketId can still be hidden.
    // - Makes it easier to track bets for the same market, without knowing which exact market it is
    mapping(MarketCommitment => ResultCommitment) marketResults;
    mapping(BetCommitment => BetInfo) bets;

    /**
     * Increments every time a user places a bet
     */
    mapping(address => uint256) userNonces;

    /**
     * Place a bet according to the request, signed offchain by the backend.
     *
     */
    function placeBet(BetRequest calldata bet) external {
        bet.token.safeTransferFrom(_msgSender(), address(this), bet.amount);

        bets[bet.commitment] = BetInfo({ amount: bet.amount });

        // TODO: check nonce and increment

        // TODO:
        // Need to prevent bets to be entered past the market deadline without revealing the deadline or the market.
        // - if we sign the blob with some specific private key and do ecrecover, we can make backend arbiter of bets.
        //   Therefore need to store AccessControl permissions for addresses
        //   recovered through ecrecover. Can enable several signers to sign
    }

    /**
     * Record a market result that can be used during bet reveal to give payouts. Note that if the `marketBlob` is known, anyone can enter the result.
     */
    function revealMarketResult(
        MarketBlob calldata marketBlob,
        ResultBlob calldata resultBlob,
        bytes calldata /* resultSignature */
    ) external {
        // TODO: verify resultSignature
        // TODO: avoid replay attack if first time rejected

        MarketCommitment marketCommitment = MarketCommitment.wrap(keccak256(marketBlob.data));
        ResultCommitment resultCommitment = ResultCommitment.wrap(keccak256(resultBlob.data));
        ResultCommitment existingCommitment = marketResults[marketCommitment];
        // TODO: add library for operations
        if (ResultCommitment.unwrap(existingCommitment) == ResultCommitment.unwrap(resultCommitment)) {
            return;
        }
        if (ResultCommitment.unwrap(existingCommitment) != bytes32(0)) {
            revert MarketsResultAlreadyRevealed(marketCommitment, existingCommitment);
        }
        // hook for implementation to verify that the result makes sense given all the bets
        _verifyResult(marketBlob, resultBlob);

        marketResults[marketCommitment] = resultCommitment;
    }

    /**
     * Reveal a bet to claim any payout
     */
    function revealBet(MarketBlob calldata marketBlob, ResultBlob calldata resultBlob, BetBlob calldata betBlob)
        public
        returns (IERC20 token, address to, uint256 amount)
    {
        // TODO: verify market and result match their commitments
        // TODO: think about re-entrancy
        // TODO: think about repeated payouts for same bet

        (token, to, amount) = _getPayout(marketBlob, resultBlob, betBlob);
        if (amount > 0) {
            token.safeTransfer(to, amount);
        }
    }

    /**
     * Hook to derive the payout from the bet blob
     */
    function _getPayout(MarketBlob calldata marketBlob, ResultBlob calldata resultBlob, BetBlob calldata betBlob)
        internal
        view
        virtual
        returns (IERC20 token, address to, uint256 amount);

    /**
     * Hook that raises an error if the result does not make sense (e.g. total potential payout amount is wrong)
     */
    function _verifyResult(MarketBlob calldata marketBlob, ResultBlob calldata resultBlob) internal view virtual;
}

contract Markets is MarketsBase {
    struct MarketInfo {
        address creator;
        uint256 deadline; // TODO: block or timestamp?
        /**
         * Non-sequential market id decided off-chain
         */
        uint256 marketId;
    }

    // TODO: call it BetBlob?
    struct BetHiddenInfo {
        MarketCommitment MarketCommitment;
        uint256 option;
        /**
         * random salt to ensure hash cannot be predicted
         */
        uint256 salt;
    }

    function _getPayout(MarketBlob calldata marketBlob, ResultBlob calldata resultBlob, BetBlob calldata betBlob)
        internal
        view
        override
        returns (IERC20 token, address to, uint256 amount)
    {
        // TODO: decode betBlob,
        // get normalization factor from result blob
        // TODO: might not need marketBlob here?
    }

    function _verifyResult(MarketBlob calldata marketBlob, ResultBlob calldata resultBlob) internal view override { }
}
