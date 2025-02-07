// solhint-disable one-contract-per-file
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Context } from "@openzeppelin/contracts/utils/Context.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";

import { UD60x18, ud60x18, unwrap } from "@prb/math/UD60x18.sol";

// TODO: split among more files

/**
 * Some implementation defined blob describing hidden info of a market. Struct is there for strong type safety.
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

ResultCommitment constant nullResultCommitment = ResultCommitment.wrap(bytes32(0));

/**
 * Some implementation defined blob describing hidden info of bet
 */
struct BetBlob {
    bytes data;
}

type BetCommitment is bytes32;

function betCommitmentEq(BetCommitment a, BetCommitment b) pure returns (bool) {
    return BetCommitment.unwrap(a) == BetCommitment.unwrap(b);
}

function resultCommitmentEq(ResultCommitment a, ResultCommitment b) pure returns (bool) {
    return ResultCommitment.unwrap(a) == ResultCommitment.unwrap(b);
}

function marketCommitmentEq(MarketCommitment a, MarketCommitment b) pure returns (bool) {
    return MarketCommitment.unwrap(a) == MarketCommitment.unwrap(b);
}

function betCommitmentNeq(BetCommitment a, BetCommitment b) pure returns (bool) {
    return BetCommitment.unwrap(a) != BetCommitment.unwrap(b);
}

function resultCommitmentNeq(ResultCommitment a, ResultCommitment b) pure returns (bool) {
    return ResultCommitment.unwrap(a) != ResultCommitment.unwrap(b);
}

function marketCommitmentNeq(MarketCommitment a, MarketCommitment b) pure returns (bool) {
    return MarketCommitment.unwrap(a) != MarketCommitment.unwrap(b);
}

using { betCommitmentEq as ==, betCommitmentNeq as != } for BetCommitment global;

using { resultCommitmentEq as ==, resultCommitmentNeq as != } for ResultCommitment global;

using { marketCommitmentEq as ==, marketCommitmentNeq as != } for MarketCommitment global;

interface MarketsErrors {
    error MarketsWrongSender(address sender);
    error MarketsInvalidUserNonce(address user, uint256 nonce);

    error MarketsResultAlreadyRevealed(MarketCommitment marketCommitment, ResultCommitment resultCommitment);
    error MarketsResultTooEarly(MarketCommitment marketCommitment, uint256 blockNumber);
    error MarketsInvalidResult(MarketCommitment marketCommitment, ResultCommitment resultCommitment);

    error MarketsInconsistentResult(MarketCommitment marketCommitment, ResultCommitment resultCommitment);
}

// TODO: ERC2771 Context? for metatx
abstract contract MarketsBase is Context, MarketsErrors, AccessControl {
    using SafeERC20 for IERC20;

    // TODO: Is packing worth it? Measure gas cost
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
    // TODO: refund deadline?

    /**
     * Stored on the blockchain to reference during reveal phase
     */
    struct BetState {
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
    mapping(MarketCommitment => ResultCommitment) public marketResults;
    mapping(BetCommitment => BetState) public bets;

    /**
     * Increments every time a user places a bet
     */
    mapping(address => uint256) public userNonces;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /**
     * Place a bet according to the request, signed offchain by the backend.
     * @param bet the publicly visible bet details
     * @param betCommitment commitment for the hidden portion of bet information
     */
    function placeBet(BetRequest calldata bet, BetCommitment betCommitment) external {
        // TODO: need signature from backend
        if (_msgSender() != bet.from) {
            revert MarketsWrongSender(_msgSender());
        }

        bets[betCommitment] = BetState({ amount: bet.amount });

        // Check user nonce to avoid replay attacks
        uint256 expectedNonce = userNonces[bet.from];
        if (bet.nonce != expectedNonce) {
            revert MarketsInvalidUserNonce(bet.from, bet.nonce);
        }
        userNonces[bet.from]++;

        // TODO: betCommitment must include the BetRequest as part of it - i.e. BetBlob includes BetRequest by default

        // TODO: take care of fees

        // TODO:
        // Need to prevent bets to be entered past the market deadline without revealing the deadline or the market.
        // - if we sign the blob with some specific private key and do ecrecover, we can make backend arbiter of bets.
        //   Therefore need to store AccessControl permissions for addresses
        //   recovered through ecrecover. Can enable several signers to sign

        // TODO: any hooks needed for the derived contract?

        bet.token.safeTransferFrom(bet.from, address(this), bet.amount);

        // TODO: event
    }

    /**
     * Record a market result that can be used during bet reveal to give payouts. Note that if the `marketBlob` is known, anyone can enter the result.
     */
    function revealMarketResult(
        MarketBlob calldata marketBlob,
        ResultBlob calldata resultBlob,
        bytes calldata resultSignature // TODO: this signature should encompass both market and result blobs
    ) external {
        // Should this be an EIP-712 signature?
        // TODO: avoid replay attack if first time rejected

        MarketCommitment marketCommitment = MarketCommitment.wrap(keccak256(marketBlob.data));
        ResultCommitment resultCommitment = ResultCommitment.wrap(keccak256(resultBlob.data));
        address signerAddress = ECDSA.recover(ResultCommitment.unwrap(resultCommitment), resultSignature);
        _checkRole(RESULT_SIGNATURE_ROLE, signerAddress);

        ResultCommitment existingCommitment = marketResults[marketCommitment];
        if (existingCommitment == resultCommitment) {
            return;
        }
        if (existingCommitment != nullResultCommitment) {
            revert MarketsResultAlreadyRevealed(marketCommitment, existingCommitment);
        }
        // hook for implementation to verify that the result makes sense given all the bets
        _verifyResult(marketCommitment, marketBlob, resultCommitment, resultBlob);

        marketResults[marketCommitment] = resultCommitment;

        // TODO: event
    }

    /**
     * Reveal a bet to claim any payout
     */
    function revealBet(MarketBlob calldata marketBlob, ResultBlob calldata resultBlob, BetBlob calldata betBlob)
        public
        returns (IERC20 token, address to, uint256 amount)
    {
        MarketCommitment marketCommitment = MarketCommitment.wrap(keccak256(marketBlob.data));
        ResultCommitment resultCommitment = ResultCommitment.wrap(keccak256(resultBlob.data));
        ResultCommitment existingCommitment = marketResults[marketCommitment];
        if (existingCommitment != resultCommitment) {
            revert MarketsInconsistentResult(marketCommitment, resultCommitment);
        }

        // TODO: think about re-entrancy
        // TODO: think about repeated payouts for same bet

        // TODO: look up bet by commitment

        (token, to, amount) = _getPayout(marketBlob, resultBlob, betBlob);
        if (amount > 0) {
            token.safeTransfer(to, amount);
        }

        // TODO: event
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
    function _verifyResult(
        MarketCommitment marketCommitment,
        MarketBlob calldata marketBlob,
        ResultCommitment resultCommitment,
        ResultBlob calldata resultBlob
    ) internal view virtual;
}

// TODO: rename Parimutuel
contract Markets is MarketsBase {
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

    struct BetInfo {
        BetRequest request;
        BetHiddenInfo hidden;
    }

    constructor(address admin) MarketsBase(admin) { }

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

    function _getPayout(MarketBlob calldata, ResultBlob calldata resultBlob, BetBlob calldata betBlob)
        internal
        pure
        override
        returns (IERC20 token, address to, uint256 amount)
    {
        BetInfo memory betInfo = abi.decode(betBlob.data, (BetInfo));
        ResultInfo memory resultInfo = abi.decode(resultBlob.data, (ResultInfo));

        // TODO: any more sanity checks?

        if (betInfo.hidden.option == resultInfo.winningOption) {
            token = betInfo.request.token;
            to = betInfo.request.from;
            // TODO: take care of fees
            amount = betInfo.request.amount + unwrap(ud60x18(betInfo.request.amount) * resultInfo.normalization);
        }
    }
}
