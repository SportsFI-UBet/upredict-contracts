// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

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

struct BetRequest {
    // TODO: need contract address in request to avoid replay attacks on other contracts
    IERC20 token;
    uint96 amount;
    address from; // who is making the bet
    uint96 nonce; // user nonce to prevent replay attack
    /**
     * block deadline when user can submit bet
     */
    uint256 submissionDeadlineBlock;
    /**
     * block when a full refund can be requested. This is to prevent collateral
     * getting stuck in the contract if settlement does not come in time.
     */
    uint256 refundStartBlock;
    /**
     * Commitment for the hidden portion of the bet
     */
    BetCommitment betCommitment;
}

type RequestCommitment is bytes32;

function requestCommitmentEq(RequestCommitment a, RequestCommitment b) pure returns (bool) {
    return RequestCommitment.unwrap(a) == RequestCommitment.unwrap(b);
}

function betCommitmentEq(BetCommitment a, BetCommitment b) pure returns (bool) {
    return BetCommitment.unwrap(a) == BetCommitment.unwrap(b);
}

function resultCommitmentEq(ResultCommitment a, ResultCommitment b) pure returns (bool) {
    return ResultCommitment.unwrap(a) == ResultCommitment.unwrap(b);
}

function marketCommitmentEq(MarketCommitment a, MarketCommitment b) pure returns (bool) {
    return MarketCommitment.unwrap(a) == MarketCommitment.unwrap(b);
}

function requestCommitmentNeq(RequestCommitment a, RequestCommitment b) pure returns (bool) {
    return RequestCommitment.unwrap(a) != RequestCommitment.unwrap(b);
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

using { requestCommitmentEq as ==, requestCommitmentNeq as != } for RequestCommitment global;

using { betCommitmentEq as ==, betCommitmentNeq as != } for BetCommitment global;

using { resultCommitmentEq as ==, resultCommitmentNeq as != } for ResultCommitment global;

using { marketCommitmentEq as ==, marketCommitmentNeq as != } for MarketCommitment global;
