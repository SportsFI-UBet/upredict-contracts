// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Context } from "@openzeppelin/contracts/utils/Context.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";

import { MarketsErrors } from "./MarketsErrors.sol";
import { IMarkets } from "./IMarkets.sol";
import {
    BetRequest,
    RequestCommitment,
    MarketCommitment,
    ResultCommitment,
    BetCommitment,
    MarketBlob,
    ResultBlob,
    BetBlob,
    nullResultCommitment
} from "./Commitments.sol";

// TODO: ERC2771 Context? for metatx
abstract contract MarketsBase is IMarkets, Context, MarketsErrors, AccessControl {
    using SafeERC20 for IERC20;

    /**
     * Stored on the blockchain to reference during reveal phase
     */
    struct BetState {
        uint96 amount;
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
    mapping(RequestCommitment => BetState) public bets;

    /**
     * Increments every time a user places a bet
     */
    mapping(address => uint256) public userNonces;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /**
     * @inheritdoc IMarkets
     */
    function placeBet(BetRequest calldata bet, bytes calldata requestSignature) external {
        require(_msgSender() == bet.from, MarketsWrongSender(_msgSender()));

        RequestCommitment requestCommitment = RequestCommitment.wrap(keccak256(abi.encode(bet)));

        address signerAddress = ECDSA.recover(RequestCommitment.unwrap(requestCommitment), requestSignature);
        _checkRole(BET_SIGNATURE_ROLE, signerAddress);

        // Check user nonce to avoid replay attacks
        uint256 expectedNonce = userNonces[bet.from];
        require(bet.nonce == expectedNonce, MarketsInvalidUserNonce(bet.from, expectedNonce, bet.nonce));

        _verifyRequest(bet, requestCommitment);

        // TODO: take care of fees

        // It should not be possible to have bet with the same bet commitment entered already.
        // The commitment includes the nonce, which prevents replay attacks.
        assert(bets[requestCommitment].amount == 0);
        bets[requestCommitment] = BetState({ amount: bet.amount });
        userNonces[bet.from]++;

        bet.token.safeTransferFrom(bet.from, address(this), bet.amount);

        emit MarketsBetPlaced(bet);
    }

    /**
     * @inheritdoc IMarkets
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
        require(
            existingCommitment == nullResultCommitment,
            MarketsResultAlreadyRevealed(marketCommitment, existingCommitment)
        );
        // hook for implementation to verify that the result makes sense given all the bets
        _verifyResult(marketCommitment, marketBlob, resultCommitment, resultBlob);

        marketResults[marketCommitment] = resultCommitment;

        emit MarketsResultRevealed(marketCommitment, resultCommitment);
    }

    /**
     * @inheritdoc IMarkets
     */
    function revealBet(
        MarketBlob calldata marketBlob,
        ResultBlob calldata resultBlob,
        BetRequest calldata request,
        BetBlob calldata betBlob
    ) public returns (IERC20 token, address to, uint256 amount) {
        MarketCommitment marketCommitment = MarketCommitment.wrap(keccak256(marketBlob.data));
        ResultCommitment resultCommitment = ResultCommitment.wrap(keccak256(resultBlob.data));
        ResultCommitment existingCommitment = marketResults[marketCommitment];
        require(existingCommitment == resultCommitment, MarketsInconsistentResult(marketCommitment, resultCommitment));

        RequestCommitment requestCommitment = RequestCommitment.wrap(keccak256(abi.encode(request)));
        BetCommitment betCommitment = BetCommitment.wrap(keccak256(betBlob.data));
        require(
            request.betCommitment == betCommitment,
            MarketsInvalidBetRequest(requestCommitment, betCommitment, request.betCommitment)
        );

        BetState storage betState = bets[requestCommitment];
        require(betState.amount == request.amount, MarketsBetAlreadyRevealed(betCommitment));
        // Since the bet is revealed, no amount should remain to be revealed
        betState.amount = 0;

        // TODO: make sure the bet has not been entered after reveal (store reveal block)
        // TODO: set money aside for creator and operator fees
        (token, to, amount) = _getPayout(marketBlob, resultBlob, request, betBlob);
        if (amount > 0) {
            token.safeTransfer(to, amount);
        }

        emit MarketsBetRevealed(requestCommitment, marketCommitment, token, to, amount);
    }

    /**
     * Hook to check that request is able to be fulfilled
     */
    function _verifyRequest(BetRequest calldata request, RequestCommitment requestCommitment) internal view virtual;

    /**
     * Hook to derive the payout from the bet blob
     */
    function _getPayout(
        MarketBlob calldata marketBlob,
        ResultBlob calldata resultBlob,
        BetRequest calldata request,
        BetBlob calldata betBlob
    ) internal view virtual returns (IERC20 token, address to, uint256 amount);

    /**
     * Hook that raises an error if the result does not make sense (e.g. total potential payout amount is wrong)
     */
    function _verifyResult(
        MarketCommitment marketCommitment,
        MarketBlob calldata marketBlob,
        ResultCommitment resultCommitment,
        ResultBlob calldata resultBlob
    ) internal view virtual;

    // TODO: distribute operator fees batch call
}
