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
     * Divisor used in fee calculations. Larger than can fit uint16, since fees are always less than 1
     */
    uint256 public constant FEE_DIVISOR = 10 ** 5;
    /**
     * Addresses that are trusted to sign bet requests
     */
    bytes32 public constant BET_SIGNATURE_ROLE = keccak256("BET_SIGNATURE_ROLE");
    /**
     * Addresses that are trusted to sign market results
     */
    bytes32 public constant RESULT_SIGNATURE_ROLE = keccak256("RESULT_SIGNATURE_ROLE");
    /**
     * Addresses that are trusted to distribute operator fees
     */
    bytes32 public constant OPERATOR_FEE_DISTRIBUTOR_ROLE = keccak256("OPERATOR_FEE_DISTRIBUTOR_ROLE");

    mapping(MarketCommitment => ResultCommitment) public marketResults;
    mapping(RequestCommitment => BetState) public bets;
    /**
     * All collected fees for a token and address
     */
    mapping(IERC20 => mapping(address => uint256)) public creatorFees;
    mapping(IERC20 => uint256) public operatorFees;
    uint16 public creatorFeeDecimal;
    uint16 public operatorFeeDecimal;

    /**
     * Increments every time a user places a bet
     */
    mapping(address => uint256) public userNonces;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function setFees(uint16 _creatorFeeDecimal, uint16 _operatorFeeDecimal) external onlyRole(DEFAULT_ADMIN_ROLE) {
        creatorFeeDecimal = _creatorFeeDecimal;
        operatorFeeDecimal = _operatorFeeDecimal;
        // TODO: emit event?
    }

    /**
     * @inheritdoc IMarkets
     */
    function placeBet(BetRequest calldata bet, bytes calldata /* requestSignature */ ) external {
        require(_msgSender() == bet.from, MarketsWrongSender(_msgSender()));

        RequestCommitment requestCommitment = RequestCommitment.wrap(keccak256(abi.encode(bet)));

        // TODO: uncomment signature verification later. Excluding it for now for easier integration
        // address signerAddress = ECDSA.recover(RequestCommitment.unwrap(requestCommitment), requestSignature);
        // _checkRole(BET_SIGNATURE_ROLE, signerAddress);

        // Check user nonce to avoid replay attacks
        uint256 expectedNonce = userNonces[bet.from];
        require(bet.nonce == expectedNonce, MarketsInvalidUserNonce(bet.from, expectedNonce, bet.nonce));

        _verifyRequest(bet, requestCommitment);

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
    function batchRevealBet(
        MarketBlob calldata marketBlob,
        ResultBlob calldata resultBlob,
        BetRequest[] calldata requests,
        BetBlob[] calldata betBlobs
    ) external {
        require(requests.length == betBlobs.length, MarketsBetInvalidBatchReveal());

        for (uint256 i = 0; i < requests.length; i++) {
            revealBet(marketBlob, resultBlob, requests[i], betBlobs[i]);
        }
    }

    /**
     * Withdraw any fees on behalf of a user
     */
    function withdrawCreatorFees(IERC20[] calldata tokens, address[] calldata users) external {
        for (uint256 i = 0; i < tokens.length; i++) {
            IERC20 token = tokens[i];
            mapping(address => uint256) storage tokenFees = creatorFees[token];

            for (uint256 u = 0; u < users.length; u++) {
                address user = users[u];
                uint256 amount = tokenFees[user];
                if (amount > 0) {
                    tokenFees[user] = 0;
                    token.safeTransfer(user, amount);
                }
            }
        }
    }

    function distributeOperatorFees(FeeDistributionRequest[] calldata requests)
        external
        onlyRole(OPERATOR_FEE_DISTRIBUTOR_ROLE)
    {
        for (uint256 i = 0; i < requests.length; i++) {
            FeeDistributionRequest calldata request = requests[i];
            IERC20 token = request.token;
            uint256 totalFeesAvailable = operatorFees[token];
            require(request.users.length == request.amounts.length, MarketsFeeDistributionRequestInvalid());

            uint256 totalTaken = 0;
            for (uint256 u = 0; u < request.users.length; u++) {
                address user = request.users[u];
                uint256 amount = request.amounts[u];
                totalTaken += amount;
                token.safeTransfer(user, amount);
            }

            require(
                totalTaken <= totalFeesAvailable, MarketsNotEnoughOperatorFees(token, totalFeesAvailable, totalTaken)
            );
            // TODO: prevent re-entrancy attack where distribute is called
            // recursively twice for half the amount. The side effect below will
            // "reset" the available fees like only half was withdrawn
            operatorFees[token] = totalFeesAvailable - totalTaken;
        }
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
        token = request.token;
        to = request.from;
        address creator;
        (amount, creator) = _getPayout(marketBlob, resultBlob, request, betBlob);
        if (amount > 0) {
            // fee can be taken out here as percentage of amount. If we assume
            // fees are taken as a percentage of every bet, then taking the same
            // percentage of every bettor's winnings is the same as doing it on the
            // whole pool.
            uint256 creatorFee = (creatorFeeDecimal * amount) / FEE_DIVISOR;
            uint256 operatorFee = (operatorFeeDecimal * amount) / FEE_DIVISOR;
            creatorFees[token][creator] += creatorFee;
            operatorFees[token] += operatorFee;
            emit MarketsBetFeeCollected(marketCommitment, token, creator, creatorFee, operatorFee);
            amount -= (creatorFee + operatorFee);

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
    ) internal view virtual returns (uint256 amount, address creator);

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
