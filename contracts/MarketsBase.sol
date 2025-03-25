// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Context } from "@openzeppelin/contracts/utils/Context.sol";
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
    nullResultCommitment,
    getCommitment,
    recoverAddress
} from "./Commitments.sol";

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

    /**
     * Safeguard to prevent draining of excess collateral for a market
     */
    mapping(MarketCommitment => uint256) public availableLosingPot;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function setFees(uint16 _creatorFeeDecimal, uint16 _operatorFeeDecimal) external onlyRole(DEFAULT_ADMIN_ROLE) {
        creatorFeeDecimal = _creatorFeeDecimal;
        operatorFeeDecimal = _operatorFeeDecimal;
        emit MarketsFeesChanged(_creatorFeeDecimal, _operatorFeeDecimal);
    }

    /**
     * @inheritdoc IMarkets
     */
    function placeBet(BetRequest calldata bet, bytes calldata requestSignature) external {
        require(_msgSender() == bet.from, MarketsWrongSender(_msgSender()));
        require(address(this) == bet.marketsContract, MarketsWrongContract(bet.marketsContract));

        RequestCommitment requestCommitment = getCommitment(bet);

        address signerAddress = recoverAddress(requestCommitment, requestSignature);
        _checkRole(BET_SIGNATURE_ROLE, signerAddress);

        // Check user nonce to avoid replay attacks
        uint256 expectedNonce = userNonces[bet.from];
        require(bet.nonce == expectedNonce, MarketsInvalidUserNonce(bet.from, expectedNonce, bet.nonce));

        require(
            block.number < bet.submissionDeadlineBlock,
            MarketsSubmissionTooLate(bet.submissionDeadlineBlock, block.number)
        );

        _verifyRequest(bet, requestCommitment);

        // It should not be possible to have bet with the same bet commitment entered already.
        // The commitment includes the nonce, which prevents replay attacks.
        assert(bets[requestCommitment].amount == 0);
        bets[requestCommitment] = BetState({ amount: bet.amount });
        userNonces[bet.from]++;

        bet.token.safeTransferFrom(_msgSender(), address(this), bet.amount);

        emit MarketsBetPlaced(bet);
    }

    /**
     * @inheritdoc IMarkets
     */
    function requestRefund(BetRequest calldata request, BetBlob calldata betBlob)
        external
        returns (IERC20 token, address to, uint256 amount)
    {
        RequestCommitment requestCommitment = getCommitment(request);
        BetState storage betState = bets[requestCommitment];
        require(betState.amount == request.amount, MarketsBetDoesntExist(requestCommitment));
        betState.amount = 0;

        require(
            block.number >= request.refundStartBlock,
            MarketsRefundTooEarly(requestCommitment, request.refundStartBlock, block.number)
        );

        MarketCommitment marketCommitment = _getMarketFromBet(betBlob);
        ResultCommitment resultCommitment = marketResults[marketCommitment];
        require(
            resultCommitment == nullResultCommitment, MarketsResultAlreadyRevealed(marketCommitment, resultCommitment)
        );

        token = request.token;
        to = request.from;
        amount = request.amount;

        token.safeTransfer(to, amount);

        emit MarketsRefundIssued(requestCommitment, marketCommitment, token, to, amount);
    }

    /**
     * @inheritdoc IMarkets
     */
    function revealMarketResult(
        MarketBlob calldata marketBlob,
        ResultBlob calldata resultBlob,
        bytes calldata resultSignature
    ) external {
        MarketCommitment marketCommitment = getCommitment(marketBlob);
        ResultCommitment resultCommitment = getCommitment(resultBlob);
        address signerAddress = recoverAddress(resultCommitment, resultSignature);
        _checkRole(RESULT_SIGNATURE_ROLE, signerAddress);

        ResultCommitment existingCommitment = marketResults[marketCommitment];
        if (existingCommitment == resultCommitment) {
            return;
        }
        require(
            existingCommitment == nullResultCommitment,
            MarketsResultAlreadyRevealed(marketCommitment, existingCommitment)
        );
        // Make sure result blob depends on market. Done here to enforce
        // invariant that resultBlob has to link to marketCommitment. The
        // implementation cannot accidentally leave that out. There is redundant
        // work here, but costs ~2k gas which is small compared to rest of the
        // function
        require(
            marketCommitment == _getMarketFromResult(resultBlob),
            MarketsInvalidResult(marketCommitment, resultCommitment)
        );
        // hook for implementation to verify that the result makes sense given all the bets
        uint256 losingTotalPot = _verifyResult(marketCommitment, marketBlob, resultCommitment, resultBlob);

        marketResults[marketCommitment] = resultCommitment;
        availableLosingPot[marketCommitment] = losingTotalPot;

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
        require(requests.length == betBlobs.length, MarketsInvalidBatchRevealBet());

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
            require(request.users.length == request.amounts.length, MarketsFeeDistributionRequestInvalid());

            uint256 totalTaken = 0;
            for (uint256 u = 0; u < request.users.length; u++) {
                address user = request.users[u];
                uint256 amount = request.amounts[u];
                totalTaken += amount;
                token.safeTransfer(user, amount);
            }

            // Regarding re-entrancy - this function can only be called by a Fee
            // Distributor, so a re-entrancy would have to go through a
            // distributor address.
            // Checking if we have recorded enough in operator fees after the transfer should avoid re-entrancy
            uint256 totalFeesAvailable = operatorFees[token];
            require(
                totalTaken <= totalFeesAvailable, MarketsNotEnoughOperatorFees(token, totalFeesAvailable, totalTaken)
            );
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
        MarketCommitment marketCommitment = getCommitment(marketBlob);
        ResultCommitment resultCommitment = getCommitment(resultBlob);
        {
            ResultCommitment existingCommitment = marketResults[marketCommitment];
            require(
                existingCommitment == resultCommitment, MarketsInconsistentResult(marketCommitment, resultCommitment)
            );
            require(marketCommitment == _getMarketFromBet(betBlob), MarketsInvalidRevealBet());
        }

        RequestCommitment requestCommitment = getCommitment(request);
        {
            BetState storage betState = bets[requestCommitment];
            BetCommitment betCommitment = getCommitment(betBlob);
            require(
                request.betCommitment == betCommitment,
                MarketsInvalidBetRequest(requestCommitment, betCommitment, request.betCommitment)
            );
            require(betState.amount == request.amount, MarketsBetDoesntExist(requestCommitment));

            // Since the bet is revealed, no amount should remain to be revealed
            betState.amount = 0;
        }

        token = request.token;
        to = request.from;
        (uint256 winningPotAmount, uint256 losingPotAmount, uint256 marketDeadlineBlock, address creator) =
            _getPayout(marketBlob, resultBlob, request, betBlob);
        if (request.submissionDeadlineBlock > marketDeadlineBlock) {
            // If bet request somehow had a submission deadline after the market
            // ended, we should just ignore such bets and refund the user (don't punish the user).
            //
            // This is highly dependent on the backend. The market result must
            // not include the money from this bet in its weight calculations,
            // otherwise this would lead to more money leaving the contract than
            // was put in.
            winningPotAmount = request.amount;
            losingPotAmount = 0;
            emit MarketsBetWasPlacedAfterResult(marketCommitment, requestCommitment);
        }
        if (losingPotAmount > 0) {
            uint256 currentlyAvailable = availableLosingPot[marketCommitment];
            require(currentlyAvailable >= losingPotAmount, MarketsInvalidResult(marketCommitment, resultCommitment));
            availableLosingPot[marketCommitment] = currentlyAvailable - losingPotAmount;

            // only charge fees on the losing pot, to discourage markets that
            // are heavily imbalanced. If the losing pot is small (because it's
            // a very unlikely result), then creator fees are also small
            uint256 creatorFee = (creatorFeeDecimal * losingPotAmount) / FEE_DIVISOR;
            uint256 operatorFee = (operatorFeeDecimal * losingPotAmount) / FEE_DIVISOR;
            creatorFees[token][creator] += creatorFee;
            operatorFees[token] += operatorFee;
            emit MarketsBetFeeCollected(marketCommitment, token, creator, creatorFee, operatorFee);
            losingPotAmount -= (creatorFee + operatorFee);
        }

        amount = winningPotAmount + losingPotAmount;
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
     * Hook to derive the payout from the bet blob. The split of the amounts is
     * there for different fees on winning vs losing pots
     * @return winningPotAmount - amount that is refunded back to the user from
     *      the winning pot (0 if they lose, their original amount if they win)
     * @return losingPotAmount - amount distributed from the losing pot
     */
    function _getPayout(
        MarketBlob calldata marketBlob,
        ResultBlob calldata resultBlob,
        BetRequest calldata request,
        BetBlob calldata betBlob
    )
        internal
        view
        virtual
        returns (uint256 winningPotAmount, uint256 losingPotAmount, uint256 marketDeadlineBlock, address creator);

    /**
     * Hook that raises an error if the result does not make sense (e.g. total potential payout amount is wrong).
     * @return losingTotalPot total amount of collateral that can be distributed among winners
     */
    function _verifyResult(
        MarketCommitment marketCommitment,
        MarketBlob calldata marketBlob,
        ResultCommitment resultCommitment,
        ResultBlob calldata resultBlob
    ) internal view virtual returns (uint256 losingTotalPot);

    /**
     * Hook to extract a marketCommitment from a result. Used to enforce that
     * the result blob is dependent on the market blob
     */
    function _getMarketFromResult(ResultBlob calldata resultBlob)
        internal
        pure
        virtual
        returns (MarketCommitment marketCommitment);

    /**
     * Hook to extract a marketCommitment from a bet blob. Used to enforce that
     * the bet blob is dependent on the market blob
     */
    function _getMarketFromBet(BetBlob calldata betBlob)
        internal
        pure
        virtual
        returns (MarketCommitment marketCommitment);
}
