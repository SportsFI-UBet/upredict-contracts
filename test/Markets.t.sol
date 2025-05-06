// solhint-disable one-contract-per-file
// solhint-disable ordering
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Vm, Test } from "forge-std/Test.sol";

import { IERC20, ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";

import { DeployTestnet } from "../script/Deploy.s.sol";
import { IMarkets } from "../contracts/IMarkets.sol";
import { MarketsErrors } from "../contracts/MarketsErrors.sol";
import {
    BetRequest,
    RequestCommitment,
    MarketCommitment,
    ResultCommitment,
    BetCommitment,
    MarketBlob,
    ResultBlob,
    BetBlob,
    getCommitment
} from "../contracts/Commitments.sol";
import { WeightedParimutuelMarkets, MarketsBase } from "../contracts/WeightedParimutuelMarkets.sol";
import { TestERC20 } from "../contracts/testnet/Token.sol";

/**
 * Malicious ERC20 that executes another call on transfer
 */
contract ReentryERC20 is TestERC20 {
    using Address for address;

    struct ReentryParams {
        /**
         * What address triggers the re-entry
         */
        address senderTrigger;
        /**
         * Which address would we re-enter through. For tests this is simulated
         * through "vm.prank" but in real world this would mean the pretend address
         * has to be another malicious contract.
         */
        address newSenderAddress;
        /**
         * The contract that will be called for re-entry
         */
        address contractAddress;
        /**
         * What call to make on the contract
         */
        bytes call;
        Vm vm;
    }

    /**
     * State that makes sure we only attempt re-entry once
     */
    bool public hasReentered;
    ReentryParams public params;

    constructor() {
        hasReentered = true;
    }

    function setParams(ReentryParams memory params_) external {
        hasReentered = false;
        params = params_;
    }

    function _update(address from, address to, uint256 value) internal override {
        ERC20._update(from, to, value);
        // execute re-entrancy
        if (_msgSender() == params.senderTrigger && !hasReentered) {
            hasReentered = true;
            params.vm.prank(params.newSenderAddress);
            params.contractAddress.functionCall(params.call);
        }
    }
}

contract MarketsTest is Test, DeployTestnet {
    address public admin;
    address public alice;
    address public bob;
    address public carol;
    address public creator;
    address public betSigner;
    uint256 public betSignerPrivateKey;
    address public resultSigner;
    uint256 public resultSignerPrivateKey;
    address public operatorFeeDistributor;

    uint256 public marketDeadlineBlock;
    uint256 public submissionDeadlineBlock;
    uint256 public refundStartBlock;

    using MessageHashUtils for bytes32;

    function setUpUpgradeScripts() internal override {
        // Ignore any deploy-latest files for anvil
        UPGRADE_SCRIPTS_BYPASS = true;
    }

    function setUp() public {
        admin = makeAddr("admin");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        carol = makeAddr("carol");
        creator = makeAddr("creator");
        admin = makeAddr("admin");
        (resultSigner, resultSignerPrivateKey) = makeAddrAndKey("result-signer");
        (betSigner, betSignerPrivateKey) = makeAddrAndKey("bet-signer");
        operatorFeeDistributor = makeAddr("operator-fee-distributor");

        DeployTestnet.setUpContracts(admin);

        submissionDeadlineBlock = block.number + 100;
        marketDeadlineBlock = block.number + 1000;
        refundStartBlock = marketDeadlineBlock + 1000;

        // Set up permissions
        bytes32 role = markets.RESULT_SIGNATURE_ROLE();
        vm.prank(admin);
        markets.grantRole(role, resultSigner);

        role = markets.BET_SIGNATURE_ROLE();
        vm.prank(admin);
        markets.grantRole(role, betSigner);

        role = markets.OPERATOR_FEE_DISTRIBUTOR_ROLE();
        vm.prank(admin);
        markets.grantRole(role, operatorFeeDistributor);
    }

    function signCommitment(uint256 privateKey, bytes32 commitment) public pure returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, commitment.toEthSignedMessageHash());
        sig = abi.encodePacked(r, s, v); // as detailed in Openzeppelin ECDSA.recover
    }

    function signResultCommitment(ResultCommitment commitment) public view returns (bytes memory) {
        return signCommitment(resultSignerPrivateKey, ResultCommitment.unwrap(commitment));
    }

    function signRequestCommitment(RequestCommitment commitment) public view returns (bytes memory) {
        return signCommitment(betSignerPrivateKey, RequestCommitment.unwrap(commitment));
    }

    function signRequest(BetRequest memory request) public view returns (bytes memory) {
        return signRequestCommitment(RequestCommitment.wrap(keccak256(abi.encode(request))));
    }

    function preparePlaceBet(address user, BetRequest memory request) public returns (bytes memory signature) {
        erc20.mint(user, request.amount);
        vm.prank(user);
        erc20.approve(address(markets), request.amount);

        signature = signRequest(request);
    }

    function placeBet(address user, BetRequest memory request) public {
        bytes memory signature = preparePlaceBet(user, request);

        vm.expectEmit(false, false, false, true);
        emit IMarkets.MarketsBetPlaced(request);
        vm.prank(user);
        markets.placeBet(request, signature);
    }

    struct MarketContext {
        WeightedParimutuelMarkets.MarketInfo marketInfo;
        MarketBlob marketBlob;
        MarketCommitment marketCommitment;
    }

    function makeMarketContext(uint256 marketId, uint256 numOutcomes) public view returns (MarketContext memory) {
        WeightedParimutuelMarkets.MarketInfo memory marketInfo = WeightedParimutuelMarkets.MarketInfo({
            creator: creator,
            deadlineBlock: marketDeadlineBlock,
            marketId: marketId,
            numOutcomes: numOutcomes
        });
        MarketBlob memory marketBlob = MarketBlob({ data: abi.encode(marketInfo) });
        MarketCommitment marketCommitment = MarketCommitment.wrap(keccak256(marketBlob.data));

        return MarketContext({ marketInfo: marketInfo, marketBlob: marketBlob, marketCommitment: marketCommitment });
    }

    function makeMarketContext() public view returns (MarketContext memory) {
        return makeMarketContext(0x42, 2);
    }

    struct BetContext {
        WeightedParimutuelMarkets.BetHiddenInfo betInfo;
        BetBlob betBlob;
        BetRequest request;
        RequestCommitment requestCommitment;
    }

    function makeBetContext(
        address user,
        uint256 amount,
        uint256 outcome,
        uint256 nonce,
        MarketCommitment marketCommitment,
        uint256 weight
    ) public view returns (BetContext memory) {
        WeightedParimutuelMarkets.BetHiddenInfo memory betInfo = WeightedParimutuelMarkets.BetHiddenInfo({
            marketCommitment: marketCommitment,
            outcome: outcome,
            betWeight: weight,
            salt: 0x42
        });
        BetBlob memory betBlob = BetBlob({ data: abi.encode(betInfo) });
        BetRequest memory request = BetRequest({
            marketsContract: address(markets),
            token: erc20,
            amount: uint96(amount),
            from: user,
            nonce: uint96(nonce),
            submissionDeadlineBlock: submissionDeadlineBlock,
            refundStartBlock: refundStartBlock,
            betCommitment: BetCommitment.wrap(keccak256(betBlob.data))
        });
        RequestCommitment requestCommitment = RequestCommitment.wrap(keccak256(abi.encode(request)));

        return
            BetContext({ betInfo: betInfo, betBlob: betBlob, request: request, requestCommitment: requestCommitment });
    }

    function makeBetContext(
        address user,
        uint256 amount,
        uint256 outcome,
        uint256 nonce,
        MarketCommitment marketCommitment
    ) public view returns (BetContext memory) {
        return makeBetContext(user, amount, outcome, nonce, marketCommitment, amount);
    }

    function prepareRevealResult(WeightedParimutuelMarkets.ResultInfo memory resultInfo)
        public
        view
        returns (ResultBlob memory resultBlob, ResultCommitment resultCommitment, bytes memory resultSignature)
    {
        resultBlob = ResultBlob({ data: abi.encode(resultInfo) });
        resultCommitment = ResultCommitment.wrap(keccak256(resultBlob.data));

        resultSignature = signResultCommitment(resultCommitment);
    }

    function revealResult(MarketContext memory marketContext, WeightedParimutuelMarkets.ResultInfo memory resultInfo)
        public
        returns (ResultBlob memory resultBlob, ResultCommitment resultCommitment, bytes memory resultSignature)
    {
        (resultBlob, resultCommitment, resultSignature) = prepareRevealResult(resultInfo);

        vm.roll(marketDeadlineBlock + 1);
        vm.expectEmit(true, false, false, true);
        emit IMarkets.MarketsResultRevealed(marketContext.marketCommitment, resultCommitment);
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);
    }

    function testEndToEnd() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);

        // Approve erc20 and make bet
        placeBet(alice, aliceBetContext.request);
        vm.assertEq(erc20.balanceOf(alice), 0, "Amount taken for bet");

        // Prepare bob to bet
        BetContext memory bobBetContext = makeBetContext(bob, 20e18, 0, 0, marketContext.marketCommitment);

        placeBet(bob, bobBetContext.request);
        vm.assertEq(erc20.balanceOf(bob), 0, "Amount taken for bet");

        // Reveal market result
        (ResultBlob memory resultBlob,,) = revealResult(
            marketContext,
            WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome, // alice should win
                losingTotalPot: bobBetContext.request.amount,
                winningTotalWeight: aliceBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            })
        );

        // Reveal each bet. Alice should get back the whole pot
        uint256 totalBetAmount = bobBetContext.request.amount + aliceBetContext.request.amount;
        vm.assertEq(erc20.balanceOf(address(markets)), totalBetAmount, "All money is in pool");

        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(bobBetContext.requestCommitment, marketContext.marketCommitment, erc20, bob, 0);
        markets.revealBet(marketContext.marketBlob, resultBlob, bobBetContext.request, bobBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), totalBetAmount);
        vm.assertEq(erc20.balanceOf(address(bob)), 0, "Bob did not win");

        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(
            aliceBetContext.requestCommitment, marketContext.marketCommitment, erc20, alice, totalBetAmount
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), 0, "Alice claimed her winnings");
        vm.assertEq(erc20.balanceOf(address(alice)), totalBetAmount, "Alice received her winnings");
    }

    function testBetLimits(uint256 lowerLimit, uint256 upperLimit) public {
        lowerLimit = bound(lowerLimit, 2, type(uint96).max - 1);
        upperLimit = bound(upperLimit, lowerLimit, type(uint96).max - 1);
        MarketContext memory marketContext = makeMarketContext();

        // Change limits
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, alice, bytes32(0))
        );
        markets.setLimits(lowerLimit, upperLimit);

        vm.prank(admin);
        markets.setLimits(lowerLimit, upperLimit);

        // Approve markets for infinity
        uint256 amount = lowerLimit;
        erc20.mint(alice, amount);
        vm.prank(alice);
        erc20.approve(address(markets), type(uint256).max);

        // Prepare alice to bet
        BetContext memory aliceBetContext = makeBetContext(alice, amount, 1, 0, marketContext.marketCommitment);

        // Staying within limits works
        vm.prank(alice);
        markets.placeBet(aliceBetContext.request, signRequestCommitment(aliceBetContext.requestCommitment));

        // Going below reverts
        amount = lowerLimit - 1;
        aliceBetContext = makeBetContext(alice, amount, 1, 1, marketContext.marketCommitment);

        vm.expectRevert(
            abi.encodeWithSelector(
                WeightedParimutuelMarkets.MarketsBetRequestOutsideLimits.selector,
                aliceBetContext.requestCommitment,
                amount
            )
        );
        vm.prank(alice);
        markets.placeBet(aliceBetContext.request, signRequestCommitment(aliceBetContext.requestCommitment));

        // Going above reverts
        amount = upperLimit + 1;
        aliceBetContext = makeBetContext(alice, amount, 1, 1, marketContext.marketCommitment);

        vm.expectRevert(
            abi.encodeWithSelector(
                WeightedParimutuelMarkets.MarketsBetRequestOutsideLimits.selector,
                aliceBetContext.requestCommitment,
                amount
            )
        );
        vm.prank(alice);
        markets.placeBet(aliceBetContext.request, signRequestCommitment(aliceBetContext.requestCommitment));
    }

    function testEndToEndWeighted() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet, give her weight of 3
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment, 3);

        // Approve erc20 and make bet
        placeBet(alice, aliceBetContext.request);
        vm.assertEq(erc20.balanceOf(alice), 0, "Amount taken for bet");

        // Bob bets, weight of 2
        BetContext memory bobBetContext = makeBetContext(bob, 20e18, 0, 0, marketContext.marketCommitment, 2);

        placeBet(bob, bobBetContext.request);
        vm.assertEq(erc20.balanceOf(bob), 0, "Amount taken for bet");

        // Carol bets, weight of 1
        BetContext memory carolBetContext = makeBetContext(carol, 10e18, 1, 0, marketContext.marketCommitment, 1);
        placeBet(carol, carolBetContext.request);

        // Reveal market result
        (ResultBlob memory resultBlob,,) = revealResult(
            marketContext,
            WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome, // alice and carol should win
                losingTotalPot: bobBetContext.request.amount,
                winningTotalWeight: aliceBetContext.betInfo.betWeight + carolBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            })
        );

        // Reveal each bet. Alice should get back 3/4 of whole pot
        uint256 totalBetAmount =
            bobBetContext.request.amount + aliceBetContext.request.amount + carolBetContext.request.amount;
        vm.assertEq(erc20.balanceOf(address(markets)), totalBetAmount, "All money is in pool");

        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(bobBetContext.requestCommitment, marketContext.marketCommitment, erc20, bob, 0);
        markets.revealBet(marketContext.marketBlob, resultBlob, bobBetContext.request, bobBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), totalBetAmount);
        vm.assertEq(erc20.balanceOf(address(bob)), 0, "Bob did not win");

        uint256 aliceWinnings = aliceBetContext.request.amount + bobBetContext.request.amount * 3 / 4;
        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(
            aliceBetContext.requestCommitment, marketContext.marketCommitment, erc20, alice, aliceWinnings
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), totalBetAmount - aliceWinnings, "Alice claimed her winnings");
        vm.assertEq(erc20.balanceOf(address(alice)), aliceWinnings, "Alice received her winnings");

        uint256 carolWinnings = carolBetContext.request.amount + bobBetContext.request.amount / 4;
        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(
            carolBetContext.requestCommitment, marketContext.marketCommitment, erc20, carol, carolWinnings
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, carolBetContext.request, carolBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), 0, "Carol claimed her winnings");
        vm.assertEq(erc20.balanceOf(address(carol)), carolWinnings, "Carol received her winnings");
    }

    function testAbandonBet() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);

        // Approve erc20 and make bet
        placeBet(alice, aliceBetContext.request);
        vm.assertEq(erc20.balanceOf(alice), 0, "Amount taken for bet");

        // Prepare bob to bet, but abandon his bet
        BetContext memory bobBetContext = makeBetContext(bob, 20e18, 0, 0, marketContext.marketCommitment);

        // Reveal market result
        (ResultBlob memory resultBlob,,) = revealResult(
            marketContext,
            WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome, // alice should win
                losingTotalPot: 0,
                winningTotalWeight: aliceBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            })
        );

        // Reveal bets
        vm.assertEq(erc20.balanceOf(address(markets)), aliceBetContext.request.amount, "Alice's money is in pool");

        // Bob's reveal should fail
        vm.expectRevert(
            abi.encodeWithSelector(MarketsErrors.MarketsBetDoesntExist.selector, bobBetContext.requestCommitment)
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, bobBetContext.request, bobBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), aliceBetContext.request.amount);
        vm.assertEq(erc20.balanceOf(address(bob)), 0, "Bob did not win");

        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(
            aliceBetContext.requestCommitment,
            marketContext.marketCommitment,
            erc20,
            alice,
            aliceBetContext.request.amount
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), 0, "Alice claimed her winnings");
        vm.assertEq(erc20.balanceOf(address(alice)), aliceBetContext.request.amount, "Alice just gets her money back");
    }

    function testWrongSender() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);

        // Approve erc20 but bet from another account
        bytes memory signature = preparePlaceBet(alice, aliceBetContext.request);

        vm.expectRevert(abi.encodeWithSelector(MarketsErrors.MarketsWrongSender.selector, bob));
        vm.prank(bob);
        markets.placeBet(aliceBetContext.request, signature);
    }

    function testZeroAmountBet() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        BetContext memory aliceBetContext = makeBetContext(alice, 0, 1, 0, marketContext.marketCommitment);
        bytes memory signature = preparePlaceBet(alice, aliceBetContext.request);

        vm.expectRevert(abi.encodeWithSelector(MarketsErrors.MarketsInvalidBetAmount.selector, 0));
        vm.prank(alice);
        markets.placeBet(aliceBetContext.request, signature);
    }

    function testWrongContract() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare request for a different contract
        WeightedParimutuelMarkets originalMarkets = markets;
        markets = new WeightedParimutuelMarkets(admin);
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);

        bytes memory signature = preparePlaceBet(alice, aliceBetContext.request);

        vm.expectRevert(abi.encodeWithSelector(MarketsErrors.MarketsWrongContract.selector, markets));
        vm.prank(alice);
        originalMarkets.placeBet(aliceBetContext.request, signature);
    }

    function testReplay() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        // Approve again, but fail due to repeated nonce
        bytes memory signature = preparePlaceBet(alice, aliceBetContext.request);

        vm.expectRevert(abi.encodeWithSelector(MarketsErrors.MarketsInvalidUserNonce.selector, alice, 1, 0));
        vm.prank(alice);
        markets.placeBet(aliceBetContext.request, signature);
    }

    function testReplayAfterReveal() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        // Reveal market result and Alice bet
        (ResultBlob memory resultBlob,,) = revealResult(
            marketContext,
            WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome,
                losingTotalPot: 0,
                winningTotalWeight: aliceBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            })
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);

        // Approve again, but fail due to repeated nonce
        bytes memory signature = preparePlaceBet(alice, aliceBetContext.request);

        vm.expectRevert(abi.encodeWithSelector(MarketsErrors.MarketsInvalidUserNonce.selector, alice, 1, 0));
        vm.prank(alice);
        markets.placeBet(aliceBetContext.request, signature);
    }

    function testSubmissionTooLate(uint256 blocksPastDeadline) public {
        blocksPastDeadline = bound(blocksPastDeadline, 0, 1000);
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);

        // Approve but submit too late
        bytes memory signature = preparePlaceBet(alice, aliceBetContext.request);

        vm.roll(submissionDeadlineBlock + blocksPastDeadline);
        vm.expectRevert(
            abi.encodeWithSelector(
                MarketsErrors.MarketsSubmissionTooLate.selector,
                submissionDeadlineBlock,
                submissionDeadlineBlock + blocksPastDeadline
            )
        );
        vm.prank(alice);
        markets.placeBet(aliceBetContext.request, signature);
    }

    function testRefund(uint256 aliceAmount) public {
        MarketContext memory marketContext = makeMarketContext();

        aliceAmount = bound(aliceAmount, 1e6, 10e18);
        BetContext memory aliceBetContext = makeBetContext(alice, aliceAmount, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        // Too early to refund
        vm.expectRevert(
            abi.encodeWithSelector(
                MarketsErrors.MarketsRefundTooEarly.selector,
                aliceBetContext.requestCommitment,
                refundStartBlock,
                block.number
            )
        );
        markets.requestRefund(aliceBetContext.request, aliceBetContext.betBlob);

        // Still too early to refund
        vm.roll(refundStartBlock - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                MarketsErrors.MarketsRefundTooEarly.selector,
                aliceBetContext.requestCommitment,
                refundStartBlock,
                block.number
            )
        );
        markets.requestRefund(aliceBetContext.request, aliceBetContext.betBlob);

        // Can refund
        vm.assertEq(erc20.balanceOf(alice), 0, "Alice doesn't have any money");
        vm.roll(refundStartBlock);
        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsRefundIssued(
            aliceBetContext.requestCommitment, marketContext.marketCommitment, erc20, alice, aliceAmount
        );
        vm.prank(bob); // can be on someone else's behalf
        markets.requestRefund(aliceBetContext.request, aliceBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(alice), aliceAmount, "Alice gets full refund");

        // Can't refund twice
        vm.roll(refundStartBlock);
        vm.expectRevert(
            abi.encodeWithSelector(MarketsErrors.MarketsBetDoesntExist.selector, aliceBetContext.requestCommitment)
        );
        markets.requestRefund(aliceBetContext.request, aliceBetContext.betBlob);
    }

    function testRefundBetZeroAmount() public {
        MarketContext memory marketContext = makeMarketContext();

        uint256 betAmount = 0;
        BetContext memory aliceBetContext = makeBetContext(alice, betAmount, 1, 0, marketContext.marketCommitment);

        // Bet doesn't exist
        vm.roll(refundStartBlock);
        vm.expectRevert(abi.encodeWithSelector(MarketsErrors.MarketsInvalidBetAmount.selector, 0));
        markets.requestRefund(aliceBetContext.request, aliceBetContext.betBlob);
    }

    function testRefundBetDoesntExist(uint256 aliceAmount) public {
        MarketContext memory marketContext = makeMarketContext();

        aliceAmount = bound(aliceAmount, 1e6, 10e18);
        BetContext memory aliceBetContext = makeBetContext(alice, aliceAmount, 1, 0, marketContext.marketCommitment);

        // Bet doesn't exist
        vm.roll(refundStartBlock);
        vm.expectRevert(
            abi.encodeWithSelector(MarketsErrors.MarketsBetDoesntExist.selector, aliceBetContext.requestCommitment)
        );
        markets.requestRefund(aliceBetContext.request, aliceBetContext.betBlob);
    }

    function testRefundAfterMarketResult(uint256 aliceAmount) public {
        MarketContext memory marketContext = makeMarketContext();

        aliceAmount = bound(aliceAmount, 1e6, 10e18);
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        (, ResultCommitment resultCommitment,) = revealResult(
            marketContext,
            WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome,
                losingTotalPot: 0,
                winningTotalWeight: aliceBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            })
        );

        // Cannot refund after market result already revealed
        vm.roll(refundStartBlock);
        vm.expectRevert(
            abi.encodeWithSelector(
                MarketsErrors.MarketsResultAlreadyRevealed.selector, marketContext.marketCommitment, resultCommitment
            )
        );
        markets.requestRefund(aliceBetContext.request, aliceBetContext.betBlob);
    }

    function testRevealResultIdempotent() public {
        MarketContext memory marketContext = makeMarketContext();

        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        // Reveal market result
        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome,
            losingTotalPot: 0,
            winningTotalWeight: aliceBetContext.betInfo.betWeight,
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob,, bytes memory resultSignature) = revealResult(marketContext, resultInfo);

        // Revealing again should not revert
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);
    }

    function testRevealResultCannotBeOverriden() public {
        MarketContext memory marketContext = makeMarketContext();

        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        // Reveal market result
        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome,
            losingTotalPot: 0,
            winningTotalWeight: aliceBetContext.betInfo.betWeight,
            marketCommitment: marketContext.marketCommitment
        });
        (, ResultCommitment resultCommitment,) = revealResult(marketContext, resultInfo);

        // Revealing different result should fail
        {
            resultInfo.losingTotalPot = 100;
            (ResultBlob memory resultBlob,, bytes memory resultSignature) = prepareRevealResult(resultInfo);

            vm.expectRevert(
                abi.encodeWithSelector(
                    MarketsErrors.MarketsResultAlreadyRevealed.selector,
                    marketContext.marketCommitment,
                    resultCommitment
                )
            );
            markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);
        }
    }

    function testRevealResultWrongMarket() public {
        MarketContext memory marketContext = makeMarketContext();

        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome,
            losingTotalPot: 0,
            winningTotalWeight: aliceBetContext.betInfo.betWeight,
            marketCommitment: MarketCommitment.wrap(bytes32(uint256(0x42)))
        });
        // Revealing result for wrong market should fail
        {
            (ResultBlob memory resultBlob, ResultCommitment resultCommitment, bytes memory resultSignature) =
                prepareRevealResult(resultInfo);

            vm.expectRevert(
                abi.encodeWithSelector(
                    MarketsErrors.MarketsInvalidResult.selector, marketContext.marketCommitment, resultCommitment
                )
            );
            markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);
        }
    }

    function testRevealResultTooEarly() public {
        MarketContext memory marketContext = makeMarketContext();

        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome,
            losingTotalPot: 0,
            winningTotalWeight: aliceBetContext.betInfo.betWeight,
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob,, bytes memory resultSignature) = prepareRevealResult(resultInfo);

        vm.expectRevert(
            abi.encodeWithSelector(
                MarketsErrors.MarketsResultTooEarly.selector, marketContext.marketCommitment, block.number
            )
        );
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);
    }

    function testRevealResultInvalidOutcomeIndex() public {
        MarketContext memory marketContext = makeMarketContext();

        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 0, // empty mask
            losingTotalPot: 0,
            winningTotalWeight: aliceBetContext.betInfo.betWeight,
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob, ResultCommitment resultCommitment, bytes memory resultSignature) =
            prepareRevealResult(resultInfo);

        vm.roll(marketDeadlineBlock + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                MarketsErrors.MarketsInvalidResult.selector, marketContext.marketCommitment, resultCommitment
            )
        );
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);

        // outcome mask outside known outcomes
        resultInfo.winningOutcomeMask = 1 << marketContext.marketInfo.numOutcomes;
        (resultBlob, resultCommitment, resultSignature) = prepareRevealResult(resultInfo);

        vm.expectRevert(
            abi.encodeWithSelector(
                MarketsErrors.MarketsInvalidResult.selector, marketContext.marketCommitment, resultCommitment
            )
        );
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);
    }

    function testRevealResultInvalidMarket() public {
        // Cannot exceed 256 outcomes
        MarketContext memory marketContext = makeMarketContext(0x42, 257);

        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 1,
            losingTotalPot: 0,
            winningTotalWeight: 1,
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob,, bytes memory resultSignature) = prepareRevealResult(resultInfo);

        vm.roll(marketDeadlineBlock + 1);
        vm.expectRevert(
            abi.encodeWithSelector(MarketsErrors.MarketsInvalidMarket.selector, marketContext.marketCommitment)
        );
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);

        // 0 outcomes should also fail
        marketContext = makeMarketContext(0x23, 0);
        resultInfo.marketCommitment = marketContext.marketCommitment;
        (resultBlob,, resultSignature) = prepareRevealResult(resultInfo);
        vm.expectRevert(
            abi.encodeWithSelector(MarketsErrors.MarketsInvalidMarket.selector, marketContext.marketCommitment)
        );
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);

        // 256 outcomes should still work
        marketContext = makeMarketContext(0x23, 256);
        resultInfo.marketCommitment = marketContext.marketCommitment;
        (resultBlob,, resultSignature) = prepareRevealResult(resultInfo);
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);
    }

    function testRevealResultInvalidWinningTotalWeight() public {
        MarketContext memory marketContext = makeMarketContext();

        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome,
            losingTotalPot: 0,
            winningTotalWeight: 0, // invalid weight
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob, ResultCommitment resultCommitment, bytes memory resultSignature) =
            prepareRevealResult(resultInfo);

        vm.roll(marketDeadlineBlock + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                MarketsErrors.MarketsInvalidResult.selector, marketContext.marketCommitment, resultCommitment
            )
        );
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);
    }

    function testRevealResultExplicitRefund(uint256 aliceAmount, uint256 bobAmount) public {
        aliceAmount = bound(aliceAmount, 1000, type(uint96).max);
        bobAmount = bound(bobAmount, 1000, type(uint96).max);
        MarketContext memory marketContext = makeMarketContext();

        // Alice and bob bet
        BetContext memory aliceBetContext = makeBetContext(alice, aliceAmount, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        BetContext memory bobBetContext = makeBetContext(bob, bobAmount, 0, 0, marketContext.marketCommitment);
        placeBet(bob, bobBetContext.request);

        // Winning mask is - "everyone wins", and so is full refund
        uint256 refundMask = (1 << marketContext.marketInfo.numOutcomes) - 1;
        (ResultBlob memory resultBlob,,) = revealResult(
            marketContext,
            WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: refundMask,
                losingTotalPot: 0, // no losers
                winningTotalWeight: 1, // winning weight doesn't matter here
                marketCommitment: marketContext.marketCommitment
            })
        );

        // Reveal each bet. Everyone should get their starting amount
        uint256 totalBetAmount = aliceAmount + bobAmount;
        vm.assertEq(erc20.balanceOf(address(markets)), totalBetAmount, "All money is in pool");

        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(
            aliceBetContext.requestCommitment, marketContext.marketCommitment, erc20, alice, aliceAmount
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), bobAmount, "Market balance without alice refund ");
        vm.assertEq(erc20.balanceOf(address(alice)), aliceAmount, "Alice got refund");

        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(
            bobBetContext.requestCommitment, marketContext.marketCommitment, erc20, bob, bobAmount
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, bobBetContext.request, bobBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), 0);
        vm.assertEq(erc20.balanceOf(address(bob)), bobAmount, "Bob got refund");
    }

    function testRevealResultWeightedTie(
        uint256 aliceAmount,
        uint256 aliceWeight,
        uint256 bobAmount,
        uint256 bobWeight,
        uint256 carolAmount
    ) public {
        aliceAmount = bound(aliceAmount, 1000, type(uint96).max);
        aliceWeight = bound(aliceWeight, 1, 10);

        bobAmount = bound(bobAmount, 1000, type(uint96).max);
        bobWeight = bound(bobWeight, 1, 10);

        carolAmount = bound(carolAmount, 1000, type(uint96).max);
        MarketContext memory marketContext = makeMarketContext(0x42, 3);

        // Alice and bob bet
        BetContext memory aliceBetContext =
            makeBetContext(alice, aliceAmount, 1, 0, marketContext.marketCommitment, aliceWeight);
        placeBet(alice, aliceBetContext.request);

        BetContext memory bobBetContext =
            makeBetContext(bob, bobAmount, 0, 0, marketContext.marketCommitment, bobWeight);
        placeBet(bob, bobBetContext.request);

        BetContext memory carolBetContext = makeBetContext(carol, carolAmount, 2, 0, marketContext.marketCommitment, 10);
        placeBet(carol, carolBetContext.request);

        // Alice and bob share win
        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 0x3, // binary 0b11
            losingTotalPot: carolAmount, // no losers
            winningTotalWeight: aliceWeight + bobWeight,
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob,,) = revealResult(marketContext, resultInfo);

        // Reveal each bet. Everyone should get their starting amount
        {
            uint256 totalBetAmount = aliceAmount + bobAmount + carolAmount;
            vm.assertEq(erc20.balanceOf(address(markets)), totalBetAmount, "All money is in pool");
        }

        {
            uint256 aliceWin = aliceAmount + (carolAmount * aliceWeight) / resultInfo.winningTotalWeight;
            vm.expectEmit(true, true, true, true);
            emit IMarkets.MarketsBetRevealed(
                aliceBetContext.requestCommitment, marketContext.marketCommitment, erc20, alice, aliceWin
            );
            markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);
            vm.assertEq(erc20.balanceOf(address(alice)), aliceWin, "Alice got win");
        }

        {
            uint256 bobWin = bobAmount + (carolAmount * bobWeight) / resultInfo.winningTotalWeight;
            vm.expectEmit(true, true, true, true);
            emit IMarkets.MarketsBetRevealed(
                bobBetContext.requestCommitment, marketContext.marketCommitment, erc20, bob, bobWin
            );
            markets.revealBet(marketContext.marketBlob, resultBlob, bobBetContext.request, bobBetContext.betBlob);
            vm.assertEq(erc20.balanceOf(address(bob)), bobWin, "Bob got win");
        }

        {
            vm.expectEmit(true, true, true, true);
            emit IMarkets.MarketsBetRevealed(
                carolBetContext.requestCommitment, marketContext.marketCommitment, erc20, carol, 0
            );
            markets.revealBet(marketContext.marketBlob, resultBlob, carolBetContext.request, carolBetContext.betBlob);
            vm.assertEq(erc20.balanceOf(address(carol)), 0, "Carol lost");
        }
    }

    function testRevealBetWrongResult() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        // Reveal market result
        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome, // alice should win
            losingTotalPot: 0,
            winningTotalWeight: aliceBetContext.betInfo.betWeight,
            marketCommitment: marketContext.marketCommitment
        });
        revealResult(marketContext, resultInfo);

        // Reveal bet, wrong result
        resultInfo.winningOutcomeMask = 1 << 0;
        (ResultBlob memory resultBlob, ResultCommitment resultCommitment,) = prepareRevealResult(resultInfo);
        vm.expectRevert(
            abi.encodeWithSelector(
                MarketsErrors.MarketsInconsistentResult.selector, marketContext.marketCommitment, resultCommitment
            )
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);
    }

    function testRevealBetWrongMarketForResult() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        // Reveal market result
        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome, // alice should win
            losingTotalPot: 0,
            winningTotalWeight: aliceBetContext.betInfo.betWeight,
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob, ResultCommitment resultCommitment,) = revealResult(marketContext, resultInfo);

        // Reveal bet, wrong market
        MarketContext memory wrongMarketContext = makeMarketContext(0x23, 2);
        vm.expectRevert(
            abi.encodeWithSelector(
                MarketsErrors.MarketsInconsistentResult.selector, wrongMarketContext.marketCommitment, resultCommitment
            )
        );
        markets.revealBet(wrongMarketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);
    }

    function testRevealBetWrongMarketInBetBlob() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        // Reveal market result
        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome, // alice should win
            losingTotalPot: 0,
            winningTotalWeight: aliceBetContext.betInfo.betWeight,
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob,,) = revealResult(marketContext, resultInfo);

        // Reveal bet, wrong market in bet blob
        MarketContext memory wrongMarketContext = makeMarketContext(0x23, 2);
        aliceBetContext = makeBetContext(alice, 10e18, 1, 0, wrongMarketContext.marketCommitment);
        vm.expectRevert(abi.encodeWithSelector(MarketsErrors.MarketsInvalidRevealBet.selector));
        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);
    }

    function testRevealBetWrongBetCommitment() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        uint256 losingOutcome = 1;
        uint256 winningOutcome = 0;
        BetContext memory aliceBetContext =
            makeBetContext(alice, 10e18, losingOutcome, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        // Reveal market result
        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 1 << winningOutcome,
            losingTotalPot: 0,
            winningTotalWeight: aliceBetContext.betInfo.betWeight,
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob,,) = revealResult(marketContext, resultInfo);

        // Reveal bet, but make betblob contain a different outcome
        BetContext memory wrongBetContext =
            makeBetContext(alice, 10e18, winningOutcome, 0, marketContext.marketCommitment);
        vm.expectRevert(
            abi.encodeWithSelector(
                MarketsErrors.MarketsInvalidBetRequest.selector,
                aliceBetContext.requestCommitment,
                wrongBetContext.request.betCommitment,
                aliceBetContext.request.betCommitment
            )
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, wrongBetContext.betBlob);
    }

    function testRevealBetLateSubmission(uint256 aliceAmount, uint256 bobAmount, uint256 carolAmount) public {
        // If the backend somehow screws up and allows a bet request whose
        // submission deadline is _after_ market deadline, we need to just
        // refund the user's bet without any winnings

        aliceAmount = bound(aliceAmount, 1e6, 10e18);
        bobAmount = bound(bobAmount, 1e6, 10e18);
        carolAmount = bound(bobAmount, 1e6, 10e18);
        MarketContext memory marketContext = makeMarketContext();

        // Fees should not affect test
        vm.prank(admin);
        markets.setFees(uint16(3e3), uint16(3e3));

        // Alice bets on outcome 0, bob bets on outcome 1
        // whoever put more wins
        uint256 winningOutcome = aliceAmount > bobAmount ? 0 : 1;
        BetContext memory aliceBetContext = makeBetContext(alice, aliceAmount, 0, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        BetContext memory bobBetContext = makeBetContext(bob, bobAmount, 1, 0, marketContext.marketCommitment);
        placeBet(bob, bobBetContext.request);

        // Change deadline for carol to be after market end. Will place the bet _after_ result reveal
        submissionDeadlineBlock = marketDeadlineBlock + 100;
        BetContext memory carolBetContext = makeBetContext(carol, carolAmount, 0, 0, marketContext.marketCommitment);

        // Reveal market result
        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcomeMask: 1 << winningOutcome,
            losingTotalPot: winningOutcome == 0 ? bobAmount : aliceAmount,
            winningTotalWeight: winningOutcome == 0 ? aliceAmount : bobAmount,
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob,,) = revealResult(marketContext, resultInfo);

        // Place carol's bet after market settled
        placeBet(carol, carolBetContext.request);

        // Reveal carol's bet - it should just be a refund, no matter who won
        vm.assertEq(erc20.balanceOf(carol), 0, "Carol doesn't have any money");
        vm.expectEmit(true, false, false, true);
        emit IMarkets.MarketsBetWasPlacedAfterResult(marketContext.marketCommitment, carolBetContext.requestCommitment);
        markets.revealBet(marketContext.marketBlob, resultBlob, carolBetContext.request, carolBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(carol), carolAmount, "Carol gets exact refund");
    }

    function testBatchRevealBetWrongInput() public {
        MarketContext memory marketContext = makeMarketContext();

        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        BetContext memory bobBetContext = makeBetContext(bob, 20e18, 0, 0, marketContext.marketCommitment);
        placeBet(bob, bobBetContext.request);

        // Reveal market result
        (ResultBlob memory resultBlob,,) = revealResult(
            marketContext,
            WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome, // alice should win
                losingTotalPot: bobBetContext.request.amount,
                winningTotalWeight: aliceBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            })
        );

        // Incorrect batch reveal
        BetRequest[] memory requests = new BetRequest[](2);
        BetBlob[] memory betBlobs = new BetBlob[](1);
        vm.expectRevert(MarketsErrors.MarketsInvalidBatchRevealBet.selector);
        markets.batchRevealBet(marketContext.marketBlob, resultBlob, requests, betBlobs);
    }

    function testBatchReveal() public {
        MarketContext memory marketContext = makeMarketContext();

        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        BetContext memory bobBetContext = makeBetContext(bob, 20e18, 0, 0, marketContext.marketCommitment);
        placeBet(bob, bobBetContext.request);

        // Reveal market result
        (ResultBlob memory resultBlob,,) = revealResult(
            marketContext,
            WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome, // alice should win
                losingTotalPot: bobBetContext.request.amount,
                winningTotalWeight: aliceBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            })
        );

        // Reveal all bets in a batch
        uint256 totalBetAmount = bobBetContext.request.amount + aliceBetContext.request.amount;
        BetRequest[] memory requests = new BetRequest[](2);
        requests[0] = aliceBetContext.request;
        requests[1] = bobBetContext.request;
        BetBlob[] memory betBlobs = new BetBlob[](2);
        betBlobs[0] = aliceBetContext.betBlob;
        betBlobs[1] = bobBetContext.betBlob;

        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(
            aliceBetContext.requestCommitment, marketContext.marketCommitment, erc20, alice, totalBetAmount
        );
        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(bobBetContext.requestCommitment, marketContext.marketCommitment, erc20, bob, 0);
        markets.batchRevealBet(marketContext.marketBlob, resultBlob, requests, betBlobs);

        vm.assertEq(erc20.balanceOf(address(bob)), 0, "Bob did not win");
        vm.assertEq(erc20.balanceOf(address(markets)), 0, "Alice claimed her winnings");
        vm.assertEq(erc20.balanceOf(address(alice)), totalBetAmount, "Alice received her winnings");
    }

    function testFees(uint256 creatorFeesDecimal, uint256 operatorFeesDecimal) public {
        creatorFeesDecimal = bound(creatorFeesDecimal, 0, 3e3);
        operatorFeesDecimal = bound(operatorFeesDecimal, 0, 3e3);

        vm.expectEmit(true, false, false, true);
        emit IMarkets.MarketsFeesChanged(uint16(creatorFeesDecimal), uint16(operatorFeesDecimal));
        vm.prank(admin);
        markets.setFees(uint16(creatorFeesDecimal), uint16(operatorFeesDecimal));

        MarketContext memory marketContext = makeMarketContext();

        // Alice and bob bet
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        BetContext memory bobBetContext = makeBetContext(bob, 20e18, 0, 0, marketContext.marketCommitment);
        placeBet(bob, bobBetContext.request);

        // Reveal market result
        (ResultBlob memory resultBlob,,) = revealResult(
            marketContext,
            WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome, // alice should win
                losingTotalPot: bobBetContext.request.amount,
                winningTotalWeight: aliceBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            })
        );

        // Reveal each bet. Alice should get back the whole pot, fees should come out of that
        uint256 totalBetAmount = bobBetContext.request.amount + aliceBetContext.request.amount;
        vm.assertEq(erc20.balanceOf(address(markets)), totalBetAmount, "All money is in pool");
        vm.assertEq(markets.operatorFees(erc20), 0, "No operator fees yet");
        vm.assertEq(markets.creatorFees(erc20, address(creator)), 0, "No creator fees yet");

        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(bobBetContext.requestCommitment, marketContext.marketCommitment, erc20, bob, 0);
        markets.revealBet(marketContext.marketBlob, resultBlob, bobBetContext.request, bobBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), totalBetAmount);
        vm.assertEq(erc20.balanceOf(address(bob)), 0, "Bob did not win");

        // Alice revealing will transfer fees. Fees only apply on losing pot
        uint256 creatorFee = creatorFeesDecimal * bobBetContext.request.amount / markets.FEE_DIVISOR();
        uint256 operatorFee = operatorFeesDecimal * bobBetContext.request.amount / markets.FEE_DIVISOR();
        uint256 aliceAmount = totalBetAmount - creatorFee - operatorFee;
        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetFeeCollectedWithRequest(
            aliceBetContext.requestCommitment, marketContext.marketCommitment, erc20, creator, creatorFee, operatorFee
        );
        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(
            aliceBetContext.requestCommitment, marketContext.marketCommitment, erc20, alice, aliceAmount
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), creatorFee + operatorFee, "Only fees remain");
        vm.assertEq(erc20.balanceOf(address(alice)), aliceAmount, "Alice received her winnings");
        vm.assertEq(markets.operatorFees(erc20), operatorFee, "Operator fee");
        vm.assertEq(markets.creatorFees(erc20, address(creator)), creatorFee, "Creator fee");

        // withdraw creator fee
        {
            IERC20[] memory tokens = new IERC20[](1);
            tokens[0] = erc20;
            address[] memory users = new address[](1);
            users[0] = creator;
            markets.withdrawCreatorFees(tokens, users);
            vm.assertEq(erc20.balanceOf(address(creator)), creatorFee, "Creator got their fee");
        }

        // distribute operator fee to bob and carol
        {
            IMarkets.FeeDistributionRequest[] memory requests = new IMarkets.FeeDistributionRequest[](1);
            requests[0] =
                IMarkets.FeeDistributionRequest({ token: erc20, users: new address[](2), amounts: new uint256[](2) });
            requests[0].users[0] = bob;
            requests[0].amounts[0] = operatorFee / 3;

            requests[0].users[1] = carol;
            requests[0].amounts[1] = operatorFee - requests[0].amounts[0];

            vm.prank(operatorFeeDistributor);
            markets.distributeOperatorFees(requests);

            vm.assertEq(erc20.balanceOf(address(bob)), requests[0].amounts[0], "Bob operator fee");
            vm.assertEq(erc20.balanceOf(address(carol)), requests[0].amounts[1], "Carol operator fee");
        }

        vm.assertEq(erc20.balanceOf(address(markets)), 0, "All collateral distributed");
    }

    function testOperatorFeesWrongInput() public {
        IMarkets.FeeDistributionRequest[] memory requests = new IMarkets.FeeDistributionRequest[](1);
        requests[0] =
            IMarkets.FeeDistributionRequest({ token: erc20, users: new address[](2), amounts: new uint256[](3) });
        requests[0].users[0] = bob;
        requests[0].users[1] = carol;

        vm.expectRevert(abi.encodeWithSelector(MarketsErrors.MarketsFeeDistributionRequestInvalid.selector));
        vm.prank(operatorFeeDistributor);
        markets.distributeOperatorFees(requests);
    }

    function testOperatorFeesExceed(uint256 operatorFeesDecimal, uint256 extra) public {
        operatorFeesDecimal = bound(operatorFeesDecimal, 0, 3e3);
        extra = bound(extra, 1, 1000);

        vm.prank(admin);
        markets.setFees(uint16(0), uint16(operatorFeesDecimal));

        MarketContext memory marketContext = makeMarketContext();

        // Alice bets
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        // Bob bets - he is the losing pot
        BetContext memory bobBetContext = makeBetContext(bob, 10e18, 0, 0, marketContext.marketCommitment);
        placeBet(bob, bobBetContext.request);

        // place bet on different market to have enough tokens to technically cover the extra fees
        {
            BetContext memory extraBetContext =
                makeBetContext(bob, extra, 1, 1, makeMarketContext(0x23, 2).marketCommitment);
            placeBet(bob, extraBetContext.request);
        }

        // Reveal market result
        (ResultBlob memory resultBlob,,) = revealResult(
            marketContext,
            WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome, // alice should win
                losingTotalPot: bobBetContext.request.amount,
                winningTotalWeight: aliceBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            })
        );

        // Reveal bet, get fees
        uint256 operatorFee = operatorFeesDecimal * bobBetContext.request.amount / markets.FEE_DIVISOR();
        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);

        // Try to distribute excess operator fee to bob and carol
        {
            IMarkets.FeeDistributionRequest[] memory requests = new IMarkets.FeeDistributionRequest[](1);
            requests[0] =
                IMarkets.FeeDistributionRequest({ token: erc20, users: new address[](2), amounts: new uint256[](2) });
            requests[0].users[0] = bob;
            requests[0].amounts[0] = operatorFee / 3;

            requests[0].users[1] = carol;
            requests[0].amounts[1] = operatorFee - requests[0].amounts[0] + extra;

            vm.expectRevert(
                abi.encodeWithSelector(
                    MarketsErrors.MarketsNotEnoughOperatorFees.selector, erc20, operatorFee, operatorFee + extra
                )
            );
            vm.prank(operatorFeeDistributor);
            markets.distributeOperatorFees(requests);
        }
    }

    // A trusted backend may have bugs during result reveal. We can't fully fix
    // mistakes, but have at least some sanity checks/barriers to prevent some
    // modes of failure

    function testBackendBugExcessWinningsFromLowTotalWeight(uint256 aliceAmount, uint256 bobAmount) public {
        aliceAmount = bound(aliceAmount, 1000, type(uint96).max);
        bobAmount = bound(bobAmount, 1000, type(uint96).max);
        MarketContext memory marketContext = makeMarketContext();

        // Alice and bob bet
        BetContext memory aliceBetContext = makeBetContext(alice, aliceAmount, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        BetContext memory bobBetContext = makeBetContext(bob, bobAmount, 0, 0, marketContext.marketCommitment);
        placeBet(bob, bobBetContext.request);

        // Due to bad result, alice will get a larger payout than is available
        (ResultBlob memory resultBlob, ResultCommitment resultCommitment,) = revealResult(
            marketContext,
            WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome,
                losingTotalPot: bobAmount,
                winningTotalWeight: aliceAmount / 2, // undercount weight, so payout is too large
                marketCommitment: marketContext.marketCommitment
            })
        );

        // Add enough collateral to contract, so we can technically cover the excess winnings
        // In reality this would be equivalent to "stealing" winnings from other markets
        erc20.mint(address(markets), aliceAmount / 2);

        vm.expectRevert(
            abi.encodeWithSelector(
                MarketsErrors.MarketsInvalidResult.selector, marketContext.marketCommitment, resultCommitment
            )
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);
    }

    function testDistributeOperatorFeesReentrancy() public {
        // Try to take operator fees twice. This relies on a convoluted sequence
        // that most likely cannot occur in reality.  distributeOperatorFees is
        // called, and during the call to transfer the erc20 re-enters back into
        // distributeOperatorFees.
        // This means distributor account has to be a smart contract for it to be called
        // from the erc20. It will typically be an EOA.
        ReentryERC20 badErc20 = new ReentryERC20();
        erc20 = badErc20;

        uint256 operatorFeesDecimal = markets.FEE_DIVISOR() / 10; // 10% fees for simple math
        uint256 betAmount = 100;
        uint256 expectedOperatorFees = 10;
        vm.prank(admin);
        markets.setFees(uint16(0), uint16(operatorFeesDecimal));

        // place bets, do all reveals to get some operator fees
        {
            MarketContext memory marketContext = makeMarketContext();

            BetContext memory aliceBetContext = makeBetContext(alice, betAmount, 0, 0, marketContext.marketCommitment);
            placeBet(alice, aliceBetContext.request);
            BetContext memory bobBetContext = makeBetContext(bob, betAmount, 1, 0, marketContext.marketCommitment);
            placeBet(bob, bobBetContext.request);

            WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome,
                losingTotalPot: betAmount,
                winningTotalWeight: betAmount,
                marketCommitment: marketContext.marketCommitment
            });
            (ResultBlob memory resultBlob,,) = revealResult(marketContext, resultInfo);

            markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);
            vm.assertEq(markets.operatorFees(erc20), expectedOperatorFees, "Operator fee");
        }

        // Do re-entrant fee distribution
        IMarkets.FeeDistributionRequest[] memory requests = new IMarkets.FeeDistributionRequest[](1);
        requests[0] =
            IMarkets.FeeDistributionRequest({ token: badErc20, users: new address[](1), amounts: new uint256[](1) });
        requests[0].users[0] = carol; // carol expects to get double the fees
        requests[0].amounts[0] = expectedOperatorFees;

        // Set up re-entrancy call
        bytes memory call = abi.encodeWithSelector(MarketsBase.distributeOperatorFees.selector, (requests));
        badErc20.setParams(
            ReentryERC20.ReentryParams({
                senderTrigger: address(markets),
                newSenderAddress: operatorFeeDistributor,
                contractAddress: address(markets),
                call: call,
                vm: vm
            })
        );

        // Make sure there is extra collateral for re-entrancy to try and steal
        badErc20.mint(address(markets), expectedOperatorFees);

        // We should revert
        vm.expectRevert(
            abi.encodeWithSelector(MarketsErrors.MarketsNotEnoughOperatorFees.selector, erc20, 0, expectedOperatorFees)
        );
        vm.prank(operatorFeeDistributor);
        markets.distributeOperatorFees(requests);
    }

    function testAuditH01GetRefundWithInvalidBetBlob(uint256 betAmount) public {
        betAmount = bound(betAmount, 1, type(uint96).max);

        // Alice/Bob place legitimate bets. Bob loses but does not reveal bet.
        // Alice gets bob's money, but Bob plans on faking a refund
        BetContext memory bobBetContext;
        {
            MarketContext memory marketContext = makeMarketContext();
            BetContext memory aliceBetContext = makeBetContext(alice, betAmount, 0, 0, marketContext.marketCommitment);
            placeBet(alice, aliceBetContext.request);

            bobBetContext = makeBetContext(bob, betAmount, 1, 0, marketContext.marketCommitment);
            placeBet(bob, bobBetContext.request);

            WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome,
                losingTotalPot: betAmount,
                winningTotalWeight: betAmount,
                marketCommitment: marketContext.marketCommitment
            });
            (ResultBlob memory resultBlob,,) = revealResult(marketContext, resultInfo);

            markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);
        }
        vm.assertEq(erc20.balanceOf(alice), betAmount * 2, "Alice got whole pot");

        // Bob requests refund even though market settled, by faking the bet blob
        {
            MarketCommitment fakeMarket = MarketCommitment.wrap(bytes32(0));
            WeightedParimutuelMarkets.BetHiddenInfo memory betInfo = bobBetContext.betInfo;
            betInfo.marketCommitment = fakeMarket;
            BetBlob memory fakeBetBlob = BetBlob({ data: abi.encode(betInfo) });

            // Give some tokens to markets contract which could be extracted
            erc20.mint(address(markets), betAmount);

            // Contract should check the bet blob matches the request
            vm.roll(refundStartBlock);
            vm.expectRevert(
                abi.encodeWithSelector(
                    MarketsErrors.MarketsInvalidBetRequest.selector,
                    bobBetContext.requestCommitment,
                    bobBetContext.request.betCommitment,
                    getCommitment(fakeBetBlob)
                )
            );
            markets.requestRefund(bobBetContext.request, fakeBetBlob);
        }
    }

    function testAuditH02DrainMarketWithMaliciousRequest(uint256 betAmount) public {
        betAmount = bound(betAmount, 1, type(uint96).max);

        // Alice/Bob place legitimate bets. And market result is revealed. Noone reveals bet so carol can steal the losing pot
        MarketContext memory marketContext = makeMarketContext();
        ResultBlob memory resultBlob;
        {
            BetContext memory aliceBetContext = makeBetContext(alice, betAmount, 0, 0, marketContext.marketCommitment);
            placeBet(alice, aliceBetContext.request);

            BetContext memory bobBetContext = makeBetContext(bob, betAmount, 1, 0, marketContext.marketCommitment);
            placeBet(bob, bobBetContext.request);

            WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome,
                losingTotalPot: betAmount,
                winningTotalWeight: betAmount,
                marketCommitment: marketContext.marketCommitment
            });
            (resultBlob,,) = revealResult(marketContext, resultInfo);
        }
        vm.assertEq(erc20.balanceOf(address(markets)), betAmount * 2, "Markets have both bets");

        // Carol reveals fake bet to steal the whole losingPot
        {
            uint256 weight = betAmount;
            BetContext memory carolBetContext = makeBetContext(carol, 0, 0, 0, marketContext.marketCommitment, weight);
            vm.expectRevert(abi.encodeWithSelector(MarketsErrors.MarketsInvalidBetAmount.selector, 0));
            markets.revealBet(marketContext.marketBlob, resultBlob, carolBetContext.request, carolBetContext.betBlob);
        }
        vm.assertEq(erc20.balanceOf(carol), 0, "Carol did not steal losingPot");
        vm.assertEq(erc20.balanceOf(address(markets)), betAmount * 2, "Markets still has all the money");
    }

    function testAuditM01FeesChangeRetroactively(uint256 creatorFeesDecimal, uint256 operatorFeesDecimal) public {
        creatorFeesDecimal = bound(creatorFeesDecimal, 1, 3e3);
        operatorFeesDecimal = bound(operatorFeesDecimal, 1, 3e3);

        uint256 betAmount = 10e18;

        // Place bets, but change fees before reveals
        MarketContext memory marketContext = makeMarketContext();
        BetContext memory aliceBetContext = makeBetContext(alice, betAmount, 0, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        BetContext memory bobBetContext = makeBetContext(bob, betAmount, 1, 0, marketContext.marketCommitment);
        placeBet(bob, bobBetContext.request);

        // Set fees after bet placement
        vm.prank(admin);
        markets.setFees(uint16(creatorFeesDecimal), uint16(operatorFeesDecimal));

        ResultBlob memory resultBlob;
        {
            WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
                winningOutcomeMask: 1 << aliceBetContext.betInfo.outcome,
                losingTotalPot: betAmount,
                winningTotalWeight: betAmount,
                marketCommitment: marketContext.marketCommitment
            });
            (resultBlob,,) = revealResult(marketContext, resultInfo);
        }

        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetContext.request, aliceBetContext.betBlob);

        // No fees should be taken retroactively
        vm.assertEq(markets.operatorFees(erc20), 0, "Operator fees");
        vm.assertEq(markets.creatorFees(erc20, address(creator)), 0, "Creator fees");
    }
}
