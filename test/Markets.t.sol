// solhint-disable one-contract-per-file
// solhint-disable ordering
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { IERC20, ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { ERC2771Forwarder } from "@openzeppelin/contracts/metatx/ERC2771Forwarder.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

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
    BetBlob
} from "../contracts/Commitments.sol";
import { WeightedParimutuelMarkets } from "../contracts/WeightedParimutuelMarkets.sol";

/// @dev Adapted from guide on testing EIP712 signatures for foundry:
/// https://book.getfoundry.sh/tutorials/testing-eip712?highlight=712#testing-eip-712-signatures
contract SigUtils {
    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
    bytes32 public constant FORWARD_REQUEST_TYPEHASH = keccak256(
        "ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,uint48 deadline,bytes data)"
    );

    bytes32 internal domainSeparator;

    constructor(bytes32 _domainSeparator) {
        domainSeparator = _domainSeparator;
    }

    // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
    function getTypedDataHash(bytes32 structHash) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    // computes the hash of a permit
    function getStructHash(Permit memory _permit) public pure returns (bytes32) {
        return keccak256(
            abi.encode(PERMIT_TYPEHASH, _permit.owner, _permit.spender, _permit.value, _permit.nonce, _permit.deadline)
        );
    }

    function getStructHash(ERC2771Forwarder.ForwardRequestData memory request, uint256 nonce)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                FORWARD_REQUEST_TYPEHASH,
                request.from,
                request.to,
                request.value,
                request.gas,
                nonce,
                request.deadline,
                keccak256(request.data)
            )
        );
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

    function makeMarketContext(uint256 marketId) public view returns (MarketContext memory) {
        WeightedParimutuelMarkets.MarketInfo memory marketInfo = WeightedParimutuelMarkets.MarketInfo({
            creator: creator,
            deadlineBlock: marketDeadlineBlock,
            marketId: marketId,
            numOutcomes: 2
        });
        MarketBlob memory marketBlob = MarketBlob({ data: abi.encode(marketInfo) });
        MarketCommitment marketCommitment = MarketCommitment.wrap(keccak256(marketBlob.data));

        return MarketContext({ marketInfo: marketInfo, marketBlob: marketBlob, marketCommitment: marketCommitment });
    }

    function makeMarketContext() public view returns (MarketContext memory) {
        return makeMarketContext(0x42);
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
            token: erc20,
            amount: uint96(amount),
            from: user,
            nonce: uint96(nonce),
            submissionDeadlineBlock: submissionDeadlineBlock,
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
                winningOutcome: aliceBetContext.betInfo.outcome, // alice should win
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
        lowerLimit = bound(lowerLimit, 1, type(uint96).max - 1);
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
                winningOutcome: aliceBetContext.betInfo.outcome, // alice and carol should win
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
                winningOutcome: aliceBetContext.betInfo.outcome, // alice should win
                losingTotalPot: 0,
                winningTotalWeight: aliceBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            })
        );

        // Reveal bets
        vm.assertEq(erc20.balanceOf(address(markets)), aliceBetContext.request.amount, "Alice's money is in pool");

        // Bob's reveal should fail
        vm.expectRevert(
            abi.encodeWithSelector(MarketsErrors.MarketsBetDoesntExist.selector, bobBetContext.request.betCommitment)
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
                winningOutcome: aliceBetContext.betInfo.outcome,
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

    function testRevealResultIdempotent() public {
        MarketContext memory marketContext = makeMarketContext();

        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        // Reveal market result
        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcome: aliceBetContext.betInfo.outcome,
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
            winningOutcome: aliceBetContext.betInfo.outcome,
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
            winningOutcome: aliceBetContext.betInfo.outcome,
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
            winningOutcome: aliceBetContext.betInfo.outcome,
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
            winningOutcome: marketContext.marketInfo.numOutcomes, // invalid outcome index
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
    }

    function testRevealBetWrongResult() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        // Reveal market result
        WeightedParimutuelMarkets.ResultInfo memory resultInfo = WeightedParimutuelMarkets.ResultInfo({
            winningOutcome: aliceBetContext.betInfo.outcome, // alice should win
            losingTotalPot: 0,
            winningTotalWeight: aliceBetContext.betInfo.betWeight,
            marketCommitment: marketContext.marketCommitment
        });
        revealResult(marketContext, resultInfo);

        // Reveal bet, wrong result
        resultInfo.winningOutcome = 0;
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
            winningOutcome: aliceBetContext.betInfo.outcome, // alice should win
            losingTotalPot: 0,
            winningTotalWeight: aliceBetContext.betInfo.betWeight,
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob, ResultCommitment resultCommitment,) = revealResult(marketContext, resultInfo);

        // Reveal bet, wrong market
        MarketContext memory wrongMarketContext = makeMarketContext(0x23);
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
            winningOutcome: aliceBetContext.betInfo.outcome, // alice should win
            losingTotalPot: 0,
            winningTotalWeight: aliceBetContext.betInfo.betWeight,
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob,,) = revealResult(marketContext, resultInfo);

        // Reveal bet, wrong market in bet blob
        MarketContext memory wrongMarketContext = makeMarketContext(0x23);
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
            winningOutcome: winningOutcome,
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
            winningOutcome: winningOutcome,
            losingTotalPot: winningOutcome == 0 ? bobAmount : aliceAmount,
            winningTotalWeight: winningOutcome == 0 ? aliceAmount : bobAmount,
            marketCommitment: marketContext.marketCommitment
        });
        (ResultBlob memory resultBlob,,) = revealResult(marketContext, resultInfo);

        // Place carol's bet after market settled
        placeBet(carol, carolBetContext.request);

        // Reveal carol's bet - it should just be a refund, no matter who won
        vm.assertEq(erc20.balanceOf(carol), 0, "Carol doesn't have any money");
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
                winningOutcome: aliceBetContext.betInfo.outcome, // alice should win
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
                winningOutcome: aliceBetContext.betInfo.outcome, // alice should win
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
                winningOutcome: aliceBetContext.betInfo.outcome, // alice should win
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
        emit IMarkets.MarketsBetFeeCollected(marketContext.marketCommitment, erc20, creator, creatorFee, operatorFee);
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
                makeBetContext(bob, extra, 1, 1, makeMarketContext(0x23).marketCommitment);
            placeBet(bob, extraBetContext.request);
        }

        // Reveal market result
        (ResultBlob memory resultBlob,,) = revealResult(
            marketContext,
            WeightedParimutuelMarkets.ResultInfo({
                winningOutcome: aliceBetContext.betInfo.outcome, // alice should win
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
}
