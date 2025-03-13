// solhint-disable one-contract-per-file
// solhint-disable ordering
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { IERC20, ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { ERC2771Forwarder } from "@openzeppelin/contracts/metatx/ERC2771Forwarder.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import { IMarkets } from "../contracts/IMarkets.sol";
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

contract MockERC20 is ERC20 {
    constructor() ERC20("TEST", "TEST") { }

    function mint(address account, uint256 value) external {
        return _mint(account, value);
    }
}

contract MarketsTest is Test {
    MockERC20 public erc20;
    WeightedParimutuelMarkets public markets;

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

    function setUp() public {
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        carol = makeAddr("carol");
        creator = makeAddr("creator");
        admin = makeAddr("admin");
        (resultSigner, resultSignerPrivateKey) = makeAddrAndKey("result-signer");
        (betSigner, betSignerPrivateKey) = makeAddrAndKey("bet-signer");
        operatorFeeDistributor = makeAddr("operator-fee-distributor");

        erc20 = new MockERC20();
        markets = new WeightedParimutuelMarkets(admin);
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, commitment);
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

    function placeBet(address user, BetRequest memory request) public {
        erc20.mint(user, request.amount);
        vm.prank(user);
        erc20.approve(address(markets), request.amount);

        bytes memory signature = signRequest(request);

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

    function makeMarketContext() public view returns (MarketContext memory) {
        WeightedParimutuelMarkets.MarketInfo memory marketInfo = WeightedParimutuelMarkets.MarketInfo({
            creator: creator,
            deadlineBlock: marketDeadlineBlock,
            marketId: 0x42,
            numOutcomes: 2
        });
        MarketBlob memory marketBlob = MarketBlob({ data: abi.encode(marketInfo) });
        MarketCommitment marketCommitment = MarketCommitment.wrap(keccak256(marketBlob.data));

        return MarketContext({ marketInfo: marketInfo, marketBlob: marketBlob, marketCommitment: marketCommitment });
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
        WeightedParimutuelMarkets.ResultInfo memory resultInfo;
        {
            resultInfo = WeightedParimutuelMarkets.ResultInfo({
                winningOutcome: aliceBetContext.betInfo.outcome, // alice should win
                losingTotalPot: bobBetContext.request.amount,
                winningTotalWeight: aliceBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            });
        }
        ResultBlob memory resultBlob = ResultBlob({ data: abi.encode(resultInfo) });
        ResultCommitment resultCommitment = ResultCommitment.wrap(keccak256(resultBlob.data));

        bytes memory resultSignature = signResultCommitment(resultCommitment);
        vm.expectEmit(true, false, false, true);
        emit IMarkets.MarketsResultRevealed(marketContext.marketCommitment, resultCommitment);
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);

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

    // TODO: test place bet, reveal bet and then replay the place bet

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
        WeightedParimutuelMarkets.ResultInfo memory resultInfo;
        {
            resultInfo = WeightedParimutuelMarkets.ResultInfo({
                winningOutcome: aliceBetContext.betInfo.outcome, // alice and carol should win
                losingTotalPot: bobBetContext.request.amount,
                winningTotalWeight: aliceBetContext.betInfo.betWeight + carolBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            });
        }
        ResultBlob memory resultBlob = ResultBlob({ data: abi.encode(resultInfo) });
        ResultCommitment resultCommitment = ResultCommitment.wrap(keccak256(resultBlob.data));

        bytes memory resultSignature = signResultCommitment(resultCommitment);
        vm.expectEmit(true, false, false, true);
        emit IMarkets.MarketsResultRevealed(marketContext.marketCommitment, resultCommitment);
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);

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

    // TODO: test abandoning a bet and trying to reveal

    function testFees(uint256 creatorFeesDecimal, uint256 operatorFeesDecimal) public {
        creatorFeesDecimal = bound(creatorFeesDecimal, 0, 3e3);
        operatorFeesDecimal = bound(operatorFeesDecimal, 0, 3e3);

        vm.prank(admin);
        markets.setFees(uint16(creatorFeesDecimal), uint16(operatorFeesDecimal));

        MarketContext memory marketContext = makeMarketContext();

        // Alice and bob bet
        BetContext memory aliceBetContext = makeBetContext(alice, 10e18, 1, 0, marketContext.marketCommitment);
        placeBet(alice, aliceBetContext.request);

        BetContext memory bobBetContext = makeBetContext(bob, 20e18, 0, 0, marketContext.marketCommitment);
        placeBet(bob, bobBetContext.request);

        // Reveal market result
        WeightedParimutuelMarkets.ResultInfo memory resultInfo;
        {
            resultInfo = WeightedParimutuelMarkets.ResultInfo({
                winningOutcome: aliceBetContext.betInfo.outcome, // alice should win
                losingTotalPot: bobBetContext.request.amount,
                winningTotalWeight: aliceBetContext.betInfo.betWeight,
                marketCommitment: marketContext.marketCommitment
            });
        }
        ResultBlob memory resultBlob = ResultBlob({ data: abi.encode(resultInfo) });
        ResultCommitment resultCommitment = ResultCommitment.wrap(keccak256(resultBlob.data));

        bytes memory resultSignature = signResultCommitment(resultCommitment);
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);

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

        // Alice revealing will transfer fees
        uint256 creatorFee = creatorFeesDecimal * totalBetAmount / markets.FEE_DIVISOR();
        uint256 operatorFee = operatorFeesDecimal * totalBetAmount / markets.FEE_DIVISOR();
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
}
