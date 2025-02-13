// solhint-disable one-contract-per-file
// solhint-disable ordering
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { IERC20Errors, IERC20, ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { ERC20Permit } from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import { IERC165, ERC165 } from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { ERC2771Forwarder } from "@openzeppelin/contracts/metatx/ERC2771Forwarder.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { UD60x18, ud60x18, unwrap, uUNIT, UNIT } from "@prb/math/UD60x18.sol";

import { IMarkets } from "../contracts/IMarkets.sol";
import {
    MarketCommitment,
    ResultCommitment,
    BetCommitment,
    MarketBlob,
    ResultBlob,
    BetBlob
} from "../contracts/Commitments.sol";
import { MarketsBase, ParimutuelMarkets } from "../contracts/ParimutuelMarkets.sol";

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
    ParimutuelMarkets public markets;

    address public admin;
    address public alice;
    address public bob;
    address public creator;
    address public resultSigner;
    uint256 public resultSignerPrivateKey;

    uint256 public marketDeadlineBlock;
    uint256 public submissionDeadlineBlock;

    using MessageHashUtils for bytes32;

    function setUp() public {
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        creator = makeAddr("creator");
        admin = makeAddr("admin");
        (resultSigner, resultSignerPrivateKey) = makeAddrAndKey("result-signer");

        erc20 = new MockERC20();
        markets = new ParimutuelMarkets(admin);
        submissionDeadlineBlock = block.number + 100;
        marketDeadlineBlock = block.number + 1000;

        // Set up permissions
        bytes32 role = markets.RESULT_SIGNATURE_ROLE();
        vm.prank(admin);
        markets.grantRole(role, resultSigner);
    }

    function signCommitment(uint256 privateKey, bytes32 commitment) public pure returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, commitment);
        sig = abi.encodePacked(r, s, v); // as detailed in Openzeppelin ECDSA.recover
    }

    function signCommitment(ResultCommitment commitment) public view returns (bytes memory) {
        return signCommitment(resultSignerPrivateKey, ResultCommitment.unwrap(commitment));
    }

    function placeBet(address user, MarketsBase.BetRequest memory request, BetCommitment betCommitment) public {
        erc20.mint(user, request.amount);
        vm.prank(user);
        erc20.approve(address(markets), request.amount);

        vm.expectEmit(false, false, false, true);
        emit IMarkets.MarketsBetPlaced(request, betCommitment);
        vm.prank(user);
        markets.placeBet(request, betCommitment);
    }

    struct MarketContext {
        ParimutuelMarkets.MarketInfo marketInfo;
        MarketBlob marketBlob;
        MarketCommitment marketCommitment;
    }

    function makeMarketContext() public view returns (MarketContext memory) {
        ParimutuelMarkets.MarketInfo memory marketInfo = ParimutuelMarkets.MarketInfo({
            creator: creator,
            deadlineBlock: marketDeadlineBlock,
            marketId: 0x42,
            numOutcomes: 2
        });
        MarketBlob memory marketBlob = MarketBlob({ data: abi.encode(marketInfo) });
        MarketCommitment marketCommitment = MarketCommitment.wrap(keccak256(marketBlob.data));

        return MarketContext({ marketInfo: marketInfo, marketBlob: marketBlob, marketCommitment: marketCommitment });
    }

    function testEndToEnd() public {
        MarketContext memory marketContext = makeMarketContext();

        // Prepare alice to bet
        ParimutuelMarkets.BetInfo memory aliceBetInfo = ParimutuelMarkets.BetInfo({
            request: IMarkets.BetRequest({
                token: erc20,
                amount: 10e18,
                from: alice,
                nonce: 0,
                submissionDeadlineBlock: submissionDeadlineBlock
            }),
            hidden: ParimutuelMarkets.BetHiddenInfo({
                marketCommitment: marketContext.marketCommitment,
                option: 1,
                salt: 0x42
            })
        });
        BetBlob memory aliceBetBlob = BetBlob({ data: abi.encode(aliceBetInfo) });
        BetCommitment aliceBetCommitment = BetCommitment.wrap(keccak256(aliceBetBlob.data));

        // Approve erc20 and make bet
        placeBet(alice, aliceBetInfo.request, aliceBetCommitment);
        vm.assertEq(erc20.balanceOf(alice), 0, "Amount taken for bet");

        // Prepare bob to bet
        ParimutuelMarkets.BetInfo memory bobBetInfo = abi.decode(aliceBetBlob.data, (ParimutuelMarkets.BetInfo));
        bobBetInfo.request.from = bob;
        bobBetInfo.request.amount = 20e18;
        bobBetInfo.hidden.option = 0;
        vm.assertNotEq(bobBetInfo.hidden.option, aliceBetInfo.hidden.option);
        BetBlob memory bobBetBlob = BetBlob({ data: abi.encode(bobBetInfo) });
        BetCommitment bobBetCommitment = BetCommitment.wrap(keccak256(bobBetBlob.data));

        placeBet(bob, bobBetInfo.request, bobBetCommitment);
        vm.assertEq(erc20.balanceOf(bob), 0, "Amount taken for bet");

        // Reveal market result
        ParimutuelMarkets.ResultInfo memory resultInfo;
        {
            // Normalization is losing balances divided by winning pool balances
            UD60x18 normalization = ud60x18(uUNIT * bobBetInfo.request.amount / aliceBetInfo.request.amount);
            resultInfo = ParimutuelMarkets.ResultInfo({
                winningOption: aliceBetInfo.hidden.option, // alice should win
                normalization: normalization
            });
        }
        ResultBlob memory resultBlob = ResultBlob({ data: abi.encode(resultInfo) });
        ResultCommitment resultCommitment = ResultCommitment.wrap(keccak256(resultBlob.data));

        bytes memory resultSignature = signCommitment(resultCommitment);
        vm.expectEmit(true, false, false, true);
        emit IMarkets.MarketsResultRevealed(marketContext.marketCommitment, resultCommitment);
        markets.revealMarketResult(marketContext.marketBlob, resultBlob, resultSignature);

        // Reveal each bet. Alice should get back the whole pot
        uint256 totalBetAmount = bobBetInfo.request.amount + aliceBetInfo.request.amount;
        vm.assertEq(erc20.balanceOf(address(markets)), totalBetAmount, "All money is in pool");

        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(bobBetCommitment, marketContext.marketCommitment, erc20, bob, 0);
        markets.revealBet(marketContext.marketBlob, resultBlob, bobBetBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), totalBetAmount);
        vm.assertEq(erc20.balanceOf(address(bob)), 0, "Bob did not win");

        vm.expectEmit(true, true, true, true);
        emit IMarkets.MarketsBetRevealed(
            aliceBetCommitment, marketContext.marketCommitment, erc20, alice, totalBetAmount
        );
        markets.revealBet(marketContext.marketBlob, resultBlob, aliceBetBlob);
        vm.assertEq(erc20.balanceOf(address(markets)), 0, "Alice claimed her winnings");
        vm.assertEq(erc20.balanceOf(address(alice)), totalBetAmount, "Alice received her winnings");
    }
}
