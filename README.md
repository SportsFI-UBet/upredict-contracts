# Overview

This repository includes the smart contracts for the Belief Market platform

The high-level idea is a variant of parimutuel markets where the user's bets are
hidden. A lot of the processing and storage is done off-chain, through the use
of commitment schemes.

There are several operations in the protocol, with a hand off back-and-forth
between the smart contract and a trusted backend. The trusted backend stores the
hidden information and reveals it when appropriate.

## Operations overview

- `placeBet`
  - User proposes a bet request to trusted Backend
  - Backend stores the hidden parts of the request, gives a commitment for the
    hidden parts to the user, and signs overall [`BetRequest`](contracts/Commitments.sol)
  - User submits signed `BetRequest` which contains the commitment.
  - The bet amount is known, but the market identity, and outcome picked are
    hidden

- `revealMarketResult`
  - Backend aggregates all the information, and decides a winner.
  - Backend reveals the MarketBlob and ResultBlob that contain enough
    information to inform how to payout users given their full bet information.
    Their commitments are stored so they can be checked during bet reveal.
  
- `revealBet`
  - User sees that market is over and result is revealed.
  - User grabs all necessary Blobs from the backend along with their original
    request, and reveals their bet
  - The smart contract calculates their payout, and takes any necessary fees

## Other requirements

- Each market has a `marketDeadline` before which all bets must be entered, and
  when the winner will be decided.
- There is a `submissionDeadline` that prevents users from delaying the
  submission of their signed `BetRequest`.
- There is a `refundStartBlock`, which is effectively a deadline for the backend
  to reveal the result. If there is no result by that time, a user is entitled to
  a full refund of their bet. `refundStartBlock` is randomized per user so it
  cannot be correlated with a particular market

## Commitments

Different structures are hidden and later revealed. They are hashed with
`keccak256` to get a commitment that is submitted to the blockchain. Various
structures are revealed at different times, so to prevent tampering of
independent pieces of information, they are all linked by containing
commitments of each other in a tree.

A user's bet request that is signed by the trusted backend is linked to the
hidden bet information, and the market information

- RequestCommitment -> BetRequest
- BetRequest -> BetCommitment
- BetCommmitment -> BetBlob
- BetBlob -> MarketCommitment
- MarketCommitment -> MarketBlob

The calculated result from the backend contains a market commitment that ensures
the result is intended for a specific market, and can be used to make payouts
for user's bets.

- ResultCommitment -> ResultBlob
- ResultBlob -> MarketCommitment
- MarketCommitment -> MarketBlob

## MarketsBase and Derived Contracts

[`MarketsBase`](contracts/MarketsBase.sol) acts like the base layer of the
protocol and faciliates most of the common operations, and enforces all the
common pre/post conditions. Only the `BetRequest` structure is set in stone.

A derived contract gets to choose what to put inside the `BetBlob`, `MarketBlob`
and `ResultBlob` and how to interpret it for payout calculations. 

## Current Deployments

Most up-to-date addresses are available in the [deployments](./deployments/)
directory per chain. A list is also provided here, but is not guaranteed to be
up-to-date:

Testnets:

- BNB testnet (chapel): [`0x2bDf19cA33444CdeEfbd65D8612d21A383a69A1a`](https://testnet.bscscan.com/address/0x2bDf19cA33444CdeEfbd65D8612d21A383a69A1a)
- Base testnet: [`0xE649ED988e1B7E2dDa1FBAB88082c8C8E94FA336`](https://sepolia.basescan.org/address/0xE649ED988e1B7E2dDa1FBAB88082c8C8E94FA336)

Mainnets:

- BNB mainnet: [`0xab1fB9B0efA9235AFF385639611cB1BbbbCc3b40`](https://bscscan.com/address/0xab1fB9B0efA9235AFF385639611cB1BbbbCc3b40)
- Base mainnet: [`0x5035608222e1C226781CAa22fe40D0DB6cc6c119`](https://basescan.org/address/0x5035608222e1C226781CAa22fe40D0DB6cc6c119)
