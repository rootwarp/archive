+++
draft = false
date = 2026-10-18T21:56:00+09:00
title = "EIP-7732: What ePBS Changes in Ethereum’s Consensus Layer"
description = "How EIP-7732 moves the builder–proposer exchange from MEV-Boost relays into Ethereum’s consensus rules, and what it changes in each slot."
slug = ""
authors = ["rootwarp"]
tags = ["ethereum", "epbs", "mev"]
categories = ["ethereum"]
externalLink = ""
series = []
+++

A validator can propose an Ethereum block without choosing every transaction inside it. Specialist builders do that work, and MEV-Boost connects the two sides through relays. EIP-7732 would bring the exchange they rely on into Ethereum’s consensus rules. That sounds like a small change in plumbing, but it changes who participants have to trust and how validators spend each slot.

## 1. Why separate proposers and builders?

Proposer-builder separation, or PBS, splits block production into two jobs. The builder chooses and orders transactions, creating what Ethereum calls an execution payload. The proposer is the validator selected to propose the beacon block for that slot. It can use a builder’s payload instead of assembling one itself.

The order of transactions matters because it can create profit. An arbitrage trade, for example, may only work if it lands immediately after another transaction. This value from transaction inclusion and ordering is part of maximal extractable value, or MEV. Competing for it takes specialized software, infrastructure, and access to transaction flow.

PBS lets validators leave that competition to builders. Builders offer part of their expected revenue to the proposer in exchange for using their payload. A validator can earn that payment without running its own competitive block-building business, while remaining responsible for proposing the block.[^1]

## 2. Where MEV-Boost comes in

MEV-Boost makes PBS practical outside Ethereum’s consensus rules. Validators use it to connect to relays, which receive payloads and bids from builders. A relay checks a submission and offers the proposer a bid alongside a blinded header: a commitment to the payload that keeps its transactions hidden.

Imagine a builder offering 0.05 ETH for its payload to be used. If it reveals the transactions before the proposer commits, a dishonest proposer could copy the valuable ordering. But if the proposer signs first, it risks committing to a payload or payment that never arrives. Both sides need a way to complete the exchange safely.

The relay fills that role. It holds the full payload, presents the blinded bid, and releases the payload once the proposer has signed its commitment. That arrangement lets builders and validators work together without having to trust each other directly.[^2]

## 3. The trust shifts to relays

The arrangement works only if the relay does its job. Builders trust it to keep transactions private until the proposer commits. Proposers trust its checks and expect it to deliver the payload after they sign. A bug or outage can break that exchange.

Relay policies matter too. A relay can choose which submissions and transactions it handles, affecting which blocks reach proposers. Running the service also costs money, yet Ethereum provides no protocol-enforced revenue model for relays.

This is the gap ePBS aims to address. Block building has become specialized, but the exchange between builders and proposers still depends on services outside the protocol.[^3]

## 4. What EIP-7732 brings into the protocol

EIP-7732 proposes enshrined PBS, or ePBS. Here, “enshrined” means that Ethereum’s own rules enforce the exchange. Builders register and fund balances in the consensus layer. They then sign bids committing to a particular payload and a payment to the proposer.

The proposer puts the selected bid in its beacon block, and the builder publishes the payload separately. Ethereum tracks the commitment, the payload’s delivery, and the payment obligation backed by the builder’s balance.

Builders still build, and validators still propose. Services can still help them find and communicate with one another. The change is that they no longer need a trusted relay to hold the payload and broker the exchange; those guarantees become the protocol’s responsibility.[^4]

{{< figure src="/img/2026-0001-mev_boost_to_epbs.jpg" alt="MEV-Boost to ePBS: a trusted relay brokers the exchange today; under ePBS the protocol enforces it" caption="Figure 1. ePBS moves the builder–proposer exchange into protocol rules. The PTC reports timeliness and blob availability; execution validity is checked separately." >}}

## 5. What happens during a slot

ePBS also changes the order of work within Ethereum’s 12-second slot. Here is the path when everything goes as expected.

First, the proposer publishes a beacon block containing the builder’s signed bid. This commits the block to the payload the builder has promised to deliver.

Validators then check and attest to the beacon block. An attestation is their vote in the consensus process. They can cast that vote without first executing the newly committed payload.

The builder broadcasts the payload and its associated blob data separately, so nodes can check execution and data availability.

The Payload Timeliness Committee, or PTC, reports whether the payload arrived on time and whether the blob data was available. Those reports are included in the next beacon block.[^5]

{{< figure src="/img/2026-0001-epbs_slot_duties.jpg" alt="ePBS slot timeline: proposer, attesters, builder and PTC duties across a 12-second slot" caption="Figure 2. The slot’s duties, adapted from the survey’s consensus timeline. Timing update: the Gloas draft checked on 27 September 2026 separates payload receipt before 6s from PTC reporting by 9s, unlike the survey’s illustrative reveal window ending near 9s. Attestations are due by 3s. These are draft deadlines, and messages may be sent earlier." >}}

The PTC consists of existing validators. Its job is to report on delivery and availability. Nodes still have to check that the transactions execute correctly, and a proposer building on a payload needs a validated parent payload.[^5]

For validators, the useful difference is when that work has to happen. In the pre-ePBS pipeline, receiving and executing the payload competes with consensus checks early in the slot. With ePBS, validators can attest to the beacon block while its payload travels through a separate delivery and validation path. That leaves more time for execution and data propagation.[^4] [^6]

## 6. How the proposer gets paid

Go back to the builder’s 0.05 ETH bid. The builder needs enough available consensus-layer balance to cover it. Including the bid in a beacon block creates a payment obligation; it does not immediately transfer the money to the proposer.

On the normal path described in the survey, a later block builds on the revealed payload, and the payment enters the withdrawal queue. Withholding the payload does not necessarily let the builder avoid paying. Payment can still be enforced if the required beacon attestations for that slot have been included. These are ordinary beacon attestations; PTC votes do not provide the payment weight.

The aim is straightforward: a builder should not be able to walk away from its bid after an honest proposer has published on time. There are conditions to protect builders too, including when a proposer’s block is late or contested. The guarantee relies on the design’s security assumptions and on the chain continuing to progress.[^6]

## 7. What ePBS improves—and what it leaves open

ePBS gives Ethereum a way to enforce the builder–proposer exchange itself. It also gives execution and data propagation more time by moving them off the current slot’s immediate attestation path. That could help support future capacity increases, though the gains still depend on client performance, networking, and other protocol limits.[^4] [^6]

Payment enforcement does not solve every incentive problem. Between committing and revealing, a builder may decide its payload is no longer worth publishing. If the market moves, avoiding a trading loss could be worth more than the bid it still has to pay. This is the free-option problem: a builder can have a reason to withhold even when it cannot escape payment.[^7]

Nor does ePBS remove the advantages of large builders. Private order flow, capital, and infrastructure still matter. Builders can still leave transactions out, so stronger censorship resistance needs additional mechanisms, such as inclusion lists. Relay-like services may also find other roles in discovery, financing, or payload distribution.[^1] [^8] [^9]

There is an engineering cost as well. Ethereum’s consensus layer has to handle more state, messages, validator duties, and rules for separate payload delivery. Removing mandatory relay trust means taking on that complexity inside the protocol.[^6] [^8]

For a validator operator, EIP-7732 changes two practical things: how a builder’s promise becomes an enforceable payment, and when the node needs to do each part of its work. Understanding those changes is a useful starting point for judging both the benefits of ePBS and the complexity it adds.

Source note: Adapted from “Enshrined Proposer-Builder Separation (EIP-7732): A Survey of Protocol Design, Security Properties, and Market Structure.” The timing figure distinguishes payload receipt before 6 seconds from PTC reporting by 9 seconds, as in the Gloas validator draft checked on 18 October 2026.[^5] Payment details follow the security analysis at the revision listed in the references.[^6] Specification details remain subject to change.

[^1]: ethereum.org contributors, “[Proposer-builder separation](https://ethereum.org/roadmap/pbs/),” ethereum.org Roadmap, accessed Oct. 18, 2026. [Online].
[^2]: Flashbots, “[MEV-Boost](https://docs.flashbots.net/flashbots-mev-boost/introduction),” Flashbots Docs, accessed Oct. 18, 2026. [Online].
[^3]: M. Neuder and J. Drake, “[Why enshrine Proposer-Builder Separation? A viable path to ePBS](https://ethresear.ch/t/why-enshrine-proposer-builder-separation-a-viable-path-to-epbs/15710),” Ethereum Research, May 2023. [Online].
[^4]: F. D’Amato, N. Flaig, B. Monnot, M. Neuder, Potuz, J. Traglia, and T. Tsao, “[EIP-7732: Enshrined Proposer-Builder Separation](https://eips.ethereum.org/EIPS/eip-7732),” Ethereum Improvement Proposals, Jun. 2024; accessed Oct. 18, 2026. [Online].
[^5]: Ethereum consensus-specs contributors, “[Gloas — Honest Validator](https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/validator.md),” consensus-specs, master branch, accessed Oct. 18, 2026. [Online].
[^6]: ePBS Security Analysis Contributors, “[ePBS: From Spec to Security Properties](https://github.com/ethereum/epbs-security-analysis/tree/5feba76f2c1fcc33789a2dbe7150e53859cfe0e5),” GitHub, commit 5feba76f, Jun. 2026. [Online].
[^7]: B. Mazorra, B. Öz, C. Schlegel, and F. Wu, “[The free option problem of ePBS](https://arxiv.org/abs/2509.24849v1),” arXiv:2509.24849v1, Sep. 2025. [Online].
[^8]: Dapplion, “[OPINION: The case against EIP-7732 for Glamsterdam](https://sigmaprime.io/blog/glamsterdam-eip7732/),” Sigma Prime, Jul. 2025. [Online].
[^9]: C. Schlegel, 0xSybil, and M. Pan, “[Trustless payments and relays](https://collective.flashbots.net/t/trustless-payments-and-relays/5761),” Flashbots Collective, Jun. 2026. [Online].
