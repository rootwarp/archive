+++ 
draft = false
date = 2024-03-05T23:46:11+09:00
title = "How to verify Ethereum attestation data"
description = "description"
slug = ""
authors = ["rootwarp"]
tags = ["crypto", "ethereum"]
categories = ["crypto", "ethereum"]
externalLink = ""
series = []
+++


## Intro

In the development of its Proof of Stake (PoS) system, Ethereum targeted a decentralized framework, leading to the participation of more than 900,000 validators in the network. Given this extensive number of validators, sophisticated techniques are employed to effectively manage their activities.

At the beginning of an epoch, validators are randomly assigned into multiple groups known as committees. Then, every 12 seconds, corresponding to the creation of a slot, validators in each committee are tasked with signing specific data. This signed information is subsequently forwarded to an *attestation aggregator*, as determined by the protocol, where the signatures are consolidated into a single signature.[^1]

This article is written for understanding of the attestation process as described above. However, the attestation process in its entirety is notably intricate. As an initial step, this piece will focus on comprehending the structure of attestation data, primarily by delving into the procedure for verifying attestation signatures.

To implement the verification code, it is necessary to make an RPC call to the Beacon Chain. However, using a public Beacon Chain RPC can be challenging. Therefore, for ease of use, the necessary data has been saved in the fixtures directory in JSON format.


## Prerequisites

Before delving into the attestation process, it's important to explore two additional technical concepts to fully grasp the signing process.

### Simple Serialize(SSZ)

SSZ[^2] is a encoding scheme that is used for data serialization in the beacon chain. The client utilizes various data structures to manage different types of data, which must be converted into byte arrays for signing or encoding. Using the same serialization algorithm is crucial for cryptographic signatures to ensure consistency across all clients. Moreover, Ethereum's SSZ method is designed to be simple and fast, facilitating quick computation of Merkle Tree Hashes.

### BLS12-381

BLS12-381 is a sophisticate elliptic curve function. It is using two elliptic curves and also called as elliptic curve-pairing. The significant feature of this is supporting the aggregation of multiple signatures. This capability significantly improves verification process efficiency by allowing the verification of aggregated signatures in one go, which is particularly beneficial when dealing with thousands of signatures. 

The below test function `TestBLS_SimpleAggregation` demonstrates how aggregated signatures can be verified more efficiently than individual signatures[^3].

As testing code shows, the aggregated signature can be verified with all related public keys and messages by one step.


```golang
func TestBLS_SimpleAggregation(t *testing.T) {
...
...
...
	// Create a new slice to convert []*bls.PublicKey to []bls.PublicKey
	pubKeys := make([]bls.PublicKey, nTest)
	for i, pk := range publicKeys {
		pubKeys[i] = *pk
	}

	testMsgs := make([][]byte, nTest)
	for i := 0; i < nTest; i++ {
		testMsgs[i] = []byte(testMsg)
	}

	// All signatures can be verified by with one aggregated signature.
	assert.True(t, aggSig.VerifyAggregateHashes(pubKeys, testMsgs))
	assert.True(t, aggSig.FastAggregateVerify(pubKeys, []byte(testMsg)))
}
```


## Verify Attestation for a Single Slot

From this section, more detail codes will be described.


To verify attestation data, it's necessary to fetch data from the Beacon Chain. For this purpose, all related data has been gathered and stored as a JSON format for testing convenience.

### Data Preparation

For verification, slot `8165556` was chosen. Due to attestation data of `8165556` included on the next slot `8165557`, `fixtures/beacon_blocks_8165557.json` has been stored for testing. Additionally, the committee number `18` had been selected to simplify test implementation.

The selected attestation data can be found on [beaconcha.in](https://beaconcha.in/slot/8165557#attestations). From the next section, the signature `0x937252738739be42843f5c2d587e78cac606d28bed848cab7c906904bbae6835d0e72704af32650c608d9c27bd394d09035b2ee51783402cfa689cf281256f179e2a546c04ffb7c3af5da002a7861f81c134d760b4e8ec366d4a4c83bc710757` will be verified.

![Fig.1. Attestation Data](/img/2024-0001-selected_attestation.png)

### Prepare Attestation Data

The verification of an aggregated BLS Signature requires the attestation data used in the signature and the corresponding public keys. This section describes the process of generating the data for signature verification. 

Beacon chain spec[^4] defines detail processes of how to create signing data like below.

```python
def get_attestation_signature(state: BeaconState, attestation_data: AttestationData, privkey: int) -> BLSSignature:
    domain = get_domain(state, DOMAIN_BEACON_ATTESTER, attestation_data.target.epoch)
    signing_root = compute_signing_root(attestation_data, domain)
    return bls.Sign(privkey, signing_root)


def get_domain(state: BeaconState, domain_type: DomainType, epoch: Epoch=None) -> Domain:
    """
    Return the signature domain (fork version concatenated with domain type) of a message.
    """
    epoch = get_current_epoch(state) if epoch is None else epoch
    fork_version = state.fork.previous_version if epoch < state.fork.epoch else state.fork.current_version
    return compute_domain(domain_type, fork_version, state.genesis_validators_root)


def compute_domain(domain_type: DomainType, fork_version: Version=None, genesis_validators_root: Root=None) -> Domain:
    """
    Return the domain for the ``domain_type`` and ``fork_version``.
    """
    if fork_version is None:
        fork_version = GENESIS_FORK_VERSION
    if genesis_validators_root is None:
        genesis_validators_root = Root()  # all bytes zero by default
    fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root)
    return Domain(domain_type + fork_data_root[:28])

def compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root:
    """
    Return the 32-byte fork data root for the ``current_version`` and ``genesis_validators_root``.
    This is used primarily in signature domains to avoid collisions across forks/chains.
    """
    return hash_tree_root(ForkData(
        current_version=current_version,
        genesis_validators_root=genesis_validators_root,
    ))

def compute_signing_root(ssz_object: SSZObject, domain: Domain) -> Root:
    """
    Return the signing root for the corresponding signing data.
    """
    return hash_tree_root(SigningData(
        object_root=hash_tree_root(ssz_object),
        domain=domain,
    f))

class SigningData(Container):
    object_root: Root
    domain: Domain
```

First, `fork data` should be created. one of fields of `fork data` is `current_version` and it is a fork number of Capella(based on 2024-02-01), `0x03000000`. The another field `genesis_validators_root` is a `hash_tree_root` of genesis validators which is fixed value `0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95`[^6]

Next, `domain` should be created. Creating `domain` can be created by adding `domain_type` and `fork_data` and truncating last bytes over 32 bytes. In here `domain_type` is defined as `0x0100000000` for attestors[^7]

For the last step, `signing data` should be created. To create `signing data`, `domain` and `attestation data` are required. The `domain` has been created on the below and `attestation data` can be collected on slot data[^8][^9].

The data creating process described above attached below[^10].

```golang
    genesisValidatorRoot, err := hex.DecodeString("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")


    var genesisValidatorRootHash [32]byte
    copy(genesisValidatorRootHash[:], genesisValidatorRoot)


    forkData := ForkData{
        CurrentVersion:        CAPELLA_FORK_VERSION,
        GenesisValidatorsRoot: genesisValidatorRootHash,
    }


    forkDataRoot, err := forkData.HashTreeRoot()


    domainData := []byte{}
    domainData = append(domainData, DOMAIN_TYPE_ATTESTER...)
    domainData = append(domainData, forkDataRoot[:28]...)


    // create signing data and signing root.
    attestationDataHash, err := attestation.Data.HashTreeRoot()
    signingData := SigningData{
        ObjectRoot: attestationDataHash,
        Domain:     Hash(domainData),
    }


    signingDataHash, err := signingData.HashTreeRoot()
```

### Aggregation Bit

If a signing data prepared, public key of validators should be collected to verify signature. But only participated public keys should be collected because the BLS verification process will be failed if a public key which is not contained on the signature is contained on verification step.

Due to this, which validators on the committee should be revealed correctly and it can be done by reading aggregation bit which is contained on slot data like below.


![Fig. 2. Aggregation Bits](/img/2024-0001-aggregation_bit.png)

Each bit on the `aggregation bits` shows which validator index on the committee has been participated attestation correctly. For example, 14th validator participated attestation and the 14th validator on the 18th committee is a validator `327352`(Found at `fixtures/beacon_states_8165556_committees.json`, line `577144`).

Raw data of `aggregation bit` shows like `0x00400000100000000000000000000000080000000000000800024005000000001000004000002000000000000002000000000000008080` and it should be scanned from MSB. The decoding code has been implemented as below[^11]

```go
func (a AggBit) ToIndex() []int {
    idx := 0
    valIndex := []int{}
    aggBitsStr := strings.TrimPrefix(a.String(), "0x")
    for i := 0; i < len(aggBitsStr); i += 2 {
        split := aggBitsStr[i : i+2]
        intVal, err := strconv.ParseUint(split, 16, 64)
        if err != nil {
            panic(err)
        }


        bitmask := uint64(1)
        for j := 0; j < 8; j++ {
            if intVal&bitmask > 0 {
                valIndex = append(valIndex, idx)
            }


            bitmask = bitmask << 1
            idx += 1
        }
    }


    return valIndex
}
```

### Get Public keys of Validator

If the validator indexes which are participated attestation, the next step is collecting public key of those validators. Fortunately, beacon chain RPC provides `getStateValudator`[^12] to get public keys and the collected public keys are stored on the fixture directory for convenience.

The response data structured like below, and `pubkey` field can be found under the `data.validator`.

```json
{
  "execution_optimistic": false,
  "finalized": true,
  "data": {
    "index": "605484",
    "balance": "32012298800",
    "status": "active_ongoing",
    "validator": {
      "pubkey": "0x87be8c61d1ce0623c6d766c4e209cf32794512d6c0ba9d567a1eb9ddab2464adc6d0df053259f7943c074a6949bf2a9c",
      "withdrawal_credentials": "0x01000000000000000000000015163df4d5de7c3a1d9f96fdfffd20c0171b17d7",
      "effective_balance": "32000000000",
      "slashed": false,
      "activation_eligibility_epoch": "200487",
      "activation_epoch": "205106",
      "exit_epoch": "18446744073709551615",
      "withdrawable_epoch": "18446744073709551615"
    }
  }
}
```

### Verify aggregated signature

Thus, all required data has been prepared. the last step is verification by using all prepared data.

On the test code, the package `github.com/herumi/bls-eth-go-binary/bls` used for BLS signature verification and it provides two functions `VerifyAggregateHashes` and `FastAggregateVerify`.

In the case of `VerifyAggregateHashes`, it requires all public keys and related messages for each signer, respectively. On the other hand, `FastAggregateVerify` required only one message for signature verification because this function assumes all participants sign to same messages.

For Ethereum, all validators which are in a same committee should sign same messages. So `FastAggregateVerify` will be better to use.

Below code[^13] is the verification code for aggregated signature.

```go
	publicKeys := []bls.PublicKey{}
	for _, n := range attestation.AggregationBits.ToIndex() {
		if n > len(committee.Validators)-1 {
			continue
		}

		validator, err := fixtureLoadValidator(Slot(blockNo), committee.Validators[n])
		assert.Nil(t, err)

		validators = append(validators, validator)
		pubkeyStr := validator.Pubkey
		pk := bls.PublicKey{}
		pk.DeserializeHexStr(strings.TrimPrefix(pubkeyStr, "0x"))

		publicKeys = append(publicKeys, pk)
	}

	aggSigStr := attestation.Signature
	aggSig := bls.Sign{}
	aggSig.DeserializeHexStr(strings.TrimPrefix(aggSigStr, "0x"))

	isValid := aggSig.FastAggregateVerify(publicKeys, signingDataHash[:])
```


## Conclusion

This article concludes by implementing signature verification processes by using publicly available information from the chain. It highlights the understanding gained regarding Ethereum's attestation data creation, the SSZ encoding method used in the Beacon Chain, and the benefits of the BLS signature method.

The complete source code are available on Github[^14] and hope this article offers a valuable resource for understanding the Ethereum's attestation.

[^1]: https://eth2book.info/capella/part2/building_blocks/aggregator/#introduction
[^2]: https://ethereum.org/developers/docs/data-structures-and-encoding/ssz
[^3]: https://github.com/rootwarp/snippets/blob/68e883f72771612ee1d94571c7ff4685d5857568/golang/ethereum/attestation/bls_test.go#L17-L62
[^4]: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#compute_signing_root
[^5]: https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/fork.md#configuration
[^6]: https://eth2book.info/capella/part3/containers/state/
[^7]: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#domain-types
[^8]: https://github.com/rootwarp/snippets/blob/68e883f72771612ee1d94571c7ff4685d5857568/golang/ethereum/attestation/types.go#L172-L178
[^9]: https://github.com/rootwarp/snippets/blob/68e883f72771612ee1d94571c7ff4685d5857568/golang/ethereum/attestation/fixtures/beacon_blocks_8165557.json#L2183-L2195
[^10]: https://github.com/rootwarp/snippets/blob/68e883f72771612ee1d94571c7ff4685d5857568/golang/ethereum/attestation/bls_test.go#L84-L112
[^11]: https://github.com/rootwarp/snippets/blob/68e883f72771612ee1d94571c7ff4685d5857568/golang/ethereum/attestation/types.go#L75-L98
[^12]: https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidator
[^13]: https://github.com/rootwarp/snippets/blob/68e883f72771612ee1d94571c7ff4685d5857568/golang/ethereum/attestation/bls_test.go#L119-L141
[^14]: https://github.com/rootwarp/snippets/tree/68e883f72771612ee1d94571c7ff4685d5857568/golang/ethereum/attestation
