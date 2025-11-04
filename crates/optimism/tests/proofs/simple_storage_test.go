package proofs

import (
	"math/big"
	"testing"

	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/dsl"
	"github.com/ethereum-optimism/optimism/op-devstack/presets"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/txplan"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func simpleStorageSetValue(t devtest.T, parsedABI *abi.ABI, user *dsl.EOA, contractAddress common.Address, value *big.Int) *types.Receipt {
	ctx := t.Ctx()
	callData, err := parsedABI.Pack("setValue", value)
	if err != nil {
		t.Error("failed to pack set call data: %v", err)
		t.FailNow()
	}

	callTx := txplan.NewPlannedTx(user.Plan(), txplan.WithTo(&contractAddress), txplan.WithData(callData))
	callRes, err := callTx.Included.Eval(ctx)
	if err != nil {
		t.Error("failed to create set tx: %v", err)
		t.FailNow()
	}

	if callRes.Status != types.ReceiptStatusSuccessful {
		t.Error("set transaction failed")
		t.FailNow()
	}
	return callRes
}

func TestStorageProofUsingSimpleStorageContract(gt *testing.T) {
	t := devtest.SerialT(gt)
	ctx := t.Ctx()

	sys := presets.NewSingleChainMultiNode(t)
	artifactPath := "contracts/artifacts/SimpleStorage.sol/SimpleStorage.json"
	parsedABI, bin, err := loadArtifact(artifactPath)
	if err != nil {
		t.Error("failed to load artifact: %v", err)
		t.FailNow()
	}

	user := sys.FunderL2.NewFundedEOA(eth.OneHundredthEther)

	// deploy contract via helper
	contractAddress, blockNum, err := deployContract(ctx, user, bin)
	if err != nil {
		t.Error("failed to deploy contract: %v", err)
		t.FailNow()
	}
	t.Logf("contract deployed at address %s in L2 block %d", contractAddress.Hex(), blockNum)

	// fetch and verify initial proof (should be zeroed storage)
	fetchAndVerifyProofs(ctx, t, sys, contractAddress, []common.Hash{common.HexToHash("0x0")}, blockNum)

	type caseEntry struct {
		Block uint64
		Value *big.Int
	}
	var cases []caseEntry
	for i := 1; i <= 5; i++ {
		writeVal := big.NewInt(int64(i * 10))
		callRes := simpleStorageSetValue(t, &parsedABI, user, contractAddress, writeVal)

		cases = append(cases, caseEntry{
			Block: callRes.BlockNumber.Uint64(),
			Value: writeVal,
		})
		t.Logf("setValue transaction included in L2 block %d", callRes.BlockNumber)
	}

	// test reset storage to zero
	callRes := simpleStorageSetValue(t, &parsedABI, user, contractAddress, big.NewInt(0))
	cases = append(cases, caseEntry{
		Block: callRes.BlockNumber.Uint64(),
		Value: big.NewInt(0),
	})
	t.Logf("reset setValue transaction included in L2 block %d", callRes.BlockNumber)

	// for each case, get proof and verify
	for _, c := range cases {
		fetchAndVerifyProofs(ctx, t, sys, contractAddress, []common.Hash{common.HexToHash("0x0")}, c.Block)
	}
}

func multiStorageSetValues(t devtest.T, parsedABI *abi.ABI, user *dsl.EOA, contractAddress common.Address, aVal, bVal *big.Int) *types.Receipt {
	ctx := t.Ctx()
	callData, err := parsedABI.Pack("setValues", aVal, bVal)
	if err != nil {
		t.Error("failed to pack set call data: %v", err)
		t.FailNow()
	}

	callTx := txplan.NewPlannedTx(user.Plan(), txplan.WithTo(&contractAddress), txplan.WithData(callData))
	callRes, err := callTx.Included.Eval(ctx)
	if err != nil {
		t.Error("failed to create set tx: %v", err)
		t.FailNow()
	}

	if callRes.Status != types.ReceiptStatusSuccessful {
		t.Error("set transaction failed")
		t.FailNow()
	}
	return callRes
}

func TestStorageProofUsingMultiStorageContract(gt *testing.T) {
	t := devtest.SerialT(gt)
	ctx := t.Ctx()

	sys := presets.NewSingleChainMultiNode(t)
	artifactPath := "contracts/artifacts/MultiStorage.sol/MultiStorage.json"
	parsedABI, bin, err := loadArtifact(artifactPath)
	if err != nil {
		t.Error("failed to load artifact: %v", err)
		t.FailNow()
	}

	user := sys.FunderL2.NewFundedEOA(eth.OneHundredthEther)

	// deploy contract via helper
	contractAddress, blockNum, err := deployContract(ctx, user, bin)
	if err != nil {
		t.Error("failed to deploy contract: %v", err)
		t.FailNow()
	}

	t.Logf("contract deployed at address %s in L2 block %d", contractAddress.Hex(), blockNum)

	// fetch and verify initial proof (should be zeroed storage)
	fetchAndVerifyProofs(ctx, t, sys, contractAddress, []common.Hash{common.HexToHash("0x0"), common.HexToHash("0x1")}, blockNum)

	// set multiple storage slots
	type caseEntry struct {
		Block      uint64
		SlotValues map[common.Hash]*big.Int
	}
	var cases []caseEntry

	for i := 1; i <= 5; i++ {
		aVal := big.NewInt(int64(i * 10))
		bVal := big.NewInt(int64(i * 20))
		callRes := multiStorageSetValues(t, &parsedABI, user, contractAddress, aVal, bVal)

		cases = append(cases, caseEntry{
			Block: callRes.BlockNumber.Uint64(),
			SlotValues: map[common.Hash]*big.Int{
				common.HexToHash("0x0"): aVal,
				common.HexToHash("0x1"): bVal,
			},
		})
		t.Logf("setValues transaction included in L2 block %d", callRes.BlockNumber)
	}

	// test reset storage slots to zero
	callRes := multiStorageSetValues(t, &parsedABI, user, contractAddress, big.NewInt(0), big.NewInt(0))
	cases = append(cases, caseEntry{
		Block: callRes.BlockNumber.Uint64(),
		SlotValues: map[common.Hash]*big.Int{
			common.HexToHash("0x0"): big.NewInt(0),
			common.HexToHash("0x1"): big.NewInt(0),
		},
	})
	t.Logf("reset setValues transaction included in L2 block %d", callRes.BlockNumber)

	// for each case, get proof and verify
	for _, c := range cases {
		var slots []common.Hash
		for slot := range c.SlotValues {
			slots = append(slots, slot)
		}

		fetchAndVerifyProofs(ctx, t, sys, contractAddress, slots, c.Block)
	}
}
