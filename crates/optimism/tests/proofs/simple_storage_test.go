package proofs

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/dsl"
	"github.com/ethereum-optimism/optimism/op-devstack/presets"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/txplan"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

// minimal parts of artifact
type artifact struct {
	ABI      json.RawMessage `json:"abi"`
	Bytecode struct {
		Object string `json:"object"`
	} `json:"bytecode"`
}

// loadArtifact reads the forge artifact JSON at artifactPath and returns the parsed ABI
// and the creation bytecode (as bytes). It prefers bytecode.object (creation) and falls
// back to deployedBytecode.object if needed.
func loadArtifact(artifactPath string) (abi.ABI, []byte, error) {
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return abi.ABI{}, nil, err
	}
	var art artifact
	if err := json.Unmarshal(data, &art); err != nil {
		return abi.ABI{}, nil, err
	}
	parsedABI, err := abi.JSON(strings.NewReader(string(art.ABI)))
	if err != nil {
		return abi.ABI{}, nil, err
	}
	binHex := strings.TrimSpace(art.Bytecode.Object)
	if binHex == "" {
		return parsedABI, nil, fmt.Errorf("artifact missing bytecode")
	}
	return parsedABI, common.FromHex(binHex), nil
}

// deployContract deploys the contract creation bytecode from the given artifact.
// user must provide a Plan() method compatible with txplan.NewPlannedTx (kept generic).
func deployContract(ctx context.Context, user *dsl.EOA, bin []byte) (common.Address, uint64, error) {
	tx := txplan.NewPlannedTx(user.Plan(), txplan.WithData(bin))
	res, err := tx.Included.Eval(ctx)
	if err != nil {
		return common.Address{}, 0, fmt.Errorf("deployment eval: %w", err)
	}
	return res.ContractAddress, res.BlockNumber.Uint64(), nil
}

func fetchAndVerifyProofs(ctx context.Context, t devtest.T, sys *presets.SingleChainMultiNode, contractAddress common.Address, slots []common.Hash, block uint64) {
	gethProofRes, err := sys.L2EL.Escape().L2EthClient().GetProof(ctx, contractAddress, slots, hexutil.Uint64(block).String())
	if err != nil {
		t.Error("failed to get proof from L2EL at block %d: %v", block, err)
		t.FailNow()
	}

	rethProofRes, err := sys.L2ELB.Escape().L2EthClient().GetProof(ctx, contractAddress, slots, hexutil.Uint64(block).String())
	if err != nil {
		t.Error("failed to get proof from L2ELB at block %d: %v", block, err)
		t.FailNow()
	}

	require.Equal(t, gethProofRes, rethProofRes, "geth and reth proofs should match")

	blockInfo, err := sys.L2EL.Escape().L2EthClient().InfoByNumber(ctx, block)
	if err != nil {
		t.Error("failed to get L2 block %d: %v", block, err)
		t.FailNow()
	}

	err = rethProofRes.Verify(blockInfo.Root())
	if err != nil {
		t.Error("proof verification failed at block %d: %v", block, err)
		t.FailNow()
	}
}

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
	// callRes := simpleStorageSetValue(t, &parsedABI, user, contractAddress, big.NewInt(0))
	// cases = append(cases, caseEntry{
	// 	Block: callRes.BlockNumber.Uint64(),
	// 	Value: big.NewInt(0),
	// })
	// t.Logf("reset setValue transaction included in L2 block %d", callRes.BlockNumber)

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
