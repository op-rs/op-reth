package utils

import (
	"math/big"

	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/dsl"
	"github.com/ethereum-optimism/optimism/op-service/txplan"
	"github.com/ethereum/go-ethereum/core/types"
)

const MultiStorageArtifact = "../contracts/artifacts/MultiStorage.sol/MultiStorage.json"

type MultiStorage struct {
	*Contract
	t devtest.T
}

func (c *MultiStorage) SetValues(user *dsl.EOA, a, b *big.Int) *types.Receipt {
	ctx := c.t.Ctx()
	callData, err := c.parsedABI.Pack("setValues", a, b)
	if err != nil {
		c.t.Error("failed to pack set call data: %v", err)
		c.t.FailNow()
	}

	callTx := txplan.NewPlannedTx(user.Plan(), txplan.WithTo(&c.Contract.address), txplan.WithData(callData))
	callRes, err := callTx.Included.Eval(ctx)
	if err != nil {
		c.t.Error("failed to create set tx: %v", err)
		c.t.FailNow()
	}

	if callRes.Status != types.ReceiptStatusSuccessful {
		c.t.Error("set transaction failed")
		c.t.FailNow()
	}
	return callRes
}

func DeployMultiStorage(t devtest.T, user *dsl.EOA) (*MultiStorage, *types.Receipt) {
	parsedABI, bin := LoadArtifact(t, MultiStorageArtifact)
	contractAddress, receipt := DeployContract(t, user, bin)
	contract := NewContract(contractAddress, parsedABI)
	return &MultiStorage{contract, t}, receipt
}
