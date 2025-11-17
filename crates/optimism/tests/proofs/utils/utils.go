package utils

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/dsl"
	"github.com/ethereum-optimism/optimism/op-service/txplan"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// minimal parts of artifact
type Artifact struct {
	ABI      json.RawMessage `json:"abi"`
	Bytecode struct {
		Object string `json:"object"`
	} `json:"bytecode"`
}

// LoadArtifact reads the forge artifact JSON at artifactPath and returns the parsed ABI
// and the creation bytecode (as bytes). It prefers bytecode.object (creation) and falls
// back to deployedBytecode.object if needed.
func LoadArtifact(t devtest.T, artifactPath string) (abi.ABI, []byte) {
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Errorf("failed to read artifact file: %v", err)
		t.FailNow()
	}

	var art Artifact
	if err := json.Unmarshal(data, &art); err != nil {
		t.Errorf("failed to unmarshal artifact JSON: %v", err)
		t.FailNow()
	}

	parsedABI, err := abi.JSON(strings.NewReader(string(art.ABI)))
	if err != nil {
		t.Errorf("failed to parse ABI: %v", err)
		t.FailNow()
	}

	binHex := strings.TrimSpace(art.Bytecode.Object)
	if binHex == "" {
		t.Errorf("artifact bytecode is empty")
		t.FailNow()
	}

	return parsedABI, common.FromHex(binHex)
}

// DeployContract deploys the contract creation bytecode from the given artifact.
// user must provide a Plan() method compatible with txplan.NewPlannedTx (kept generic).
func DeployContract(t devtest.T, user *dsl.EOA, bin []byte) (common.Address, *types.Receipt) {
	tx := txplan.NewPlannedTx(user.Plan(), txplan.WithData(bin))
	res, err := tx.Included.Eval(t.Ctx())
	if err != nil {
		t.Errorf("failed to deploy contract: %v", err)
		t.FailNow()
	}

	if res.Status != types.ReceiptStatusSuccessful {
		t.Error("contract deployment transaction failed")
		t.FailNow()
	}

	return res.ContractAddress, res
}
