package utils

import (
	"math/big"

	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/dsl"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/txplan"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const TokenVaultArtifact = "../contracts/artifacts/TokenVault.sol/TokenVault.json"
const BalanceSlotIndex = 0
const AllowanceSlotIndex = 1
const DepositorSlotIndex = 2

type TokenVault struct {
	*Contract
	t devtest.T
}

func (c *TokenVault) Deposit(user *dsl.EOA, amount eth.ETH) *types.Receipt {
	depositCalldata, err := c.Contract.parsedABI.Pack("deposit")
	if err != nil {
		c.t.Errorf("failed to pack deposit: %v", err)
		c.t.FailNow()
	}
	depTx := txplan.NewPlannedTx(user.Plan(), txplan.WithTo(&c.Contract.address), txplan.WithData(depositCalldata), txplan.WithValue(amount))
	depRes, err := depTx.Included.Eval(c.t.Ctx())
	if err != nil {
		c.t.Errorf("deposit tx failed: %v", err)
		c.t.FailNow()
	}

	if depRes.Status != types.ReceiptStatusSuccessful {
		c.t.Error("deposit transaction failed")
		c.t.FailNow()
	}

	return depRes
}

func (c *TokenVault) Approve(user *dsl.EOA, spender common.Address, amount *big.Int) *types.Receipt {
	approveCalldata, err := c.Contract.parsedABI.Pack("approve", spender, amount)
	if err != nil {
		c.t.Errorf("failed to pack approve: %v", err)
		c.t.FailNow()
	}

	approveTx := txplan.NewPlannedTx(user.Plan(), txplan.WithTo(&c.Contract.address), txplan.WithData(approveCalldata))
	approveRes, err := approveTx.Included.Eval(c.t.Ctx())
	if err != nil {
		c.t.Errorf("approve tx failed: %v", err)
		c.t.FailNow()
	}

	if approveRes.Status != types.ReceiptStatusSuccessful {
		c.t.Error("approve transaction failed")
		c.t.FailNow()
	}
	return approveRes
}

func (c *TokenVault) DeactivateAllowance(user *dsl.EOA, spender common.Address) *types.Receipt {
	deactCalldata, err := c.Contract.parsedABI.Pack("deactivateAllowance", spender)
	if err != nil {
		c.t.Errorf("failed to pack deactivateAllowance: %v", err)
		c.t.FailNow()
	}
	deactTx := txplan.NewPlannedTx(user.Plan(), txplan.WithTo(&c.Contract.address), txplan.WithData(deactCalldata))
	deactRes, err := deactTx.Included.Eval(c.t.Ctx())
	if err != nil {
		c.t.Errorf("deactivateAllowance tx failed: %v", err)
		c.t.FailNow()
	}

	if deactRes.Status != types.ReceiptStatusSuccessful {
		c.t.Error("deactivateAllowance transaction failed")
		c.t.FailNow()
	}
	return deactRes
}

func (c *TokenVault) GetBalanceSlot(user common.Address) common.Hash {
	keyBytes := common.LeftPadBytes(user.Bytes(), 32)
	slotBytes := common.LeftPadBytes(new(big.Int).SetUint64(BalanceSlotIndex).Bytes(), 32)
	return crypto.Keccak256Hash(append(keyBytes, slotBytes...))
}

func (c *TokenVault) GetAllowanceSlot(owner, spender common.Address) common.Hash {
	ownerBytes := common.LeftPadBytes(owner.Bytes(), 32)
	slotBytes := common.LeftPadBytes(new(big.Int).SetUint64(AllowanceSlotIndex).Bytes(), 32)
	inner := crypto.Keccak256(ownerBytes, slotBytes)
	spenderBytes := common.LeftPadBytes(spender.Bytes(), 32)
	return crypto.Keccak256Hash(append(spenderBytes, inner...))
}

func (c *TokenVault) GetDepositorSlot(index uint64) common.Hash {
	slotBytes := common.LeftPadBytes(new(big.Int).SetUint64(DepositorSlotIndex).Bytes(), 32)
	base := crypto.Keccak256(slotBytes)
	baseInt := new(big.Int).SetBytes(base)
	elem := new(big.Int).Add(baseInt, new(big.Int).SetUint64(index))
	return common.BigToHash(elem)
}

func DeployTokenVault(t devtest.T, user *dsl.EOA) (*TokenVault, *types.Receipt) {
	parsedABI, bin := LoadArtifact(t, TokenVaultArtifact)
	contractAddress, receipt := DeployContract(t, user, bin)
	contract := NewContract(contractAddress, parsedABI)
	return &TokenVault{contract, t}, receipt
}
