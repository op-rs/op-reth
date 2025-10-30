package proofs

import (
	"testing"

	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/presets"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/txplan"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

// TestTransactionsInMultipleBlocks tests adding transactions from different accounts
// at different blocks on L1. This verifies account state changes across multiple blocks.
func TestTransactionsInMultipleBlocks(t *testing.T) {
	dt := devtest.SerialT(t)
	preset := presets.NewMinimal(dt)

	// Create multiple funded accounts on L1
	const numAccounts = 3
	const initialFunding = 10 // ETH
	accounts := preset.FunderL1.NewFundedEOAs(numAccounts, eth.Ether(initialFunding))

	// Track initial balances
	initialBalances := make(map[common.Address]eth.ETH)
	for _, account := range accounts {
		initialBalances[account.Address()] = account.GetBalance()
		t.Logf("Account %s initial balance: %s ETH", account.Address().Hex(), account.GetBalance())
	}

	// Create recipient account
	recipient := preset.FunderL1.NewFundedEOA(eth.Ether(1))
	recipientAddr := recipient.Address()
	recipientInitialBalance := recipient.GetBalance()

	// Block 1: Send transaction from first account
	t.Log("Block 1: Sending transaction from account 0")
	currentBlock := preset.L1EL.WaitForBlock()
	t.Logf("Current L1 block number: %d", currentBlock.Number)

	transferAmount := eth.Ether(1)
	tx1 := accounts[0].Transfer(recipientAddr, transferAmount)
	receipt1, err := tx1.Included.Eval(dt.Ctx())
	require.NoError(t, err)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt1.Status)
	t.Logf("Transaction 1 hash: %s", receipt1.TxHash.Hex())
	t.Logf("Transaction 1 included in block: %d", receipt1.BlockNumber.Uint64())

	// Verify account 0 balance decreased
	balance0AfterTx1 := accounts[0].GetBalance()
	require.True(t, balance0AfterTx1.Lt(initialBalances[accounts[0].Address()]),
		"Account 0 balance should decrease after sending transaction")

	// Wait for next block
	preset.L1EL.WaitForBlockNumber(currentBlock.Number + 1)

	// Block 2: Send transaction from second account
	t.Log("Block 2: Sending transaction from account 1")
	currentBlock = preset.L1EL.WaitForBlock()
	t.Logf("Current L1 block number: %d", currentBlock.Number)

	tx2 := accounts[1].Transfer(recipientAddr, transferAmount)
	receipt2, err := tx2.Included.Eval(dt.Ctx())
	require.NoError(t, err)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt2.Status)
	t.Logf("Transaction 2 hash: %s", receipt2.TxHash.Hex())
	t.Logf("Transaction 2 included in block: %d", receipt2.BlockNumber.Uint64())

	// Verify transactions are in different blocks
	require.NotEqual(t, receipt1.BlockNumber.Uint64(), receipt2.BlockNumber.Uint64(),
		"Transactions should be in different blocks")

	// Verify account 1 balance decreased
	balance1AfterTx2 := accounts[1].GetBalance()
	require.True(t, balance1AfterTx2.Lt(initialBalances[accounts[1].Address()]),
		"Account 1 balance should decrease after sending transaction")

	// Wait for next block
	preset.L1EL.WaitForBlockNumber(currentBlock.Number + 1)

	// Block 3: Send transaction from third account
	t.Log("Block 3: Sending transaction from account 2")
	currentBlock = preset.L1EL.WaitForBlock()
	t.Logf("Current L1 block number: %d", currentBlock.Number)

	tx3 := accounts[2].Transfer(recipientAddr, transferAmount)
	receipt3, err := tx3.Included.Eval(dt.Ctx())
	require.NoError(t, err)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt3.Status)
	t.Logf("Transaction 3 hash: %s", receipt3.TxHash.Hex())
	t.Logf("Transaction 3 included in block: %d", receipt3.BlockNumber.Uint64())

	// Verify all transactions are in different blocks
	require.NotEqual(t, receipt2.BlockNumber.Uint64(), receipt3.BlockNumber.Uint64(),
		"Transactions 2 and 3 should be in different blocks")

	// Verify account 2 balance decreased
	balance2AfterTx3 := accounts[2].GetBalance()
	require.True(t, balance2AfterTx3.Lt(initialBalances[accounts[2].Address()]),
		"Account 2 balance should decrease after sending transaction")

	// Verify recipient received all transfers
	expectedRecipientBalance := recipientInitialBalance.Add(transferAmount.Mul(3))
	recipient.WaitForBalance(expectedRecipientBalance)
	finalRecipientBalance := recipient.GetBalance()
	require.Equal(t, expectedRecipientBalance, finalRecipientBalance,
		"Recipient should have received all 3 transfers")

	t.Logf("All transactions successfully processed across %d blocks",
		receipt3.BlockNumber.Uint64()-receipt1.BlockNumber.Uint64()+1)
}

// TestMultipleAccountsInSameBlock tests multiple accounts sending transactions
// that get included in the same L1 block or close blocks.
func TestMultipleAccountsInSameBlock(t *testing.T) {
	dt := devtest.SerialT(t)
	preset := presets.NewMinimal(dt)

	// Create multiple funded accounts on L1
	const numAccounts = 5
	const initialFunding = 10 // ETH
	accounts := preset.FunderL1.NewFundedEOAs(numAccounts, eth.Ether(initialFunding))

	// Create recipient
	recipient := preset.FunderL1.NewFundedEOA(eth.Ether(1))
	recipientAddr := recipient.Address()
	recipientInitialBalance := recipient.GetBalance()

	// Send transactions from all accounts
	transferAmount := eth.Ether(1)
	var txs []*txplan.PlannedTx

	t.Log("Sending transactions from multiple accounts")
	for i, account := range accounts {
		tx := account.Transfer(recipientAddr, transferAmount)
		txs = append(txs, tx)
		t.Logf("Sent transaction %d from account %s", i, account.Address().Hex())
	}

	// Wait for all transactions to be included
	for i, tx := range txs {
		receipt, err := tx.Included.Eval(dt.Ctx())
		require.NoError(t, err)
		require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
		t.Logf("Transaction %d included in block %d", i, receipt.BlockNumber.Uint64())
	}

	// Verify recipient received all transfers
	expectedBalance := recipientInitialBalance.Add(transferAmount.Mul(numAccounts))
	recipient.WaitForBalance(expectedBalance)
	finalBalance := recipient.GetBalance()
	require.Equal(t, expectedBalance, finalBalance,
		"Recipient should have received all transfers")

	// Verify all accounts' balances decreased
	for i, account := range accounts {
		balance := account.GetBalance()
		expected := eth.Ether(initialFunding).Sub(transferAmount)
		// Account for gas costs by checking balance is less than or equal to expected
		require.True(t, balance.Lt(expected) || balance.ToBig().Cmp(expected.ToBig()) == 0,
			"Account %d balance should be at most initial - transfer amount (accounting for gas)", i)
	}

	t.Logf("Successfully processed %d transactions from different accounts", numAccounts)
}

// TestAccountNonceProgression tests that account nonces progress correctly
// across multiple blocks and transactions.
func TestAccountNonceProgression(t *testing.T) {
	dt := devtest.SerialT(t)
	preset := presets.NewMinimal(dt)

	// Create a single funded account
	account := preset.FunderL1.NewFundedEOA(eth.Ether(10))
	recipient := preset.FunderL1.NewFundedEOA(eth.Ether(1))
	recipientAddr := recipient.Address()

	// Send multiple transactions from the same account across different blocks
	const numTransactions = 5
	transferAmount := eth.Ether(1)

	expectedNonce := account.PendingNonce()

	for i := 0; i < numTransactions; i++ {
		t.Logf("Block %d: Sending transaction with expected nonce %d", i+1, expectedNonce)

		// Verify nonce before sending
		currentNonce := account.PendingNonce()
		require.Equal(t, expectedNonce, currentNonce,
			"Nonce should match expected value before transaction %d", i)

		// Send transaction
		tx := account.Transfer(recipientAddr, transferAmount)
		receipt, err := tx.Included.Eval(dt.Ctx())
		require.NoError(t, err)
		require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)

		// Get the actual transaction
		signedTx, err := tx.Signed.Eval(dt.Ctx())
		require.NoError(t, err)

		t.Logf("Transaction %d hash: %s, nonce: %d, block: %d",
			i, receipt.TxHash.Hex(), signedTx.Nonce(), receipt.BlockNumber.Uint64())

		// Verify transaction used correct nonce
		require.Equal(t, expectedNonce, signedTx.Nonce(),
			"Transaction %d should use nonce %d", i, expectedNonce)

		expectedNonce++

		// Wait for next block before sending next transaction
		if i < numTransactions-1 {
			currentBlock := preset.L1EL.BlockRefByLabel("latest")
			preset.L1EL.WaitForBlockNumber(currentBlock.Number + 1)
		}
	}

	// Verify final nonce
	finalNonce := account.PendingNonce()
	require.Equal(t, expectedNonce, finalNonce,
		"Final nonce should be %d after %d transactions", expectedNonce, numTransactions)

	t.Logf("Successfully verified nonce progression from %d to %d across %d transactions",
		expectedNonce-uint64(numTransactions), finalNonce, numTransactions)
}

// TestConcurrentAccountTransactions tests concurrent transactions from multiple
// accounts to verify proper state management.
func TestConcurrentAccountTransactions(t *testing.T) {
	dt := devtest.SerialT(t)
	preset := presets.NewMinimal(dt)

	// Create multiple funded accounts
	const numSenders = 4
	const numRecipients = 3
	const initialFunding = 20 // ETH

	senders := preset.FunderL1.NewFundedEOAs(numSenders, eth.Ether(initialFunding))
	recipients := preset.FunderL1.NewFundedEOAs(numRecipients, eth.Ether(1))

	// Track initial balances
	recipientInitialBalances := make(map[common.Address]eth.ETH)
	for _, recipient := range recipients {
		recipientInitialBalances[recipient.Address()] = recipient.GetBalance()
	}

	// Each sender sends to each recipient
	transferAmount := eth.Ether(1)
	var allTxs []*txplan.PlannedTx

	t.Log("Sending transactions from multiple senders to multiple recipients")
	for i, sender := range senders {
		for j, recipient := range recipients {
			tx := sender.Transfer(recipient.Address(), transferAmount)
			allTxs = append(allTxs, tx)
			t.Logf("Sender %d → Recipient %d (tx initiated)", i, j)
		}
	}

	// Wait for all transactions to be included
	t.Log("Waiting for all transactions to be included...")
	for _, tx := range allTxs {
		receipt, err := tx.Included.Eval(dt.Ctx())
		require.NoError(t, err)
		require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
	}

	// Verify each recipient received correct amount
	expectedPerRecipient := transferAmount.Mul(numSenders)
	for i, recipient := range recipients {
		initialBalance := recipientInitialBalances[recipient.Address()]
		expectedBalance := initialBalance.Add(expectedPerRecipient)

		recipient.WaitForBalance(expectedBalance)
		finalBalance := recipient.GetBalance()

		require.Equal(t, expectedBalance, finalBalance,
			"Recipient %d should have received %d transfers", i, numSenders)

		t.Logf("Recipient %d: initial=%s, expected=%s, final=%s",
			i, initialBalance, expectedBalance, finalBalance)
	}

	t.Logf("Successfully processed %d transactions (%d senders × %d recipients)",
		len(allTxs), numSenders, numRecipients)
}

// TestAccountStateAcrossBlocks tests that account state (balance, nonce) is
// correctly maintained across multiple blocks with various transaction patterns.
func TestAccountStateAcrossBlocks(t *testing.T) {
	dt := devtest.SerialT(t)
	preset := presets.NewMinimal(dt)

	// Create test accounts
	account := preset.FunderL1.NewFundedEOA(eth.Ether(100))
	recipient1 := preset.FunderL1.NewFundedEOA(eth.Ether(1))
	recipient2 := preset.FunderL1.NewFundedEOA(eth.Ether(1))

	// Track state
	type AccountState struct {
		Balance eth.ETH
		Nonce   uint64
		Block   uint64
	}

	var states []AccountState
	recordState := func(blockNum uint64) {
		states = append(states, AccountState{
			Balance: account.GetBalance(),
			Nonce:   account.PendingNonce(),
			Block:   blockNum,
		})
		t.Logf("Block %d: balance=%s, nonce=%d",
			blockNum, account.GetBalance(), account.PendingNonce())
	}

	// Record initial state
	currentBlock := preset.L1EL.BlockRefByLabel("latest")
	recordState(currentBlock.Number)

	// Block 1: Single transaction
	t.Log("Block 1: Sending single transaction")
	tx1 := account.Transfer(recipient1.Address(), eth.Ether(10))
	receipt1, err := tx1.Included.Eval(dt.Ctx())
	require.NoError(t, err)
	recordState(receipt1.BlockNumber.Uint64())

	// Verify nonce increased
	require.Equal(t, states[0].Nonce+1, states[1].Nonce, "Nonce should increase by 1")

	// Block 2: Multiple transactions
	t.Log("Block 2: Sending multiple transactions")
	tx2a := account.Transfer(recipient2.Address(), eth.Ether(5))
	tx2b := account.Transfer(recipient1.Address(), eth.Ether(5))

	receipt2a, err := tx2a.Included.Eval(dt.Ctx())
	require.NoError(t, err)
	receipt2b, err := tx2b.Included.Eval(dt.Ctx())
	require.NoError(t, err)

	// Record state after both transactions
	laterBlock := receipt2a.BlockNumber.Uint64()
	if receipt2b.BlockNumber.Uint64() > laterBlock {
		laterBlock = receipt2b.BlockNumber.Uint64()
	}
	recordState(laterBlock)

	// Get the signed transactions to check nonces
	signedTx1, _ := tx1.Signed.Eval(dt.Ctx())
	signedTx2a, _ := tx2a.Signed.Eval(dt.Ctx())
	signedTx2b, _ := tx2b.Signed.Eval(dt.Ctx())

	// Verify nonces increased correctly
	require.Equal(t, signedTx1.Nonce()+1, signedTx2a.Nonce(), "tx2a nonce should follow tx1")
	require.Equal(t, signedTx2a.Nonce()+1, signedTx2b.Nonce(), "tx2b nonce should follow tx2a")

	// Block 3: Wait for a block without transactions
	t.Log("Block 3: Waiting for block without sending transaction")
	preset.L1EL.WaitForBlockNumber(laterBlock + 1)
	emptyBlockNum := preset.L1EL.BlockRefByLabel("latest").Number
	recordState(emptyBlockNum)

	// Verify state remains unchanged in empty block
	require.Equal(t, states[2].Balance, states[3].Balance,
		"Balance should remain the same in empty block")
	require.Equal(t, states[2].Nonce, states[3].Nonce,
		"Nonce should remain the same in empty block")

	// Block 4: Final transaction
	t.Log("Block 4: Sending final transaction")
	tx4 := account.Transfer(recipient2.Address(), eth.Ether(1))
	receipt4, err := tx4.Included.Eval(dt.Ctx())
	require.NoError(t, err)
	recordState(receipt4.BlockNumber.Uint64())

	// Verify final nonce
	finalNonce := states[len(states)-1].Nonce
	require.Equal(t, states[0].Nonce+4, finalNonce,
		"Final nonce should be initial + 4 (4 transactions sent)")

	t.Logf("Successfully tracked account state across %d blocks", len(states))
	t.Logf("Initial nonce: %d, Final nonce: %d", states[0].Nonce, finalNonce)
}

// TestTransactionReceiptVerification verifies that transaction receipts contain
// correct information about block inclusion and execution status.
func TestTransactionReceiptVerification(t *testing.T) {
	dt := devtest.SerialT(t)
	preset := presets.NewMinimal(dt)

	sender := preset.FunderL1.NewFundedEOA(eth.Ether(10))
	recipient := preset.FunderL1.NewFundedEOA(eth.Ether(1))

	// Send transaction
	transferAmount := eth.Ether(5)
	tx := sender.Transfer(recipient.Address(), transferAmount)
	receipt, err := tx.Included.Eval(dt.Ctx())
	require.NoError(t, err)

	// Verify receipt fields
	require.NotNil(t, receipt, "Receipt should not be nil")
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status,
		"Transaction should be successful")
	require.NotZero(t, receipt.BlockNumber.Uint64(), "Block number should be set")
	require.NotZero(t, receipt.GasUsed, "Gas used should be non-zero")
	require.NotEqual(t, common.Hash{}, receipt.TxHash, "Transaction hash should be set")

	t.Logf("Transaction receipt verified:")
	t.Logf("  Hash: %s", receipt.TxHash.Hex())
	t.Logf("  Block: %d", receipt.BlockNumber.Uint64())
	t.Logf("  Status: %d", receipt.Status)
	t.Logf("  Gas Used: %d", receipt.GasUsed)

	// Verify the transaction is in the specified block
	blockInfo := preset.L1EL.BlockRefByNumber(receipt.BlockNumber.Uint64())
	require.NotNil(t, blockInfo, "Block should exist")
	require.Equal(t, receipt.BlockNumber.Uint64(), blockInfo.Number,
		"Receipt block number should match block info")

	t.Logf("Block %d hash: %s", blockInfo.Number, blockInfo.Hash.Hex())
}
