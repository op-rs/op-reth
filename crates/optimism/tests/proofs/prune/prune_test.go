package prune

import (
	"testing"
	"time"

	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/presets"
	"github.com/ethereum-optimism/optimism/op-service/apis"
	"github.com/stretchr/testify/require"
)

func TestPruneProofStorage(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := presets.NewSingleChainMultiNode(t)

	var proofWindow = uint64(200)         // Defined in the devnet yaml
	var prunerPruneInterval = time.Minute // Defined in the devnet yaml

	synceStatus := getProofSyncStatus(t, sys.L2ELB.Escape().EthClient())
	distance := synceStatus.Latest - synceStatus.Earliest
	if distance < proofWindow {
		// Wait till we reach proof window
		t.Logf("Waiting for block %d", synceStatus.Earliest+proofWindow)
		sys.L2ELB.WaitForBlockNumber(synceStatus.Earliest + proofWindow)
	}
	// Now we need to wait for pruner to execute pruning can be done anytime in 1 minutes(pruner prune interval = 1min)
	startTime := time.Now()
	for {
		// Get sync status each Second
		if time.Since(startTime) > prunerPruneInterval {
			t.Error("Pruner did not prune proof storage within the interval")
		}
		newSynceStatus := getProofSyncStatus(t, sys.L2ELB.Escape().EthClient())
		if synceStatus.Earliest == newSynceStatus.Earliest {
			t.Log("Sync status: %v", synceStatus)
			time.Sleep(time.Second)
			continue
		}
		// Check how many has been pruned -  we should have current proof window intake
		currentProofWindow := newSynceStatus.Latest - newSynceStatus.Earliest
		t.Log("Sync status:", synceStatus)
		require.GreaterOrEqual(t, currentProofWindow, proofWindow, "Pruner has changed the proof window")
		t.Logf("Successfully pruned proof storage. synce status: %v", synceStatus)
	}

}

type proofSyncStatus struct {
	Earliest uint64 `json:"earliest"`
	Latest   uint64 `json:"latest"`
}

func getProofSyncStatus(t devtest.T, client apis.EthClient) proofSyncStatus {
	var result proofSyncStatus
	err := client.RPC().CallContext(t.Ctx(), &result, "debug_proofsSyncStatus")
	if err != nil {
		t.Error(err)
	}
	return result
}
