// This utility benchmarks the performance of the `eth_getProof` RPC method by simulating
// historical proof requests against a specific contract (WETH).
//
// How it works:
// 1. Setup: Configures the target RPC endpoint and block range via CLI flags.
// 2. Target: Targets the WETH contract and a pre-defined list of holder addresses.
// 3. Slot Calculation: For every request, it mathematically derives the storage slot for `balanceOf[address]`.
//   - Formula: keccak256(leftPad32(address) . leftPad32(slot_position))
//
// 4. Execution Loop:
//   - Iterates from `fromBlock` to `toBlock` with a defined `step`.
//   - Spawns concurrent workers to send `eth_getProof` requests.
//   - Measures the HTTP round-trip latency.
//
// 5. Reporting:
//   - Aggregates and prints latency statistics (Avg/Min/Max) per block interval.
//   - Performance metrics from the node's grafana dashboard can be correlated with these results for deeper analysis.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	rpcURL      string
	fromBlock   int
	toBlock     int
	step        int
	reqPerBlock int
	concurrent  int
)

const (
	contract = "0x4200000000000000000000000000000000000006"
)

var addresses = []common.Address{
	common.HexToAddress("0x48107537B9e358B1894c7a491C17E4bF035AFC74"),
	common.HexToAddress("0x917AbB78953902213F63e16268E78feBAC362846"),
	common.HexToAddress("0xA32Ce4EB5802809EB89032E6cc0FB06EB51bde38"),
	common.HexToAddress("0x8AE9Ed8aB2abF45376cDFb671c05170353dd1F0E"),
	common.HexToAddress("0x2195DbA1ab41966E91C22e4C601Be6517a40f2aB"),
	common.HexToAddress("0x04bF3799798077629cb627DfF76E48a015f0B3CB"),
	common.HexToAddress("0x5aaFa65D234e962121C6f44fd570EE353Ac52Bf5"),
	common.HexToAddress("0x5aaFa65D234e962121C6f44fd570EE353Ac52Bf5"),
	common.HexToAddress("0x2a58adA546c2e9cd3134c163FBfC0E335Ff91AfA"),
	common.HexToAddress("0x8AE9Ed8aB2abF45376cDFb671c05170353dd1F0E"),
	common.HexToAddress("0x8524771B4c5a8122E8959cFDeB641E3f498188AF"),
	common.HexToAddress("0xf530AD425154CC9635CAaD538e8bf3C638191a4E"),
	common.HexToAddress("0x73a5bB60b0B0fc35710DDc0ea9c407031E31Bdbb"),
	common.HexToAddress("0xfE978E4Dc6f3d716121c603311b0c37a9acd7234"),
	common.HexToAddress("0xcAAd4EB9ABfc93Ab9eA86FB5733B8F85c952200b"),
	common.HexToAddress("0xd15b5531050AC78Aa78AeF8A6DE4256Fa4536107"),
}

type RPCRequest struct {
	Jsonrpc string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type RPCResponse struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Sample struct {
	LatencyMs float64
	Success   bool
}

func main() {
	flag.StringVar(&rpcURL, "rpc", "http://localhost:8545", "RPC Endpoint URL")
	flag.IntVar(&fromBlock, "from", -1, "Start block number (required)")
	flag.IntVar(&toBlock, "to", -1, "End block number (required)")
	flag.IntVar(&step, "step", 100000, "Step size")
	flag.IntVar(&reqPerBlock, "reqs", 10, "Number of samples per block")
	flag.IntVar(&concurrent, "workers", 2, "Concurrency limit")
	flag.Parse()

	if fromBlock == -1 || toBlock == -1 {
		fmt.Fprintln(os.Stderr, "Error: -from and -to flags are required")
		flag.Usage()
		os.Exit(1)
	}

	start := time.Now()

	// Print Header
	fmt.Printf("%-15s %-15s %-15s %-15s %-15s\n", "Block", "Avg(ms)", "Min(ms)", "Max(ms)", "Errors")

	// concurrency pool
	sem := make(chan struct{}, concurrent)

	for block := fromBlock; block <= toBlock; block += step {
		var wg sync.WaitGroup
		results := make(chan Sample, reqPerBlock)

		for i := 0; i < reqPerBlock; i++ {
			wg.Add(1)
			sem <- struct{}{}

			go func(attempt int) {
				defer wg.Done()
				s := runProof(block, attempt)
				results <- s
				<-sem
			}(i + 1)
		}

		wg.Wait()
		close(results)

		var totalLatency float64
		var minLatency float64 = math.MaxFloat64
		var maxLatency float64
		var errorCount int
		var count int

		for s := range results {
			count++
			totalLatency += s.LatencyMs
			if s.LatencyMs < minLatency {
				minLatency = s.LatencyMs
			}
			if s.LatencyMs > maxLatency {
				maxLatency = s.LatencyMs
			}
			if !s.Success {
				errorCount++
			}
		}

		avgLatency := 0.0
		if count > 0 {
			avgLatency = totalLatency / float64(count)
		} else {
			minLatency = 0
		}

		fmt.Printf("%-15d %-15.2f %-15.2f %-15.2f %-15d\n", block, avgLatency, minLatency, maxLatency, errorCount)
	}

	elapsed := time.Since(start)
	fmt.Printf("\nTotal time: %s\n", elapsed)
}

func balanceOfSlot(addr common.Address) common.Hash {
	key := common.LeftPadBytes(addr.Bytes(), 32)
	slot := common.LeftPadBytes(big.NewInt(3).Bytes(), 32)
	return crypto.Keccak256Hash(append(key, slot...))
}

func runProof(block int, attempt int) Sample {
	start := time.Now()

	// randomly select an address
	addr := addresses[attempt%len(addresses)]
	slot := balanceOfSlot(addr)

	params := []interface{}{
		contract,
		[]string{slot.Hex()},
		fmt.Sprintf("0x%x", block),
	}

	req := RPCRequest{
		Jsonrpc: "2.0",
		ID:      attempt,
		Method:  "eth_getProof",
		Params:  params,
	}

	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", rpcURL, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	latency := float64(time.Since(start).Milliseconds())
	if err != nil {
		return Sample{
			LatencyMs: latency,
			Success:   false,
		}
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	var rpcResp RPCResponse
	err = json.Unmarshal(data, &rpcResp)
	if err != nil {
		return Sample{
			LatencyMs: latency,
			Success:   false,
		}
	}

	if rpcResp.Error != nil {
		return Sample{
			LatencyMs: latency,
			Success:   false,
		}
	}

	return Sample{
		LatencyMs: latency,
		Success:   true,
	}
}
