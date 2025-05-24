package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/ripemd160"
)

// =============================================================================
// Wallet Logic (core/wallet.go)
// =============================================================================

type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

func NewWallet() (*Wallet, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	public := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)
	return &Wallet{PrivateKey: *private, PublicKey: public}, nil
}

func (w *Wallet) GetAddress() string {
	pubHash := sha256.Sum256(w.PublicKey)

	hasher := ripemd160.New()
	hasher.Write(pubHash[:])
	publicRipemd := hasher.Sum(nil)

	versionedPayload := append([]byte{0x00}, publicRipemd...)
	checksum := checksum(versionedPayload)

	fullPayload := append(versionedPayload, checksum...)
	address := base58Encode(fullPayload)

	return string(address)
}

func (w *Wallet) Sign(data string) ([]byte, error) {
	hash := sha256.Sum256([]byte(data))
	signature, err := ecdsa.SignASN1(rand.Reader, &w.PrivateKey, hash[:])
	return signature, err
}

func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])
	return secondSHA[:4]
}

func base58Encode(input []byte) []byte {
	b58Alphabet := []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	var result []byte

	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, b58Alphabet[mod.Int64()])
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	for i := 0; i < len(input) && input[i] == 0; i++ {
		result = append([]byte{b58Alphabet[0]}, result...)
	}

	return result
}

// =============================================================================
// Transaction Logic (core/transaction.go)
// =============================================================================

const (
	MiningReward = 12.5
)

type Transaction struct {
	ID        string
	From      string
	To        string
	Amount    float64
	Timestamp int64
	Signature []byte
}

func (tx *Transaction) calculateID() string {
	data := fmt.Sprintf("%s%s%f%d", tx.From, tx.To, tx.Amount, tx.Timestamp)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func NewCoinbaseTX(toAddress string) *Transaction {
	tx := &Transaction{
		From:      "COINBASE",
		To:        toAddress,
		Amount:    MiningReward,
		Timestamp: time.Now().UnixNano(),
	}
	tx.ID = tx.calculateID()
	return tx
}

type Mempool struct {
	transactions map[string]*Transaction
	mutex        sync.Mutex
}

func NewMempool() *Mempool {
	return &Mempool{
		transactions: make(map[string]*Transaction),
	}
}

func (m *Mempool) Add(tx *Transaction) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.transactions[tx.ID] = tx
}

func (m *Mempool) AddBatch(txs []*Transaction) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	for _, tx := range txs {
		m.transactions[tx.ID] = tx
	}
}

func (m *Mempool) GetAll() []*Transaction {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var txs []*Transaction
	for _, tx := range m.transactions {
		txs = append(txs, tx)
	}
	return txs
}

func (m *Mempool) Clear() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.transactions = make(map[string]*Transaction)
}

// =============================================================================
// Blockchain Logic (core/blockchain.go)
// =============================================================================

const (
	DifficultyAdjustmentInterval = 10
	TargetBlockTime              = 10 * time.Second
)

type Block struct {
	Index        int64
	Timestamp    int64
	Transactions []*Transaction
	PreviousHash string
	Hash         string
	Nonce        int64
	Difficulty   int
}

func NewBlock(index int64, transactions []*Transaction, prevHash string, difficulty int) *Block {
	return &Block{
		Index:        index,
		Timestamp:    time.Now().UnixNano(),
		Transactions: transactions,
		PreviousHash: prevHash,
		Difficulty:   difficulty,
	}
}

func (b *Block) CalculateHash() string {
	txHashes := []string{}
	for _, tx := range b.Transactions {
		txHashes = append(txHashes, tx.ID)
	}
	sort.Strings(txHashes)
	txData, _ := json.Marshal(txHashes)

	data := fmt.Sprintf("%d%d%s%s%d%d", b.Index, b.Timestamp, string(txData), b.PreviousHash, b.Nonce, b.Difficulty)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

type Blockchain struct {
	Blocks     []*Block
	Difficulty int
	mempool    *Mempool
	mutex      sync.Mutex
}

func NewBlockchain(difficulty int) *Blockchain {
	genesisBlock := createGenesisBlock()
	genesisBlock.Difficulty = difficulty
	genesisBlock.Hash = genesisBlock.CalculateHash()

	return &Blockchain{
		Blocks:     []*Block{genesisBlock},
		Difficulty: difficulty,
		mempool:    NewMempool(),
	}
}

func createGenesisBlock() *Block {
	tx := NewCoinbaseTX("genesis")
	return NewBlock(0, []*Transaction{tx}, "0", 1)
}

func (bc *Blockchain) GetLatestBlock() *Block {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	return bc.Blocks[len(bc.Blocks)-1]
}

func (bc *Blockchain) AddBlock(block *Block) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	if bc.isBlockValid(block) {
		bc.Blocks = append(bc.Blocks, block)
		bc.adjustDifficulty()
	}
}

func (bc *Blockchain) isBlockValid(block *Block) bool {
	lastBlock := bc.Blocks[len(bc.Blocks)-1]
	if block.Index != lastBlock.Index+1 {
		return false
	}
	if block.PreviousHash != lastBlock.Hash {
		return false
	}
	if block.CalculateHash() != block.Hash {
		return false
	}
	return true
}

func (bc *Blockchain) adjustDifficulty() {
	if len(bc.Blocks)%DifficultyAdjustmentInterval != 0 {
		return
	}

	lastAdjustmentBlock := bc.Blocks[len(bc.Blocks)-DifficultyAdjustmentInterval]
	expectedTime := time.Duration(DifficultyAdjustmentInterval) * TargetBlockTime
	actualTime := time.Unix(0, bc.GetLatestBlock().Timestamp).Sub(time.Unix(0, lastAdjustmentBlock.Timestamp))

	if actualTime < expectedTime/2 {
		bc.Difficulty++
	} else if actualTime > expectedTime*2 && bc.Difficulty > 1 {
		bc.Difficulty--
	}
}

func (bc *Blockchain) GetDifficulty() int {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	return bc.Difficulty
}

func (bc *Blockchain) NewTransaction(senderWallet *Wallet, recipient string, amount float64) (*Transaction, error) {
	senderAddress := senderWallet.GetAddress()
	balance := bc.GetBalance(senderAddress)

	if balance < amount {
		return nil, fmt.Errorf("insufficient funds. Balance: %.4f, Amount: %.4f", balance, amount)
	}

	tx := &Transaction{
		From:      senderAddress,
		To:        recipient,
		Amount:    amount,
		Timestamp: time.Now().UnixNano(),
	}
	tx.ID = tx.calculateID()

	signature, err := senderWallet.Sign(tx.ID)
	if err != nil {
		return nil, err
	}
	tx.Signature = signature

	return tx, nil
}

func (bc *Blockchain) GetBalance(address string) float64 {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	balance := 0.0
	for _, block := range bc.Blocks {
		for _, tx := range block.Transactions {
			if tx.From == address {
				balance -= tx.Amount
			}
			if tx.To == address {
				balance += tx.Amount
			}
		}
	}
	return balance
}

// =============================================================================
// Miner Logic (miner/miner.go)
// =============================================================================

type Miner struct {
	Blockchain   *Blockchain
	Mempool      *Mempool
	MinerAddress string
	StopChan     chan bool
}

func NewMiner(bc *Blockchain, mempool *Mempool, minerAddress string, stopChan chan bool) *Miner {
	return &Miner{
		Blockchain:   bc,
		Mempool:      mempool,
		MinerAddress: minerAddress,
		StopChan:     stopChan,
	}
}

func (m *Miner) Mine() {
	color.Green("Mining process started. Good luck!")
	time.Sleep(1 * time.Second)

	for {
		select {
		case <-m.StopChan:
			color.Red("\nMining process stopped by user.")
			return
		default:
			m.mineBlock()
		}
	}
}

func (m *Miner) mineBlock() {
	lastBlock := m.Blockchain.GetLatestBlock()
	difficulty := m.Blockchain.GetDifficulty()

	transactions := m.Mempool.GetAll()
	if len(transactions) == 0 {
		color.Yellow("\rMempool is empty. Waiting for transactions...")
		time.Sleep(2 * time.Second)
		return
	}

	coinbaseTx := NewCoinbaseTX(m.MinerAddress)
	transactions = append([]*Transaction{coinbaseTx}, transactions...)

	newBlock := NewBlock(lastBlock.Index+1, transactions, lastBlock.Hash, difficulty)

	target := strings.Repeat("0", difficulty)
	startTime := time.Now()

	var nonce int64
	for {
		select {
		case <-m.StopChan:
			m.Mempool.AddBatch(transactions[1:])
			return
		default:
			nonce++
			newBlock.Nonce = nonce
			newBlock.Timestamp = time.Now().UnixNano()
			hash := newBlock.CalculateHash()

			if strings.HasPrefix(hash, target) {
				newBlock.Hash = hash
				m.Blockchain.AddBlock(newBlock)
				m.Mempool.Clear()

				duration := time.Since(startTime)
				hashRate := float64(nonce) / duration.Seconds()

				color.HiGreen("\n\n=============================================")
				color.HiGreen("    🎉 Block Mined Successfully! 🎉")
				color.HiGreen("=============================================")
				color.White("Block Index  : %d", newBlock.Index)
				color.White("Nonce        : %d", newBlock.Nonce)
				color.White("Hash         : %s", newBlock.Hash)
				color.White("Mining Time  : %s", duration.Round(time.Millisecond))
				color.White("Hash Rate    : %.2f H/s", hashRate)
				color.Yellow("Reward       : %.4f GBC", MiningReward)
				color.HiGreen("=============================================\n")

				time.Sleep(3 * time.Second)
				return
			}

			if nonce%10000 == 0 {
				hashRate := float64(nonce) / time.Since(startTime).Seconds()
				color.Cyan("\rMining... [Nonce: %d] [Hashrate: %.0f H/s] [Target: %s...]", nonce, hashRate, target)
			}
		}
	}
}

// =============================================================================
// CLI Logic (cli/cli.go)
// =============================================================================

type CLI struct {
	bc      *Blockchain
	wallet  *Wallet
	mempool *Mempool
}

func NewCLI(bc *Blockchain, wallet *Wallet) *CLI {
	return &CLI{
		bc:      bc,
		wallet:  wallet,
		mempool: NewMempool(),
	}
}

func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

func (cli *CLI) Run() {
	reader := bufio.NewReader(os.Stdin)

	for {
		cli.printMenu()
		cmdString, _ := reader.ReadString('\n')
		cmdString = strings.TrimSpace(cmdString)

		switch cmdString {
		case "1":
			cli.startMining(reader)
		case "2":
			cli.createTransaction(reader)
		case "3":
			cli.printBlockchain()
		case "4":
			cli.printMempool()
		case "5":
			cli.showWallet()
		case "6":
			ClearScreen()
			os.Exit(0)
		default:
			color.Red("Invalid command. Please try again.")
			time.Sleep(1 * time.Second)
		}
	}
}

func (cli *CLI) printMenu() {
	ClearScreen()
	color.Cyan("=============================================")
	color.Yellow("          GO-BLOCKCHAIN MINER v2.0")
	color.Cyan("=============================================")
	fmt.Println()
	color.Green("  1. Start Mining")
	color.Green("  2. Create Transaction")
	color.Green("  3. View Blockchain")
	color.Green("  4. View Mempool")
	color.Green("  5. Show Wallet Info")
	color.Green("  6. Exit")
	fmt.Println()
	color.Cyan("---------------------------------------------")
	fmt.Print("Enter command: ")
}

func (cli *CLI) startMining(reader *bufio.Reader) {
	stopChan := make(chan bool)
	miner := NewMiner(cli.bc, cli.mempool, cli.wallet.GetAddress(), stopChan)

	go miner.Mine()

	fmt.Println("\nPress 's' and Enter to stop mining...")
	for {
		input, _ := reader.ReadString('\n')
		if strings.TrimSpace(input) == "s" {
			stopChan <- true
			break
		}
	}
	color.Yellow("\nReturning to main menu...")
	time.Sleep(2 * time.Second)
}

func (cli *CLI) createTransaction(reader *bufio.Reader) {
	ClearScreen()
	color.Yellow("--- Create New Transaction ---")

	fmt.Print("Recipient Address: ")
	recipient, _ := reader.ReadString('\n')
	recipient = strings.TrimSpace(recipient)

	fmt.Print("Amount: ")
	amountStr, _ := reader.ReadString('\n')
	amount, err := strconv.ParseFloat(strings.TrimSpace(amountStr), 64)
	if err != nil {
		color.Red("Invalid amount.")
		time.Sleep(2 * time.Second)
		return
	}

	tx, err := cli.bc.NewTransaction(cli.wallet, recipient, amount)
	if err != nil {
		color.Red("Failed to create transaction: %v", err)
		time.Sleep(2 * time.Second)
		return
	}

	cli.mempool.Add(tx)
	color.Green("\nTransaction successfully created and added to mempool!")
	time.Sleep(2 * time.Second)
}

func (cli *CLI) printBlockchain() {
	ClearScreen()
	color.Cyan("--- Full Blockchain ---")
	for i := len(cli.bc.Blocks) - 1; i >= 0; i-- {
		block := cli.bc.Blocks[i]
		color.Yellow("\nBlock #%d", block.Index)
		color.Cyan("------------------------------------------------------------------")
		fmt.Printf("Timestamp    : %s\n", time.Unix(0, block.Timestamp).Format(time.RFC1123))
		fmt.Printf("Transactions : %d\n", len(block.Transactions))
		fmt.Printf("Nonce        : %d\n", block.Nonce)
		fmt.Printf("Difficulty   : %d\n", block.Difficulty)
		fmt.Printf("Hash         : %s\n", block.Hash)
		fmt.Printf("Previous Hash: %s\n", block.PreviousHash)
		color.Cyan("------------------------------------------------------------------")
	}
	fmt.Print("\nPress Enter to return to menu...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func (cli *CLI) printMempool() {
	ClearScreen()
	color.Cyan("--- Mempool (Pending Transactions) ---")
	transactions := cli.mempool.GetAll()
	if len(transactions) == 0 {
		color.Yellow("Mempool is empty.")
	} else {
		for _, tx := range transactions {
			color.Green("\nTransaction ID: %s", tx.ID)
			fmt.Printf("From    : %s\n", tx.From)
			fmt.Printf("To      : %s\n", tx.To)
			fmt.Printf("Amount  : %.4f\n", tx.Amount)
			color.Cyan("------------------------------------")
		}
	}

	fmt.Print("\nPress Enter to return to menu...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func (cli *CLI) showWallet() {
	ClearScreen()
	color.Cyan("--- Your Wallet Information ---")
	address := cli.wallet.GetAddress()
	balance := cli.bc.GetBalance(address)
	color.Yellow("\nAddress:")
	fmt.Printf("%s\n", address)
	color.Yellow("\nCurrent Balance:")
	color.Green("%.4f GBC\n", balance)

	fmt.Print("\nPress Enter to return to menu...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

// =============================================================================
// Main Function (Application Entrypoint)
// =============================================================================

func main() {
	difficulty := 2
	blockchain := NewBlockchain(difficulty)

	userWallet, err := NewWallet()
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}

	app := NewCLI(blockchain, userWallet)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		ClearScreen()
		fmt.Println("Program exited gracefully.")
		os.Exit(0)
	}()

	app.Run()
}
