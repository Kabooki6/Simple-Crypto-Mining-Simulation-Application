package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Block struct {
	Index        int
	Timestamp    int64
	Data         string
	PreviousHash string
	Hash         string
	Nonce        int
}

func (b *Block) calculateHash() string {
	record := strconv.Itoa(b.Index) +
		strconv.FormatInt(b.Timestamp, 10) +
		b.Data +
		b.PreviousHash +
		strconv.Itoa(b.Nonce)

	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func (b *Block) mineBlock(difficulty int) {
	target := strings.Repeat("0", difficulty)
	startTime := time.Now()

	for !strings.HasPrefix(b.Hash, target) {
		b.Nonce++
		b.Hash = b.calculateHash()
	}
	endTime := time.Now()
	miningTime := endTime.Sub(startTime)

	fmt.Printf("Block mined: %s (Nonce: %d, Time: %s)\n", b.Hash, b.Nonce, miningTime)
}

type Blockchain struct {
	Blocks     []*Block
	Difficulty int
}

func NewBlockchain(difficulty int) *Blockchain {
	genesisBlock := &Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		Data:         "Genesis Block",
		PreviousHash: "0",
		Nonce:        0,
	}
	genesisBlock.Hash = genesisBlock.calculateHash()

	return &Blockchain{
		Blocks:     []*Block{genesisBlock},
		Difficulty: difficulty,
	}
}

func (bc *Blockchain) GetLatestBlock() *Block {
	return bc.Blocks[len(bc.Blocks)-1]
}

func (bc *Blockchain) AddBlock(data string) {
	latestBlock := bc.GetLatestBlock()
	newBlock := &Block{
		Index:        latestBlock.Index + 1,
		Timestamp:    time.Now().Unix(),
		Data:         data,
		PreviousHash: latestBlock.Hash,
		Nonce:        0,
	}
	newBlock.Hash = newBlock.calculateHash()
	fmt.Printf("Mining block %d with data: '%s'...\n", newBlock.Index, newBlock.Data)
	newBlock.mineBlock(bc.Difficulty)
	bc.Blocks = append(bc.Blocks, newBlock)
	fmt.Println("Block successfully added to the chain.\n")
}

func (bc *Blockchain) IsChainValid() bool {
	for i := 1; i < len(bc.Blocks); i++ {
		currentBlock := bc.Blocks[i]
		previousBlock := bc.Blocks[i-1]

		if currentBlock.Hash != currentBlock.calculateHash() {
			fmt.Printf("Invalid hash for block %d. Expected %s, got %s\n",
				currentBlock.Index, currentBlock.calculateHash(), currentBlock.Hash)
			return false
		}

		if currentBlock.PreviousHash != previousBlock.Hash {
			fmt.Printf("Invalid previous hash for block %d. Expected %s, got %s\n",
				currentBlock.Index, previousBlock.Hash, currentBlock.PreviousHash)
			return false
		}

		target := strings.Repeat("0", bc.Difficulty)
		if !strings.HasPrefix(currentBlock.Hash, target) {
			fmt.Printf("Block %d hash (%s) does not meet difficulty target (%s)\n",
				currentBlock.Index, currentBlock.Hash, target)
			return false
		}
	}
	return true
}

func main() {
	difficulty := 4
	myBlockchain := NewBlockchain(difficulty)
	fmt.Printf("Blockchain initialized with difficulty: %d\n", difficulty)
	fmt.Println("Genesis Block created:")
	printBlockDetails(myBlockchain.Blocks[0])

	fmt.Println("\nStarting the mining process...\n")

	fmt.Println("Adding first new block...")
	myBlockchain.AddBlock("Transaction Data 1: Alice sends 10 CryptoCoins to Bob")

	fmt.Println("Adding second new block...")
	myBlockchain.AddBlock("Transaction Data 2: Bob sends 5 CryptoCoins to Charlie")

	fmt.Println("Adding third new block...")
	myBlockchain.AddBlock("Transaction Data 3: Charlie sends 2 CryptoCoins to Alice")

	fmt.Println("Verifying blockchain integrity...")
	if myBlockchain.IsChainValid() {
		fmt.Println("Blockchain is valid!")
	} else {
		fmt.Println("Blockchain is NOT valid!")
	}

	fmt.Println("\n--- Full Blockchain ---")
	for _, block := range myBlockchain.Blocks {
		printBlockDetails(block)
	}
}

func printBlockDetails(block *Block) {
	fmt.Println("-------------------------")
	fmt.Printf("Index:        %d\n", block.Index)
	fmt.Printf("Timestamp:    %s\n", time.Unix(block.Timestamp, 0).Format(time.RFC1123))
	fmt.Printf("Data:         %s\n", block.Data)
	fmt.Printf("Nonce:        %d\n", block.Nonce)
	fmt.Printf("Hash:         %s\n", block.Hash)
	fmt.Printf("Previous Hash: %s\n", block.PreviousHash)
	fmt.Println("-------------------------")
}
