package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	mimc_encrypt "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	mimc "github.com/consensys/gnark/std/hash/mimc"
)

// Define declares the circuit constraints
// Define declares the circuit logic. The compiler then produces a list of constraints
// which must be satisfied (valid witness) in order to create a valid zk-SNARK
// This circuit proves knowledge of a pre-image such that hash(secret) == hash
type MimcCircuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (circuit *MimcCircuit) Define(api frontend.API) error {

	mimc, _ := mimc.NewMiMC(api)

	mimc.Write(circuit.PreImage)

	api.AssertIsEqual(circuit.Hash, mimc.Sum())
	return nil
}

func main() {
	var circuit MimcCircuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, _ := groth16.Setup(ccs)

	mimc := mimc_encrypt.NewMiMC()

	// data to hash
	data := "0xdeadf00d"

	// mimc.Write([]byte(data))
	hash := mimc.Sum([]byte(data))
	hash_string := fmt.Sprintf("%", hash)

	// print data and hash
	fmt.Println("data is ", data)
	fmt.Println("hash is ", hash_string)

	assignment := MimcCircuit{
		PreImage: data,
		Hash:     "1037254799353855871006189384309576393135431139055333626960622147300727796413",
		// Hash: hash_string,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())

	publicWitness, _ := witness.Public()

	// fmt.Println("hash string is ", dummyData.HashString)
	// fmt.Println("hash by array is ", utils.HexStringToByteArray(dummyData.HashString))
	fmt.Println("------------ Public Witness is ", publicWitness, "--------------")

	proof, _ := groth16.Prove(ccs, pk, witness)

	groth16.Verify(proof, vk, publicWitness)
}
