package main

import (
 "fmt"
 "github.com/consensys/gnark-crypto/ecc"
 bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
//  bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
 "github.com/consensys/gnark/backend/groth16"
 "github.com/consensys/gnark/frontend"
 r1cs2 "github.com/consensys/gnark/frontend/cs/r1cs"
 "github.com/consensys/gnark/std/hash/mimc"
//  "math/big"
)

type Circuit struct {
 PreImage frontend.Variable
 Hash     frontend.Variable `gnark:",public"`
 Salt   frontend.Variable `gnark:",public"`
 SaltedHash frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
    //  api.Println(circuit.Hash)
    //  api.Println(circuit.PreImage)
    mimc, _ := mimc.NewMiMC(api)
    mimc.Write(circuit.PreImage)
    //  api.Println(mimc.Sum())
    api.AssertIsEqual(circuit.Hash, mimc.Sum())
    saltedInput := api.Add(circuit.PreImage, circuit.Salt)
    mimc.Write(saltedInput)
    api.AssertIsEqual(circuit.SaltedHash, mimc.Sum())
    return nil
}

// func mimcHash(data []byte) []byte {
//  f := bw6761.NewMiMC()
//  hash := f.Sum(data)
// //  hashInt := big.NewInt(0).SetBytes(hash)
//  return hash
// }

func main() {
 preImage := []byte("1")
 salt := []byte("2")
//  fmt.Println(salt)
 hash := mimcHash(preImage)
 saltedHash := mimcHash([]byte("3"))

//  fmt.Println(preImage)

//  fmt.Printf("hash: %s\n", hash.String())

 var circuit Circuit

 r1cs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs2.NewBuilder, &circuit)
 if err != nil {
  fmt.Printf("Compile failed : %v\n", err)
  return
 }

 pk, vk, err := groth16.Setup(r1cs)
 if err != nil {
  fmt.Printf("Setup failed\n")
  return
 }

 assignment := &Circuit{
    PreImage: frontend.Variable(preImage),
    Hash:     frontend.Variable(hash),
    Salt:   frontend.Variable(salt),
    SaltedHash: frontend.Variable(saltedHash),
 }
 fmt.Println("assignment.Hash", assignment.Hash)

 witness, err := frontend.NewWitness(assignment, ecc.BW6_761.ScalarField())
 proof, err := groth16.Prove(r1cs, pk, witness)
 if err != nil {
  fmt.Printf("Prove failed： %v\n", err)
  return
 }

 publicAssignment := &Circuit{
    Hash: frontend.Variable(hash),
    Salt: frontend.Variable(salt),
    SaltedHash: frontend.Variable(saltedHash),
 }
 fmt.Println(hash)

 publicWitness, err := frontend.NewWitness(publicAssignment, ecc.BN254.ScalarField())
 err = groth16.Verify(proof, vk, publicWitness)
 if err != nil {
  fmt.Printf("verification failed: %v\n", err)
  return
 }
 fmt.Printf("verification succeded\n")
}