package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

/* OLD COMMENT
// CubicCircuit defines a simple circuit
// x**3 + x + 5 == y
*/

type CubicCircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**2 - 5x + 6 == 0
// x**2 - 4x + 4 == 0
func (circuit *CubicCircuit) Define(api frontend.API) error {
	x2 := api.Mul(circuit.X, circuit.X)
    m5x := api.Mul(circuit.X, -5)
	m4x := api.Mul(circuit.X, -4)
	api.AssertIsEqual(circuit.Y, api.Add(x2, m5x, 6))
	api.AssertIsEqual(circuit.Y, api.Add(x2, m4x, 4))
	return nil
}

func main() {
	// compiles our circuit into a R1CS
	var circuit CubicCircuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition
	assignment := CubicCircuit{X: 3, Y: 0}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}