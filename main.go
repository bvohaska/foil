package main

import (
	"fmt"
	"os"

	"encryptorcore/commands"
)

//
func main() {

	//
	if err := commands.FoilCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
