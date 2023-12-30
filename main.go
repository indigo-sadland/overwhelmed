package main

import (

	"flag"
	"fmt"
	"os"
	"overwhelmed/cmd"

)

func main() {

	InputDomain := flag.String("domain", "", "Domain to work with")
	Output := flag.String("out","cmd", "Type of output (cmd/doc/raw)\n cmd - will print to terminal field name and its value\n " +
		"doc - will write to Word file with table structure. NEEDS API KEY\n raw - will print to terminal only fields values")
	flag.Parse()

	if *InputDomain == "" {
		fmt.Println("DOMAIN NAME CAN NOT BE EMPTY")
		flag.PrintDefaults()
		os.Exit(1)
	}

	cmd.GetWhois(*InputDomain, *Output)
}
