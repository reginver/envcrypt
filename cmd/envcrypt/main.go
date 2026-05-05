// Command envcrypt provides a CLI for encrypting and managing .env files
// using age encryption. It supports key generation, encryption, and decryption
// of environment variable files.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/vault"
)

const usage = `envcrypt - Encrypt and manage .env files using age encryption

Usage:
  envcrypt <command> [options]

Commands:
  init      Generate a new age key pair (public + private key files)
  encrypt   Encrypt a .env file into an encrypted vault file
  decrypt   Decrypt a vault file back into a .env file

Options:
  -h, --help   Show this help message

Examples:
  envcrypt init
  envcrypt encrypt -in .env -out .env.age
  envcrypt decrypt -in .env.age -out .env
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		runInit(os.Args[2:])
	case "encrypt":
		runEncrypt(os.Args[2:])
	case "decrypt":
		runDecrypt(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}

// runInit handles the "init" subcommand, generating a new key pair.
func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	overwrite := fs.Bool("overwrite", false, "Overwrite existing key files if present")
	fs.Parse(args)

	paths := vault.DefaultKeyPaths()
	if err := vault.InitKeys(paths, *overwrite); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Key pair generated:\n  public key : %s\n  private key: %s\n", paths.PublicKeyPath, paths.PrivateKeyPath)
}

// runEncrypt handles the "encrypt" subcommand.
func runEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	inFile := fs.String("in", ".env", "Input plaintext .env file")
	outFile := fs.String("out", ".env.age", "Output encrypted vault file")
	fs.Parse(args)

	paths := vault.DefaultKeyPaths()
	v, err := vault.New(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading keys: %v\n", err)
		os.Exit(1)
	}

	if err := v.Encrypt(*inFile, *outFile); err != nil {
		fmt.Fprintf(os.Stderr, "error encrypting: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Encrypted %s -> %s\n", *inFile, *outFile)
}

// runDecrypt handles the "decrypt" subcommand.
func runDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	inFile := fs.String("in", ".env.age", "Input encrypted vault file")
	outFile := fs.String("out", ".env", "Output plaintext .env file")
	fs.Parse(args)

	paths := vault.DefaultKeyPaths()
	v, err := vault.New(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading keys: %v\n", err)
		os.Exit(1)
	}

	if err := v.Decrypt(*inFile, *outFile); err != nil {
		fmt.Fprintf(os.Stderr, "error decrypting: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Decrypted %s -> %s\n", *inFile, *outFile)
}
