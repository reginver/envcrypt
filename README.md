# envcrypt

Lightweight utility to encrypt and manage `.env` files using [age](https://github.com/FiloSottile/age) encryption.

---

## Installation

```bash
go install github.com/yourusername/envcrypt@latest
```

Or build from source:

```bash
git clone https://github.com/yourusername/envcrypt.git
cd envcrypt && go build -o envcrypt .
```

---

## Usage

**Encrypt a `.env` file:**

```bash
envcrypt encrypt .env --output .env.age
```

**Decrypt a `.env` file:**

```bash
envcrypt decrypt .env.age --output .env
```

**Run a command with decrypted environment variables injected:**

```bash
envcrypt run --env .env.age -- ./your-app
```

Keys are generated automatically on first use and stored in `~/.config/envcrypt/keys`. You can also provide a recipient public key for team-shared secrets:

```bash
envcrypt encrypt .env --recipient age1ql3z7hjy...
```

---

## Requirements

- Go 1.21+
- [filippo.io/age](https://pkg.go.dev/filippo.io/age)

---

## License

MIT © [yourusername](https://github.com/yourusername)