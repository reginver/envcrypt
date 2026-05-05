// Package env provides utilities for parsing, serializing, and manipulating
// .env files used by envcrypt.
//
// A .env file consists of key=value pairs, optional comments (lines starting
// with '#'), and blank lines. Quoted values (single or double quotes) are
// supported and stripped during parsing.
//
// Example usage:
//
//	file, _ := os.Open(".env")
//	defer file.Close()
//
//	entries, err := env.Parse(file)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	m := env.ToMap(entries)
//	fmt.Println(m["DATABASE_URL"])
package env
