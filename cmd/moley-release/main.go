// Command moley-release makes release signing keys and the signed update
// manifest the tray app checks:
//
//	moley-release keygen
//	MOLEY_RELEASE_KEY=<private> moley-release manifest -version 0.3.0 \
//	    -url https://example.com/Moley-Setup-0.3.0.exe dist/windows/Moley-Setup-0.3.0.exe > latest.json
//
// Build the tray app with the public key (-X main.updateKey) and the
// manifest's URL (-X main.updateURL).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"moley/internal/release"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: moley-release keygen | manifest -version V -url URL [-platform windows] [-notes N] <file>")
	}
	switch os.Args[1] {
	case "keygen":
		pub, priv, err := release.Keygen()
		check(err)
		fmt.Printf("public  %s\nprivate %s\n", pub, priv)
	case "manifest":
		fs := flag.NewFlagSet("manifest", flag.ExitOnError)
		version := fs.String("version", "", "release version")
		url := fs.String("url", "", "where the file is downloaded from")
		platform := fs.String("platform", "windows", "windows or linux")
		notes := fs.String("notes", "", "release notes")
		check(fs.Parse(os.Args[2:]))
		key := os.Getenv("MOLEY_RELEASE_KEY")
		if fs.NArg() != 1 || *version == "" || *url == "" || key == "" {
			fail("manifest needs -version, -url, one file, and MOLEY_RELEASE_KEY")
		}
		f, err := os.Open(fs.Arg(0))
		check(err)
		defer f.Close()
		a, err := release.Sign(f, key, release.Artifact{URL: *url, Filename: filepath.Base(fs.Arg(0)), Platform: *platform, Arch: "amd64"})
		check(err)
		m, err := release.NewManifest(*version, *notes, a)
		check(err)
		fmt.Println(string(m))
	default:
		fail("unknown command " + os.Args[1])
	}
}

func check(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "moley-release: "+msg)
	os.Exit(2)
}
