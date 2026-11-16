# deepscan

A terminal tool that inspects files in depth for hidden, embedded or misleading content and summarises what it found, ranked by severity.

It reads the file without opening or running it. One Python file, standard library only.

```
python3 deepscan.py <files or folders>
```

## What it checks

| Area | Examples |
|---|---|
| Identity | real type from the bytes vs. the extension, double extensions, right-to-left filename tricks |
| Hashes | MD5, SHA-1, SHA-256 |
| Metadata | EXIF (including GPS), XMP, PNG text chunks, PDF info, Office author/company fields, extended attributes |
| Hidden data | data appended after the real end of a file, files embedded in other files, extra data inside PNG image streams, base64/hex-encoded executables |
| Steganography | text or file headers in pixel least-significant bits (PNG, BMP), chi-square test for encrypted LSB payloads, whitespace and zero-width text stego |
| Active content | Office macros, remote templates, hidden sheets/text, tracked deletions, PDF JavaScript and auto-actions, zip-slip paths, executables disguised inside archives |
| Strings | URLs, IPs, e-mail addresses, private keys and tokens, downloader commands |
| Text tricks | invisible Unicode tag messages, bidirectional overrides, homoglyphs, terminal escape sequences |
| Entropy | overall value, per-block bar, high-entropy regions |

## Usage

```
deepscan.py suspicious.pdf              # one file
deepscan.py ~/Downloads                 # a folder, recursively
deepscan.py ~/Downloads -s medium       # hide low-level notes
deepscan.py ~/Downloads -q              # summary only
deepscan.py folder --html report.html   # self-contained HTML report
deepscan.py folder --json out.json      # full results as JSON ('-' for stdout)
deepscan.py photo.png --extract found/  # save whatever was hidden
deepscan.py photo.png --deep            # scan whole images, slower
```

Exit status: `0` nothing notable, `1` medium-severity findings, `2` high-severity findings.

Each file gets a verdict: `SUSPICIOUS` (high), `REVIEW` (medium), `minor notes` (low) or `clean`.

`file` and `exiftool` are used for extra detail when they are installed. `--vt` looks the SHA-256 up on VirusTotal (only the hash is sent; needs `VT_API_KEY`).

## Try it

```
python3 make_test_files.py      # creates ./test-files with 23 harmless samples
python3 deepscan.py test-files
```

The samples each hide one thing (a message in pixel bits, a ZIP glued after an image, a macro, invisible characters, and so on). None of them is real malware: the "executables" are empty headers that cannot run, and every key, URL and name is made up.

## Limits

- Does not detect password-based JPEG steganography (steghide, outguess, F5) or audio/video steganography.
- Cannot look inside encrypted archives or encrypted documents.
- Flags that Office macros exist but does not decompile them; use `olevba` from oletools for that.
- A `clean` verdict means none of the checks fired. It is not a guarantee that a file is safe and not a replacement for antivirus.

## License

MIT. See [LICENSE](LICENSE).
