# **PyKryptor documentation**

## **How to build**
Since **Linux** now is (slightly) more tested; or in general if you want to compile the app yourself with your changes, here are the following steps.

### **Python 3.12**
Why this version specifically? Well this only applies if you are planning to compile the app with `Nuitka` and with `GCC`. Since `3.13` only supports `MSVC` which is not tested.

Again, this does not apply if you don't plan to compile the app; in that case I recommend something like **Python 3.9+**.

### **General C compiler**
Since **PyKryptor** has a few bits coded in **C**; you will need **GCC / MinGW64** installed on your machine.

#### [**MSYS2**](https://www.msys2.org/); download and setup your **UCRT64** terminal (if on windows)

Once that's done, and you make sure you have everything in `PATH`, you can run this command to download `GCC`.

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc
```

### **Clone de repo**
Once you have `GCC` and what not. You need to make sure you have `git`; since it's the most effective way to clone the source code and compile it.

```bash
git clone https://github.com/Commonwealthrocks/PyKryptor/
cd PyKryptor
```

If shits all good n' dandy it should clone with no issues!

### **Libraries / building**
Once you have that, you should also by now have your needed `pip`. And make sure to download all of the needed libraries for the app.

```cmd
pip install -r src/requirements.txt
pip install nuitka
```

Once that is dealt with, you can start compiling. There's two build scripts; a `.sh` and a `.bat`, `.sh` is cross platform meaning it will both work on **Windows** and **Linux** ensuring your environment is right.

```bash
bash build.sh
```

```cmd
build.bat
```

Once you have it running, follow the steps in the file CAREFULLY and all should compile with `Nuitka`. The first time you do compile something with `Nuitka` you will get a few popups to download a specific version of `GCC` (needed) and a helper library.

You still need **MSYS2's** version of `GCC` to compile the raw `.c` files still though.

## **CLI**
This is just a run down of basic CLI usage, mostly from the now deleted `cli.txt` or any other files.

### **Where to use?**
The first thing to keep in mind is that **PyKryptor's** CLI can only be used from the source code; starting most commands with `python cli.py [...]` to invoke it. There's no global `pykryptor` command unless you compile it — it's just a Python script for now.

So `cd` into the `src/` directory (or wherever `cli.py` lives) and go from there.

### **Basic operations**
The two core flags are `-e` for encryption and `-d` for decryption. `-p` sets the password, and `-f` points to your file(s). That's really the minimum you need.

```bash
python cli.py -e -p "ur_password" -f data.bin
python cli.py -d -p "ur_password" -f data.dat
```

Multiple files work too, just keep stacking them after `-f`. Although this for most use cases is *VERY* slow.

```bash
python cli.py -e -p "ur_password" -f ransomware.exe tax_fraud.pdf cookie_recipe.txt
```

### **Output options**
By default the output lands next to the input file with a `.dat` extension. You can change both.

```bash
python cli.py -e -p "ur_password" -f data.bin -o ./output_folder/ --ext enc
```

You also have three options for how the output filename is chosen with `--name-type`:

- `keep` - keeps the original name, just swaps the extension. Default.
- `hash` - renames the output to a **SHA-256** hash of the file contents, your best bet if you want zero data leak. cannot be reversed back tho.
- `base64` - base64 encodes the original filename; good if you want to obscure what the file even was and is reverseable.

```bash
python cli.py -e -p "ur_password" -f secrets.log --name-type hash
```

### **Keyfiles**
Don't want to use a password? Or want to use both? That's what `-k` is for.

```bash
python cli.py -e -k ./my_keyfile.pykx -f file.txt
```

A keyfile is a `512` byte blob of random data in `.pykx` format. You can generate one from the GUI, or honestly just use `python -c "import os; open('key.pykx','wb').write(os.urandom(512))"` if you're in a hurry.

When BOTH a password and a keyfile are provided, they are combined before key derivation; so you'd need both to decrypt.

```bash
python cli.py -e -p "ur_password" -k ./my_keyfile.pykx -f video.mp4
```

If you lose it, then yeah that's on you fucking idiot.

### **KDF options**
**Argon2ID** is the recommended `KDF` and is what you should be using for anything sensitive. Pass `--use-argon2` to enable it.

```bash
python cli.py -e -p "ur_password" -f passwords.txt --use-argon2
```

You can also tune the **Argon2ID** parameters if you know what you're doing.

```bash
python cli.py -e -p "ur_password" -f data.bin --use-argon2 --argon2-memory 131072 --argon2-time 4 --argon2-parallelism 4
```

If you stick with **PBKDF2** (default), you can adjust the iteration count and hash type.

```bash
python cli.py -e -p "ur_password" -f file.file --kdf-iterations 2000000 --pbkdf2-hash sha512
```

The defaults are `1,000,000` iterations with **SHA-256**. Bump it up if you're paranoid, but it WILL be slower.

### **Encryption algorithm**
Two options, both **AEAD**. **AES-256-GCM** is the default and faster if your CPU has `AES-NI` (most do). **ChaCha20-Poly1305** is software based and may actually be faster on hardware without `AES-NI`.

```bash
python cli.py -e -p "pass" -f nudes_maybe.png --aead chacha20-poly1305
```

### **Compression**
Five levels, picked with `--compression`. Default is `none`.

- `none` - no compression, fastest.
- `normal` - `zlib`, fast with a decent ratio.
- `best` - `zstd` level 3, balanced.
- `ultrakill` - `zstd` level 22, slow but best ratio.
- `[L] ultrakill` - `lzma` preset 9, really slow. Legacy option, mostly there cause I'm too lazy to remove it.

```bash
python cli.py -e -p "ur_password" -f big_big_file.pk3 --compression best
```

You can also tell **PyKryptor** to be "smart" (as smart as rocks) about it and skip compression on files that are already compressed (images, videos, zipped files, etc.) with `--detection-mode`.

- `legacy` - checks file extensions only. Default.
- `magic` - reads file signatures (magic bytes).
- `entropy` - samples ~8KB and checks if the data is already high-entropy.
- `magic+entropy` - combines both, most accurate.

```bash
python cli.py -e -p "pass" -f mixed_files/* --compression best --detection-mode magic+entropy
```

The `--entropy-threshold` flag (range `6.0`–`8.0`, default `7.5`) controls how aggressive the entropy check is. Higher means less likely to skip a file. Only applies to entropy-based modes.

### **Archive mode**
Packs multiple files into a single encrypted archive. File names and structure are encrypted too, unlike regular `.zip`.

```bash
python cli.py -e -p "pass" -f ./folder/* --archive --archive-name output.dat
```

If `--archive-name` is not set it defaults to `archive.dat` (or whatever `--ext` is set to).

### **USB-codec**
Hardware bound second factor; The USB drive must have been set up with `--usb-setup` first.

```bash
python cli.py --usb-list
python cli.py --usb-setup E:\
python cli.py -e -p "ur_password" -f sql.db --usb-key E:\
```

To decrypt you'll need the same USB drive that was used during encryption. Lose it and the file is gone.

### **Save states**
Save your current settings to a `JSON` file and reload them later. Useful if you have a specific setup you use often. Passwords and file paths are never saved.

```bash
python cli.py -ss config1.json -e -p "ur_password" -f file.txt --compression best --use-argon2
python cli.py -ls config1.json -e -p "ur_password" -f another.txt
```

### **Other flags**
A few extra ones worth knowing.

- `--secure-clear` - zeros out the password from memory after use. Needs the `secure_mem` C library to be built, falls back to a Python method otherwise.
- `--recovery` - adds **Reed-Solomon** error correction data to each chunk. Helps recover mildly corrupted files at the cost of a slightly larger output.
- `--chunk-size [MBs]` - default is `3` MBs per chunk. Larger chunks are faster but eat more RAM. PLEASE use with caution.

### **Full example**
Something more realistic with most options combined.

```bash
python cli.py -e -p "pass" -f ./documents/* --archive --archive-name docs_backup.dat --use-argon2 --argon2-memory 131072 --compression best --detection-mode magic+entropy --aead aes-gcm --recovery -o ./output/
```
## **File format**
Now I do already have this... ahem, `info.txt` HOWEVER most of you are afraid of reading text files so we're using fancy ass markdown.

### **Header**
Every encrypted file starts with a fixed header. If the first 5 bytes aren't `PYKX\x00` (or the legacy `PYLI\x00` for older files) then it's not a **PyKryptor** file and decryption will refuse to even try.

```
- Magic number: 5 bytes | "PYKX\x00" (legacy: "PYLI\x00")
- Format version: 1 byte | currently 11
- AEAD algorithm: 1 byte | 1 = AES-256-GCM, 2 = ChaCha20-Poly1305
- Flags: 1 byte | bitfield; recovery data, archive mode, USB-codec
- KDF ID: 1 byte | 1 = PBKDF2, 2 = Argon2ID
- Compression ID: 1 byte | 0-4; none through [L] ULTRAKILL
- Recovery bytes: 1 byte | only if recovery flag set; always 32
- KDF parameters: variable | Argon2ID; time + memory + parallelism (12 bytes) | PBKDF2; hash type + iterations (5 bytes)
- Salt: 16 bytes | random per file
- Extension nonce: 12 bytes | random, used to decrypt the file extension
- Extension length: 4 bytes | length of the encrypted extension blob encrypted extension variable | the original file extension, encrypted
```

The extension being encrypted is intentional; even the file type is hidden. It's recovered first on decryption to reconstruct the output filename.

### **Chunks**
After the header, file data follows in chunks.

```
- Nonce: 12 bytes  | random, unique per chunk
- Length: 4 bytes | length of the encrypted chunk data
- Encrypted data: variable | compressed (if enabled) then encrypted
- Parity: 32 bytes | Reed-Solomon, only if --recovery was used
```

From **v11** onwards each chunk's **AAD** binds the full file header + chunk index + byte offset. Chunks can't be silently reordered or swapped between files. Pre-v11 used header only **AAD** which didn't have this guarantee; that was the chunk reordering attack fixed in `v2.0`.

### **Archive format**
When archive mode is used the decrypted payload is itself a mini format sitting before the actual file data.

```
- File count: 4 bytes | number of files in the archive
- Path length: 4 bytes | length of the relative path string
- Relative path: variable | UTF-8 encoded path
- File size: 8 bytes | size of this file's data in bytes
- File data: variable | sequential, in the same order as the metadata
```

Directory structure is preserved and path traversal attempts are caught and rejected on extraction.

### **Key derivation**
Salt is `16` bytes of `os.urandom()`, unique per file. Derived key is always `256` bits.

```
- Argon2ID defaults: 64MB memory, time cost 3, parallelism 4
- PBKDF2 defaults: 1,000,000 iterations, SHA-256 / 512
- Keyfile / USB: password + key material combined with SHA-256 / 512 before derivation PBKDF2 forced to minimum 500,000 iterations regardless of setting
```

### **What v11 actually changed**
Files encrypted before `v2.0` will still decrypt fine via the legacy path, the format version in the header tells the decryptor which path to take. The breaking change was chunk **AAD** binding. Old files used header only **AAD** so chunk index and offset weren't authenticated. v11 fixes that.

## **FAQ (I guess)**
Here are *SOME* questions that may or may not answer your questions.

### **"Kryptor and PyKryptor...?"**
Now yeah before you mix those two up, they are very different. Just that the name is very similar and yeah **PyKryptor** is not a fork of **Kryptor**.

### **"Why does PyKryptor get flagged by my anti-virus?"**
Well, I myself don't fully know but from what I can assume, **PyKryptor** is not code signed (expensive ☹), and in most anti-virus databases. Hashes match so it ends up looking like ransomware.

This can't be really fixed unless just a lot of time passes, you are running the app from source or you add the app and it's components to an exclusion zone.

### **"What happens if I lose / forget my [insert_encryption_method]"**
Long story short; if it was a weak password, you may be able to bruteforce it. If you lost a keyfile / **USB-codec** key or just a high entropy password. Yeah not much I can do to help, file are *GONE GONE*.

### **"Does PyKryptor collect any data / telemetry?**
No.

### **"What happened to PyLI?"**
Now this one isn't that crazy, just a history report of the app. But back in `v0.1a` when I was first making the concept for this app; I used the normal `libsodium.dll` for encryption... so I named the app **`Py`thon `Li`bsodium**.

That being said that version is lost to time, and honestly I have no idea what I was cooking to re-create it.