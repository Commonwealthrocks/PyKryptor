# **PyKryptor** - *"Can you make this readme not as terrible as before?"*
Yeah sure thing, well new year and uh... finally locking in a bit on this project once more, so let's get started!!

## **About PyKryptor**
*"What the hell even is **PyKryptor**?!?!"*; well to answer your question, **PyKryptor** is dedicated encryption software built on modern algorithms like **AES-256-GCM** and **ChaCha20-Poly1305**. Offline first, no data collection and or accounts (applies with offline first).

If you care about protecting your data, PyKryptor is here for you. Other tools like **Age**, **Kryptor**, or **Cryptomator** are solid too, but **PyKryptor** brings its own advantages and workflow.

## **Why use PyKryptor?**
Ever wondered why software like **WinRAR** or **7-zip** use **AES-256-CBC** in the grand ol' 26? Yeah me too.

The software's main ideal is encryption, but it tackles other categories like compression and archives.

- **AEAD algorithms** > **PyKryptor** offers two authenticated encryption algorithms; **AES-256-GCM** and **ChaCha20-Poly1305**. Both protect your data and verify integrity.  
- **Key derivation function / hashing** > **PyKryptor** uses **PBKDF2** or **Argon2ID** for its password hashing, **Argon2ID** is preferred since it counters most GPU based attacks too.
- **Archive mode** > Combine multiple files or folders into a single encrypted archive, similar to how traditional archive tools work.
- **MIT license** > Open source and free. You can even fork **PyKryptor** and become the new head dev. And any retarded actions you do are ON you. `¯\_(ツ)_/¯`
- **Offline first** > You'd be surprised how many apps don't offer this... cough cough... **AxCrypt**... but **PyKryptor** is fully offline and it's as simple as running the `.exe` to get started.
- **Configuration** > As for configuration, **PyKryptor** offers configuration of just about... anything in the app, from the **AEAD**, the **KDF** and so on.

That's the *short* run down of most of it... there's a lot I can and shall talk about.

## **For YOU.**

A few things to keep in mind for when using my app and or software.

### **Bugs**
I've done to the most of my ability with catching and fixing bugs, and core breaking ones are very rare. But always keep in mind on what can and cannot go wrong.

### **Update schedule**
As a solo developer. It takes a good while to make these ideas and or code them up, especially with life being life, updates sometimes can be small and or slow...

### **Passwords**
Now actually related with the software, this is *WHAT* determines your care for your files. No matter how strong **AES-256-GCM** and **Argon2ID** or whatever may be. It is always recommended to put a STRONG password for sensitive information

Since a weak password renders all of that cryptography as just fancy **Base64**.

### **Compatability**
So far, only **Windows 10** and **11**, **Linux** *MIGHT* or might not work... God only knows. And any other OS like **macOS** is very unsupported.

### **MIT license**
As every one of my projects for now, I assign it an **MIT license**; in other words if you do not know what it means. You are free to do *WHATEVER* ("as-is") with my code or anything under this repository.

In return I am not liable for any damages, data loss, or issues caused by using this software. Use it at your own risk.

### **The joke.**
Like most... no wait. All of my software. **PyKryptor** started out as a joke, and I see it as something I work on when I'm bored. That doesn't mean the software itself is *bad*, there's just a reason for some bits.

## **List of features**

Now that we've gotten over the core idea of *what* this mess that I call software is. We can head onto the nerdy info.

### **Compression**
**PyKryptor** offers compression just like **WinRAR** and **7-zip** and so on. Not as good as said software since those are *DEDICATED* compression tools, however the rates provided still here are great and an industry standard.

### **AES-256-GCM and ChaCha20-Poly1305**
**PyKryptor** supports two encryption algorithms, both of which are **Authenticated Encryption with Associated Data** (**AEAD**). This means they don't just encrypt your data; they also detect if anyone has tampered with it.

**AES** (**Advanced Encryption Standard**) is a symmetric block cipher and the global standard for encrypting sensitive data. It's trusted enough for government classified information, so yeah, it's legit.

The `256` in **AES-256** refers to the key size; 256 bits. This gives you `2^256` possible combinations, which is such a stupidly large number that brute forcing it is computationally impossible with current technology (and will stay that way for a long long time).

`GCM` stands for **Galois / Counter Mode**. This is what gives AES both confidentiality (data is encrypted) and integrity (tampering is detected). If someone tries to flip bits or modify your encrypted file, `GCM` will catch it during decryption.

**ChaCha20** is the encryption cipher, `Poly1305` is the authentication tag. Together they form an AEAD algorithm designed by **Daniel J. Bernstein** (the guy who made most of our modern crypto). Unlike **AES**, **ChaCha20** doesn't rely on hardware acceleration. It's designed to be fast in software, which makes it ideal for devices without `AES-NI` or older hardware.

`Poly1305` handles authentication (detecting tampering), just like `GCM` does for **AES**. So basically the same shit.

Now which one should you use? Really, both are very strong and virtually have no difference except hardware that does not support `AES-NI` will run **AES-256-GCM** way worse than **ChaCha20-Poly1305**.

### **Argon2ID**
First on the agenda is **Argon2ID**, a hashing algorithm, and a winner of the **Password Hashing Competition** in 2015. **Argon2ID** is a memory / RAM intensive algorithm, so instead of only halting CPUs like **PBKDF2**, it can make most GPU farms fry themselves.

`Time cost` > how many iterations (more = slower, more secure)

`Memory cost` > how much RAM it consumes (more = slower, more secure).

`Parallelism` > how many threads / cores to used to operate **Argon2ID**.

### **PBKDF2**

And the other **KDF** for **PyKryptor** is **Password Based Key Derivation Function 2** (**PBKDF2**) is the most common password hashing algorithm you'd see most software. While it can provide authentication with `HMAC`, that is already taken care of by `GCM` and `Poly1305`.

While **PBKDF2** is good against CPU based attacks, on GPU / memory rich attacks it's practically useless and doesn't slow down much.

The more iterations you use, the stronger / more time consuming it is to crack, it is recommended to have a default of 1 million KDFs; anything under is pretty weak-ish to a dedicated attacker.

### **Salt**
Not the ingredient but rather it gives each file a unique `16` byte **Salt** (in other words unique data). This ensures all files can't be traced to one another file and prevents identical passwords from producing identical keys to the encryption.

### **What IS a KDF?**
`KDF` is what takes your password and unique **Salt** that generates a `32` byte **AES** key to stray away as *MUCH* as possible from the original password / key. This will not save your sorry ass from weak passwords btw.

### **Nonce**
**Nonce** is usually (and in **PyKryptor**) a `12` byte unique set of data that applies per chunk. Re-using / hardcoding **Nonce** (which **PyKryptor** does NOT do) is a sure way for **AES-256-GCM** or **ChaCha20-Poly1305** to also be totally useless.

With that, do not mix up **Nonce** and **Salt**, **Nonce** ensures encryption is unique per operation, even with the same key. While **Salt** is more of a hash for the *ACTUAL* file.

### **Archive mode**
Instead of **PyKryptor** using something like `tarfile` I done made my own packer which in this case works out better for me. It allows smoother encryption flow with files.

And the improved format is resistant to **RAM exhaustion attacks and TOCTOU attacks** while keeping any and all metadata encrypted by default.

### **Secure password wiping (optional)**
In **Python**, you can't allocate memory as in languages like **C**, this means that the garbage collector can keep sensitive data / bytearrays like passwords in your systems RAM / memory.

That's where **C** comes into play, with `secure_mem.c`, this forces passwords after they are used for encryption to be *WIPED* from RAM, leaving only pure zero's.

### **USB-codec**
**USB-codec** is where you can set up a USB drive / device as your encryption and decryption method alongside a password.

To do said, you'd first need to serialize a USB drive for it to be usable as a valid key; we do that by combining many unique values of the USB and hashing them together with **SHA-512**.

This allows every USB to be "unique" and cloning it or replicating it is near impossible.

### **Keyfile**
A keyfile is using an individual file as your password itself, or well the `SHA` of it. Using any file as your keyfile alone is *NOT* a good practice, and is a bad security habit.

Thus why; PyKryptor allows you to generate a `512` byte keyfile with `os.urandom()` + **Salt**, which is near impossible to replicate.

This does mean losing this file = losing your data too, no doubt there.

## **FAQ**
In case you'd have any *common* questions about **PyKryptor**, here are your answers.

### *"Is **PyKryptor** safe?"*
It'd be ironic if my *SECURITY* tool was unsafe, but yes. **PyKryptor** is safe to use, using well known and audited cryptographic primitives.

### *"Why does the `.exe` get flagged by my antivirus?"*
Well, this is more common than you think with encryption software; especially since **WannaCry** came into effect.

Antivirus software looks for patterns, not intent itself. If an AV sees that my or any software can encrypt, edit, write, compress, archive, zero out RAM... it will assume it's ransomware.

But if you're really paranoid, you can boot up **PyKryptor** in a sandboxed environment or in a virtual machine to test it... or throw it into **VirusTotal** ([**VirusTotal.com**](https://virustotal.com/)) and see what comes out of it.

### *"What happens if I forget my password or any decryption method?"*
Well, unless your password is easily guessable or something, your files are as good as gone.

**AES-256-GCM** and **ChaCha20-Poly1305** are state of the art encryption methods, they cannot be easily cracked nor reversed. So you must *ALWAYS* make sure to keep your passwords or any keyfile / USB safe.

### *"What languages are used to make this?"*
Well in case you couldn't see on the side of the repo for *SOME* reason. I've used **Python (3.12)** for the GUI (`PySide6`), encryption (`cryptography`), and 95% of the app in general.

For more lower level things like RAM wiping, I step down with **C** and use `gcc` as my general compiler.

### *"What happened to **PyLI**?"*
In short, I changed the name from that to **PyKryptor** to fit it better, and **PyLI** sounded like some knockoff version of `PyNaCl`.

In case you wanted to know why, or not, you can skip this part. Back in version `0.1a`, I used the **C** library / `.dll` for **Libsodium** itself; hence why I named it **Py**thon-**LI**bsodium. Yeah not the smartest name but it's a cool fact...

### *"WHAT ABOUT THE CLI?!?!?!?!?!?!?"*
Well I mean... it's *THERE*, just... not tested actually, but it IS documented in `src/txts/cli.txt` a bit more in depth; but for most users this is just not needed.

### *"Why are the `.zips` passworded on **Google Drive**?"*
Well, the reason is it's too big to fit into a single release.

*"Well you can just use git and LFS for that!!"*

Yeah I use git, but I'm too lazy for the rest.

## **Disclaimer**
**PyKryptor** is overkill. And I'm one to admit it, I'm not going to sit here and say that you *NEED* my software for every use case.

It all depends on your use case, example something as your photos, or anything you don't see as "super critical" but still want to be sorta safe; an **AES-256-CBC** archive with **WinRAR** or **7-zip** is still stupid safe.

But if you're dealing with sensitive data and or material. It's better to be overkill than careless, simple as that. **PyKryptor** is for the people who want control over *MOST* things and want transparency; that's why I made it in the first place. Even if it started out as a joke.

But time will do it's effect, `CBC` won't be fullproof forever... and refusing to change from it is how stuff like data breaches happen.