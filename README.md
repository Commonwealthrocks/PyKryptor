# **PyKryptor**
Alright I get it I get it... I'll do you something better!

## **What is PyKryptor?**
**PyKryptor** is a file encryption tool built around modern **AEAD** algorithms, example **AES-256-GCM** and **ChaCha20-Poly1305**; with proper key derivation via **Argon2id**, compression, archive support, and USB-based authentication. It started as a joke, like most of my tools... but it turnt into something I use myself for day to day encryption.

## **Why not just use WinRAR or 7-Zip?**
Well, in all honesty those tools do fine themselves in this day and age but sophisticated encryption tools exist for a reason.

One of the key selling points of mine and many other tools is that it follows an **AEAD (Authenticated Encryption with Associated Data)** algorithms those being **AES-256-GCM** and **ChaCha20-Poly1305** over **WinRAR's** or **7-zip's** **AES-256-CBC**.

Another key point in the world of encryption is the `KDF`, the apps mentioned above and some others use **PBKDF2 (Password Based Key Derivation Function 2)**. Which like `CBC` is 2000s crypto, not bad but not ideal for sensitive data. Falls weak to GPU or ASIC attacks, since each iteration is pretty lightweight.

**PyKryptor** and a decent amount of other tools use **Argon2ID**, which is a much more modern hashing algorithm, winner of the "**Password Hashing Competition**" in 2015, it provides resistance against GPU, CPU and ASIC based attacks.

### **Why `GCM` over `CBC`?**
**AES-256-CBC** was established back in 2001. Now that isn't the point however the key issue is that its NOT an **AEAD**, but what does **AEAD** even mean in terms of encryption?

**AEAD** is basically what provides your file(s) or data confidentiality, authenticity by combining encryption and a **message authentication code (MAC)** into a single process.

**CBC** falls short to this because its data can be tampered, flipped, or is weak to padding attacks. **PyKryptor** uses **AES-256-GCM** and **ChaCha20-Poly1305**; both **AEAD**, so tampering is caught on decryption. Every. Fucking. Time.

## **Why PyKryptor over [insert_any_tool_or_sum]?**
Well, I won't sit here and say that my tool is better. Each one has its own set of tradeoffs.

### **"I just want to zip up files, and encryption is not super important to me."**
In that case, I recommend you use tools like...

- **7-zip**; open source, has many forks for almost each specific need.
- **WinRAR**; closed source, slightly worse compression ratios and encryption.
- **PeaZip**; open source like **7-zip** with the factor that it has an option for **AES-256-GCM** too, however the `EAX` mode is used by default.

### **"I want to share encrypted files with people who aren't nerds."**
Ouch, anyways. For this **PyKryptor** too isn't really recommended, and you should try the following...

- **Cryptomator**; pretty dead simple to use. You can directly upload to almost any cloud service and share with anyone, and is too open source on **GitHub**. And strangely only on the desktop version you need to pay for dark mode...?

- **AxCrypt**; although I don't recommend the use of this for a set of reasons. However it is pretty dead simple and easy to share with others. The reason why I don't recommend this tool over **Cryptomator** is that it's paid, closed source and ties with their servers directly.

### **"I want full ass disk encryption."**
Now none of the tools above are really made for this. So in that case you should use something like **VeraCrypt**.

### **"I want a CLI tool, minimal GUI."**
For this one you have some of the best options in fact...

- **age**; dead simple, does one thing and does it well. No config, no GUI, just `age -e -r <recipient> file`. If you're comfortable in a terminal and don't need archives or compression, this is probably the cleanest and easiest option out there.

- **GPG**; now before you lash out at me. Yeah, **GPG** can be used as a file encryptor too in general (if used right). However it relies on keys (a public one and a private one), if you're already in the **GPG** ecosystem, zuper! If not, the learning curve probably isn't worth it just for file encryption.

### **"I want to control ALMOST everything."**
Finally I can shamelessly self promote my own tool. **PyKryptor** is for you if any of this sounds familiar...

- You want **AEAD** encryption and actually understand why it matters.
- You want **Argon2ID** as your `KDF`, not just **PBKDF2** slapped on by default.
- You want compression and encryption and archiving in one tool, not three.
- You want to actually tune your `KDF` parameters instead of hoping the defaults are good.
- You want a USB hardware key as a second factor.
- You want everything to stay offline, no accounts, no servers, no cloud.
- You're on **Windows**, yeah that's it.

If that's you, be my guest! If not, hopefully one of the tools above does the job.

## **What about PyKryptor's features?**
Now, the reason why you MIGHT consider using **PyKryptor** in the first place...

### **Control**
In **PyKryptor**, assuming you're not a fucking idiot or something. You can swap the **AEAD** algorithm, tune **Argon2ID** memory and time cost, set chunk size, pick your compression level, configure compression detection mode...

Some settings are more sensitive than other ones, make sure to read the tooltips for each one when in the app.

### **AEAD algorithms only**
Like mentioned earlier, **AES-256-GCM** and **ChaCha20-Poly1305** are the ONLY supported algorithms. Due to mentioned issues with others, I flat out refuse to add non-**AEAD** algorithms, if you want 'em; add them yourself. The app IS open source after all!

### **Argon2ID and PBKDF2**
Now I did say that **PBKDF2** is "weak" for its set of reasons. But since back when I first started making this app, it was the ONLY available `KDF` option... so still there for compatibility with older encrypted files, but **Argon2ID** is the default and what you should be using.

### **Archive mode**
*"Isn't this just a knock off `.zip` format?"*, well I mean... yeah it is. However it does have its own benefits!

Unlike for legacy `.zip` formats, the metadata is ALWAYS encrypted and tagged with `GCM` or `Poly1305`. Meaning that your file names AREN'T just sitting in plaintext anymore.

And the format for the archive is designed to resist well against **TOCTOU (time of check to time of use)** and **RE (RAM Exhaustion)** attacks and or path traversal vulnerabilities.

### **Compression**
**PyKryptor** also has compression! Just not as good as **WinRAR** or **7-zip** however it does use industry standard libraries like `lzma` (mostly deprecated), `zlib` and `zstd`; that being said you can expect still some good ass compression ratios.

Oh and **PyKryptor** has a configurable "smart skipper" implemented in **C**, I'm too lazy to explain it here but you can see everything in the tooltip for that section :)

### **Authentication methods**
Another big selling point to **PyKryptor** is its set of authentication options; you have `password`, `password + USB-codec` and `keyfiles`.

Each one is pretty explanatory based on the names, only that `USB-codec` is binding a **USB** drive as an extra method of 2FA if you'll call it that. Also that means that EACH **USB** is unique (based on hardware data) and makes it harder to replicate... unless it gets stolen.

A `keyfile` can be used standalone and is probably your best option if you're not a fan of passwords, in **PyKryptor** you can also generate a random `512` byte keyfile for usage as a `.pykx` format.

Generally it is not recommended to use just any file you have sitting as a keyfile itself, so make sure they are always **PRNG** or pure **RNG**.

### **Always offline**
This is pretty common in most software, but **PyKryptor** doesn't connect to the internet at ALL. Meaning you have no fear of your files being visible to me! However if your **OS** is compromised then yeah that'd be the bigger issue.

And with it always being offline, I don't collect any data with it, everything is purely local and never leaves your machine.

### **C library usage**
As mentioned with my "smart skipper" earlier, some bits of the app are coded in pure **C** and compiled with **MinGW64 / GCC**.

The other **C** library is `secure_mem.c` which just takes your password when typed in as a `bytearray()` in **Python** and zero's it out; ensuring no traces are left.

Besides that the rest of the app is mostly in **Python**; but I mean stuff like `cryptography` is based on `OpenSSL` and that library is made in **C** and in general it's all tied back to **C**.

## **License**
If you have a pair of functioning eyes you can see the `LICENSE` file above this file. And incase you can't tell this repo uses the **MIT** license. What that means is you can do basically ANYTHING with the code, as long as it's not my issue in the end result.

Same applies for using my tool; if you do dumb shit then you'll be the one wearing the dunce hat.

## **Quick start**
Here's a quick start guide (mostly for **Windows**) users!

### **Download the latest version**
Yes when I say the latest version I MEAN the latest version. Keep in mind that your **AV** might flag it or straight up delete it because they think its the next **WannaCry** or sum.

### **Make sure your OS is supported**
When I say that, I mean that you're using at least **Windows** 10 or 11.

Any other **OS** is a hit or miss... for **Linux** you'll need to manually compile and or run the app from the source. No pre-built binaries yet. And for **macOS** I am not sure if ANYTHING works; please test it if you can lmfao.

### **Run it**
After downloading, extracting... WHATEVER you were doing. Run the app in however way, check out the settings tab, adjust to your liking and boom you can start encrypting!

## **Limitations**
Because I'm no bad liar, **PyKryptor** has some of its own limitations.

- **Windows** is the target platform, **Linux** is best effort as said and **macOS** is pain and misery for me to obtain.
- "The solo dev problem"; something I face is that I work on this big ass project alone while having to juggle my own mess in life.
- Bugs, they're pretty often but I try to catch them before pushing; so far `v2.0` seems to be super bug free!
- Not tested on ancient hardware, not that `PySide6` or whatever would work on **Windows XP**.
- The code is not PROFESSIONALLY audited, that doesn't mean that the encryption logic is bad, it's just not tested by the ACTUAL nerds.

## **The joke.**
As it is with this tool and any tool of mine. **PyKryptor** started out as a joke; which you can see present in some bits of the app, so my app may contain anything... but the only thing I can promise is encryption, lot's of it.