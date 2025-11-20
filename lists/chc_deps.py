## chc_deps.py
## last updated: 20.11.2025 <d/m/y>
import pkg_resources

deps = ["numpy", "cryptography", "argon2-cffi", "colorama", "pyside6", "pygame", "reedsolo", "zstandard", "pyzstd", "zxcvbn"]
for d in deps:
    try:
        print(d, "==", pkg_resources.get_distribution(d).version)
    except Exception as e:
        print(d, "[DEV PRINT] Not installed ")

## end