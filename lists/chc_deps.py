## chc_deps.py
## last updated: 10/02/2026 <d/m/y>
import pkg_resources

deps = ["numpy", "cryptography", "argon2-cffi", "colorama", "pyside6", "pygame", "reedsolo", "zstandard", "pyzstd", "zxcvbn", "imageio"]
for d in deps:
    try:
        print(d, "==", pkg_resources.get_distribution(d).version)
    except Exception as e:
        print(d, "[DEV PRINT] Not installed ")

## end