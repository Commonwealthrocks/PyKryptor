// chc_cmp.c
// last updated: 27/12/2025 <d/m/y>
// p-y-k-x
// win32: gcc -shared -o c/win32/chc_cmp.dll c/chc_cmp.c -O2 -Wall -fvisibility=hidden -fno-strict-aliasing -fno-lto -static-libgcc -static-libstdc++
// linux / linux2: gcc -shared -fPIC -o c/penguin/chc_cmp.so c/chc_cmp.c -O2 -Wall -fvisibility=hidden -fno-strict-aliasing -fno-lto -lm
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <stdint.h>
#if defined(_WIN32)
#include <windows.h>
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT __attribute__((visibility("default")))
#endif
typedef struct
{
    const uint8_t *signature;
    size_t sig_len;
    const char *description;
} MagicSignature;
static const MagicSignature KNOWN_SIGNATURES[] = {
    {(const uint8_t *)"\x50\x4B\x03\x04", 4, "ZIP"},
    {(const uint8_t *)"\x50\x4B\x05\x06", 4, "ZIP (empty)"},
    {(const uint8_t *)"\x50\x4B\x07\x08", 4, "ZIP (spanned)"},
    {(const uint8_t *)"\x52\x61\x72\x21\x1A\x07", 6, "RAR"},
    {(const uint8_t *)"\x52\x61\x72\x21\x1A\x07\x01\x00", 8, "RAR 5"},
    {(const uint8_t *)"\x37\x7A\xBC\xAF\x27\x1C", 6, "7-Zip"},
    {(const uint8_t *)"\x1F\x8B", 2, "GZIP"},
    {(const uint8_t *)"\x42\x5A\x68", 3, "BZIP2"},
    {(const uint8_t *)"\xFD\x37\x7A\x58\x5A\x00", 6, "XZ"},
    {(const uint8_t *)"\x5D\x00\x00", 3, "LZMA"},
    {(const uint8_t *)"\xFF\xD8\xFF", 3, "JPEG"},
    {(const uint8_t *)"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", 8, "PNG"},
    {(const uint8_t *)"\x47\x49\x46\x38\x37\x61", 6, "GIF87a"},
    {(const uint8_t *)"\x47\x49\x46\x38\x39\x61", 6, "GIF89a"},
    {(const uint8_t *)"\x52\x49\x46\x46", 4, "WEBP"},
    {(const uint8_t *)"\x42\x4D", 2, "BMP"},
    {(const uint8_t *)"\x66\x4C\x61\x43", 4, "FLAC"},
    {(const uint8_t *)"\x4F\x67\x67\x53", 4, "OGG"},
    {(const uint8_t *)"\xFF\xFB", 2, "MP3"},
    {(const uint8_t *)"\xFF\xF3", 2, "MP3"},
    {(const uint8_t *)"\xFF\xF2", 2, "MP3"},
    {(const uint8_t *)"\x49\x44\x33", 3, "MP3 (ID3)"},
    {(const uint8_t *)"\x00\x00\x00\x18\x66\x74\x79\x70", 8, "MP4"},
    {(const uint8_t *)"\x00\x00\x00\x1C\x66\x74\x79\x70", 8, "MP4"},
    {(const uint8_t *)"\x00\x00\x00\x20\x66\x74\x79\x70", 8, "MP4"},
    {(const uint8_t *)"\x1A\x45\xDF\xA3", 4, "MKV/WEBM"},
    {(const uint8_t *)"\x52\x49\x46\x46", 4, "AVI"},
    {(const uint8_t *)"\x4D\x5A", 2, "EXE/DLL"},
    {(const uint8_t *)"\x7F\x45\x4C\x46", 4, "ELF"},
    {(const uint8_t *)"\xCF\xFA\xED\xFE", 4, "Mach-O"},
    {(const uint8_t *)"\xFE\xED\xFA\xCF", 4, "Mach-O"},
    {(const uint8_t *)"\x25\x50\x44\x46", 4, "PDF"},
    {(const uint8_t *)"\x49\x53\x63\x28", 4, "CAB"},
    {(const uint8_t *)"\x50\x4B\x03\x04", 4, "DOCX/XLSX/PPTX"},
    {(const uint8_t *)"\x1F\x9D", 2, "TAR (compress)"},
    {(const uint8_t *)"\x75\x73\x74\x61\x72", 5, "TAR (ustar)"},
    {(const uint8_t *)"\x1F\xA0", 2, "TAR (lzh)"},
    {(const uint8_t *)"\x4D\x5A\x90\x00", 4, "EXE (PE)"},
    {(const uint8_t *)"\x49\x49\x2A\x00", 4, "TIFF (little-endian)"},
    {(const uint8_t *)"\x4D\x4D\x00\x2A", 4, "TIFF (big-endian)"},
    {(const uint8_t *)"\x00\x00\x01\x00", 4, "ICO"},
    {(const uint8_t *)"\x52\x49\x46\x46", 4, "WAV"},
    {(const uint8_t *)"\xFF\xF1", 2, "AAC (ADTS)"},
    {(const uint8_t *)"\xFF\xF9", 2, "AAC (ADTS)"},
    {(const uint8_t *)"\x00\x00\x00\x20\x66\x74\x79\x70\x4D\x34\x41", 11, "M4A"},
    {(const uint8_t *)"\x00\x00\x00\x18\x66\x74\x79\x70\x71\x74\x20\x20", 12, "MOV"},
    {(const uint8_t *)"\x46\x4C\x56\x01", 4, "FLV"},
    {(const uint8_t *)"\x30\x26\xB2\x75\x8E\x66\xCF\x11", 8, "WMV/ASF"},
    {(const uint8_t *)"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8, "DOC/XLS (old)"},
    {(const uint8_t *)"{\\rtf", 5, "RTF"},
    {(const uint8_t *)"PYKX\x00", 5, "PyKryptor"},
    {(const uint8_t *)"PYLI\x00", 5, "PyKryptor (legacy)"},
};
static const size_t NUM_SIGNATURES = sizeof(KNOWN_SIGNATURES) / sizeof(KNOWN_SIGNATURES[0]);
static const char *COMPRESSED_EXTS[] = {
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".lzma",
    ".jar", ".apk", ".whl", ".tar", ".tgz", ".tar.gz",
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
    ".flac", ".ogg", ".mp3", ".aac", ".opus", ".wma", ".m4a", ".wav",
    ".mp4", ".mkv", ".avi", ".mov", ".webm", ".flv", ".wmv", ".asf",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".tif", ".tiff", ".ico",
    ".exe", ".dll", ".so", ".dylib",
    ".iso", ".img", ".dmg",
    ".dat", ".pdf", ".cab", ".doc", ".xls", ".ppt", ".rtf"};
static const size_t NUM_COMPRESSED_EXTS = sizeof(COMPRESSED_EXTS) / sizeof(COMPRESSED_EXTS[0]);
DLLEXPORT int check_extension(const char *filepath)
{
    if (!filepath)
        return 0;
    const char *ext = strrchr(filepath, '.');
    if (!ext)
        return 0;
    char lower_ext[32];
    size_t ext_len = strlen(ext);
    if (ext_len >= sizeof(lower_ext))
        return 0;
    for (size_t i = 0; i < ext_len && i < sizeof(lower_ext) - 1; i++)
    {
        lower_ext[i] = (ext[i] >= 'A' && ext[i] <= 'Z') ? ext[i] + 32 : ext[i];
    }
    lower_ext[ext_len] = '\0';
    for (size_t i = 0; i < NUM_COMPRESSED_EXTS; i++)
    {
        if (strcmp(lower_ext, COMPRESSED_EXTS[i]) == 0)
        {
            return 1;
        }
    }
    return 0;
}
DLLEXPORT int check_magic_bytes(const char *filepath)
{
    if (!filepath)
        return 0;
    FILE *f = fopen(filepath, "rb");
    if (!f)
        return 0;
    uint8_t buffer[16];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), f);
    fclose(f);
    if (bytes_read == 0)
        return 0;
    for (size_t i = 0; i < NUM_SIGNATURES; i++)
    {
        if (bytes_read >= KNOWN_SIGNATURES[i].sig_len)
        {
            if (memcmp(buffer, KNOWN_SIGNATURES[i].signature, KNOWN_SIGNATURES[i].sig_len) == 0)
            {
                if (KNOWN_SIGNATURES[i].sig_len == 4 &&
                    memcmp(KNOWN_SIGNATURES[i].signature, "\x52\x49\x46\x46", 4) == 0)
                { // sigh check, absurd.
                    if (bytes_read >= 12 && memcmp(buffer + 8, "WEBP", 4) == 0)
                    {
                        return 1;
                    }
                    if (bytes_read >= 12 && memcmp(buffer + 8, "AVI ", 4) == 0)
                    {
                        return 1;
                    }
                    if (bytes_read >= 12 && memcmp(buffer + 8, "WAVE", 4) == 0)
                    {
                        return 1;
                    }
                }
                else
                {
                    return 1;
                }
            }
        }
    }
    return 0;
}
static double calculate_entropy(const uint8_t *data, size_t len)
{
    if (len == 0)
        return 0.0;
    uint32_t freq[256] = {0};
    for (size_t i = 0; i < len; i++)
    {
        freq[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] > 0)
        {
            double p = (double)freq[i] / len;
            entropy -= p * (log(p) / log(2.0));
        }
    }
    return entropy;
}
DLLEXPORT int check_entropy(const char *filepath, double entropy_threshold)
{
    if (!filepath)
        return 0;
    FILE *f = fopen(filepath, "rb");
    if (!f)
        return 0;
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (file_size <= 0)
    {
        fclose(f);
        return 0;
    }
    size_t sample_size = (file_size < 8192) ? file_size : 8192;
    uint8_t *buffer = (uint8_t *)malloc(sample_size);
    if (!buffer)
    {
        fclose(f);
        return 0;
    }
    size_t bytes_read = fread(buffer, 1, sample_size, f);
    fclose(f);
    if (bytes_read == 0)
    {
        free(buffer);
        return 0;
    }
    double entropy = calculate_entropy(buffer, bytes_read);
    free(buffer);
    if (entropy_threshold <= 0.0)
    {
        entropy_threshold = 7.5;
    }
    return (entropy >= entropy_threshold) ? 1 : 0;
}
DLLEXPORT int should_skip_compression(const char *filepath, int mode, double entropy_threshold)
{
    if (!filepath)
        return 0;
    switch (mode)
    {
    case 0:
        return check_extension(filepath);
    case 1:
        return check_magic_bytes(filepath);
    case 2:
        return check_entropy(filepath, entropy_threshold);
    case 3:
        if (check_magic_bytes(filepath))
        {
            return 1;
        }
        return check_entropy(filepath, entropy_threshold);
    default:
        return 0;
    }
}

// end