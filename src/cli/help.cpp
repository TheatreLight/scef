#include "help.h"
#include "Header.h"

#include <iostream>

namespace cli {

void print_help()
{
    std::cout << "scef v" SCEF_VERSION " - Self-contained Encrypted Container Format\n"
              << "\n"
              << "Usage: scef <command> [options]\n"
              << "\n"
              << "Commands:\n"
              << "  create   -c <dir> -f <file> -s <bytes>   Create a new container\n"
              << "  add      -c <dir> -f <file>               Add a file to the container\n"
              << "  list     -c <dir>                         List files in the container\n"
              << "  extract  -c <dir> -o <dir>                Extract files from the container\n"
              << "  benchmark                                  Measure Argon2id timings per KDF profile\n"
              << "\n"
              << "Options:\n"
              << "  -c <dir>                  Path to container directory\n"
              << "  --name <filename>         Container filename (no path separators allowed).\n"
              << "                            create: default is auto-numbered (container.scef,\n"
              << "                              container_1.scef, ...) — never overwrites existing files.\n"
              << "                            open/add/list/extract: default is container.scef;\n"
              << "                              if that does not exist, the single *.scef in -c is used.\n"
              << "  -f <file>                 File to add or extract (repeatable)\n"
              << "  -o <dir>                  Output directory for extract\n"
              << "  -s <bytes>                Fixed container size in bytes (required for create)\n"
              << "  --max_table_size <bytes>  Max encrypted file table size per slot\n"
              << "                            (default: " << DEFAULT_MAX_TABLE_SIZE << " bytes)\n"
              << "  --log-level <level>       debug, info, bench, warning, error\n"
              << "  -y, --yes                 Assume yes for confirmation prompts\n"
              << "  --strength-only           Read password from stdin, print score/bits, exit\n"
              << "\n"
              << "KDF options (create only):\n"
              << "  --kdf-profile <name>      Use a predefined KDF profile.\n"
              << "                            Names: fast, default, high, browser\n"
              << "  --kdf-m <MiB>             Manual Argon2id memory in MiB (min 1, max 4096; <8 warns)\n"
              << "  --kdf-t <n>               Manual Argon2id iterations (min 1, max 100)\n"
              << "  --kdf-p <n>               Manual Argon2id parallelism (min 1, max 64)\n"
              << "                            Aliases: --kdf-m-cost, --kdf-t-cost, --kdf-parallelism\n"
              << "  Note: --kdf-profile and --kdf-m/t/p are mutually exclusive.\n"
              << "        If nothing is specified, the 'default' profile is used.\n"
              << "\n"
              << "Cipher options (create only):\n"
              << "  --cipher <name>           aes, aes-256-gcm, kuznechik, kuznyechik, gost\n"
              << "                            (default: aes)\n"
              << "  --hash <name>             sha256, sha-256, streebog256, streebog-256,\n"
              << "                            streebog512, streebog-512\n"
              << "                            (default: sha256 for AES, streebog512 for Kuznechik)\n"
              << "\n"
              << "Browser viewer options (create only):\n"
              << "  --no-browser-viewer       Do not copy index.html next to the new container.\n"
              << "                            Default: copy index.html (located next to the scef\n"
              << "                            executable). Fails if the file is missing.\n"
              << "\n"
              << "  --help, -h    Show this help\n"
              << "  --version     Show version\n";
}

void print_version()
{
    std::cout << "scef v" SCEF_VERSION "\n";
}

} // namespace cli
