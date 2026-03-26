#ifndef FILE_TABLE_H
#define FILE_TABLE_H

#include "botan/hash.h"

#include <memory>
#include <string>
#include <vector>

// {
//   "files": [
//     {
//       "name": "document.pdf",
//       "size": 1048576,
//       "offset": 131072,
//       "chunks": 16,
//       "checksum_sha256": "a1b2c3d4..."
//     }
//   ]
// }

struct FileEntry {
    std::string name;
    size_t size;
    size_t offset;
    size_t chunks;
    std::string checksum_sha256;
};

class FileTable {
public:
    FileTable();
    ~FileTable() = default;

    void updateChecksum(const void* chunk, size_t size);
    std::string getChecksum();
    void addFileEntry(const std::string& pathToFile, const std::string& checkSum, size_t offset);
    std::string serialize();
    void deserialize(const std::string& data);
    std::string to_string(bool isFull = false) const;
    void reset();
    const FileEntry& getFileInfoByName(const std::string& fName);
    const std::vector<FileEntry>& getFilesTable() const;
private:
    std::vector<FileEntry> filesTable_;
    std::unique_ptr<Botan::HashFunction> funcSHA_;
};

#endif // FILE_TABLE_H
