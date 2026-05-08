#ifndef FILE_TABLE_H
#define FILE_TABLE_H

#include <cstdint>
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
    uint64_t size;
    uint64_t offset;
    uint64_t chunks;
    std::string checksum_sha256;
};

class FileTable {
public:
    FileTable();
    ~FileTable();

    void addFileEntry(const std::string& pathToFile, const std::string& checkSum, uint64_t offset,
                      uint64_t actual_size);
    std::string serialize();
    void deserialize(const std::string& data);
    std::string to_string(bool isFull = false) const;
    const FileEntry& getFileInfoByName(const std::string& fName);
    const std::vector<FileEntry>& getFilesTable() const;

    // Offset of the byte immediately after the last written data chunk.
    // Persisted in the file table JSON so add() can resume without
    // recalculating across slot boundaries.
    void setNextWriteOffset(uint64_t offset) { next_write_offset_ = offset; }
    uint64_t getNextWriteOffset() const { return next_write_offset_; }

private:
    std::vector<FileEntry> filesTable_;
    uint64_t next_write_offset_ = 0;
};

#endif // FILE_TABLE_H
