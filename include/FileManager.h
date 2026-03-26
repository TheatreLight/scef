#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include "CryptoManager.h"
#include "Header.h"
#include "FileTable.h"

#include <fstream>
#include <memory>
#include <vector>

constexpr const char* CONTAINER_FILE_NAME = "container.scef";

class FileManager {
public:
    FileManager();
    ~FileManager();
    FileManager(const FileManager&) = delete;
    FileManager& operator=(const FileManager&) = delete;
    FileManager(FileManager&&) = delete;
    FileManager& operator=(FileManager&&) = delete;

    void init(const std::vector<std::string>& filesList, const std::string& pathToDir);
    void readMeta();
    void extract(const std::string& pathToOutputFolder);
    void write();
    void add();

    void printHeader() const;
    void printFilesTable() const;
private:
    size_t writeHeader();
    size_t writeChunks(size_t headerOffset);
    void writeFilesTable(size_t chunksOffset);
    void setFilesTableInfoToHeader(const std::string& info, size_t chunksOffset);

    void readHeader();
    void readFilesTable();
    void readFiles(const std::string& pathToOutputFolder);
    void readChunks(std::ofstream& output, const FileEntry& file);
    bool checkSumVerify(const FileEntry& file);

    std::unique_ptr<Header> header_;
    FileTable fileTable_;

    std::unique_ptr<std::fstream> containerStream_;
    std::unique_ptr<CryptoManager> crypto_;
    std::string containerFilePath_;
    std::vector<std::string> filesList_;
};

#endif // FILE_MANAGER_H
