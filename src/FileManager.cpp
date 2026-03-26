#include "FileManager.h"
#include "Header.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <ios>
#include <iostream>
#include <memory>

FileManager::FileManager() {
    header_ = std::make_unique<Header>();
    crypto_ = std::make_unique<CryptoManager>();
}

FileManager::~FileManager() {
    if (containerStream_) {
        containerStream_->close();
    }
}

void FileManager::init(const std::vector<std::string>& filesList, const std::string& pathToDir) {
    containerFilePath_ = pathToDir + "/" + CONTAINER_FILE_NAME;
    auto mode = std::ios::binary | std::ios::in | std::ios::out;
    containerStream_ = std::make_unique<std::fstream>(containerFilePath_, mode);
    if (!containerStream_->is_open()) {
        // File doesn't exist — create it
        containerStream_ = std::make_unique<std::fstream>(containerFilePath_,
            std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
    }
    filesList_ = filesList;
}

void FileManager::readMeta() {
    containerStream_->flush();
    readHeader();
    readFilesTable();
}
void FileManager::extract(const std::string& pathToOutputFolder) {
    containerStream_->flush();
    try {
        readMeta();
        readFiles(pathToOutputFolder);
    } catch (const std::exception& e) {
        printf("ERROR | FileManager: Failed to extract files: %s\n", e.what());
    }
}

void FileManager::write() {
    containerStream_->flush();
    try {
        size_t headerOffset = writeHeader();
        size_t chunksOffset = writeChunks(headerOffset);
        writeFilesTable(chunksOffset);
    } catch (const std::exception& e) {
        printf("ERROR | FileManager: Failed to write container file: %s\n", e.what());
    }
}

void FileManager::add() {
    containerStream_->flush();
    try {
        readMeta();
        size_t lastFilePosition = header_->getFileTableOffset();
        lastFilePosition = writeChunks(lastFilePosition);
        writeFilesTable(lastFilePosition);
    } catch (const std::exception& e) {
        printf("ERROR | FileManager: Failed to add files: %s\n", e.what());
    }
}

// TODO: this is test method, should be removed
void FileManager::printHeader() const {
    std::cout << header_->to_string() << std::endl;
}

void FileManager::printFilesTable() const {
    std::cout << fileTable_.to_string() << std::endl;
}

size_t FileManager::writeHeader() {
    containerStream_->seekp(0, std::ios::beg);
    const char* buf = reinterpret_cast<const char*>(header_->buffer().data());
    if (!containerStream_->write(buf, HEADER_SIZE).good()) {
        throw std::runtime_error("Failed to write header");
    }
    return containerStream_->tellp();
}

size_t FileManager::writeChunks(size_t offset) {
    containerStream_->seekp(offset, std::ios::beg);
    std::vector<char> chunk(BLOCK_SIZE);
    std::vector<char> encryptedChunk(ENCRYPTED_BLOCK_SIZE);
    for (const auto& file : filesList_) {
        uint64_t fileStartOffset = containerStream_->tellp();
        std::ifstream input(file, std::ios::binary);
        while(input.read(chunk.data(), BLOCK_SIZE)) {
            fileTable_.updateChecksum(chunk.data(), BLOCK_SIZE);
            crypto_->encrypt(chunk.data(), encryptedChunk.data(), BLOCK_SIZE);
            if (!containerStream_->write(encryptedChunk.data(), ENCRYPTED_BLOCK_SIZE).good()) {
                throw std::runtime_error("Can't write file '" + file + "': Failed to write chunk");
            }
        }
        if (size_t lastBytes = input.gcount(); lastBytes > 0) {
            fileTable_.updateChecksum(chunk.data(), lastBytes);
            crypto_->encrypt(chunk.data(), encryptedChunk.data(), lastBytes);
            if (!containerStream_->
                write(encryptedChunk.data(), lastBytes+NONCE_SIZE+AUTH_TAG_SIZE).good()) {
                throw std::runtime_error("Cant't write file '" + file + "': Failed to write chunk");
            }
        }
        fileTable_.addFileEntry(file, fileTable_.getChecksum(), fileStartOffset);
        header_->increaseFileCount();
    }
    return containerStream_->tellp();
}

void FileManager::writeFilesTable(size_t chunksOffset) {
    std::string fileTableSerialised = fileTable_.serialize();
    size_t fTableSize = fileTableSerialised.length();
    std::vector<char> buf(fTableSize + NONCE_SIZE + AUTH_TAG_SIZE);
    crypto_->encrypt(fileTableSerialised.c_str(), buf.data(), fTableSize);
    if (!containerStream_->write(buf.data(), fTableSize + NONCE_SIZE + AUTH_TAG_SIZE)
        .good()) {
        throw std::runtime_error("Failed to write file table");
    }
    header_->setContainerSize(containerStream_->tellp());
    setFilesTableInfoToHeader(fileTableSerialised, chunksOffset);
}

void FileManager::setFilesTableInfoToHeader(const std::string& info, size_t chunksOffset) {
    header_->setFileTableOffset(chunksOffset);
    header_->setFileTableSize(info.length());
    header_->write();
    containerStream_->seekp(0, std::ios::beg);
    containerStream_->write(reinterpret_cast<const char*>(header_->buffer().data()), HEADER_SIZE);
}

void FileManager::readHeader() {
    HeaderBuffer headerBuffer;
    char* headerPtr = reinterpret_cast<char*>(headerBuffer.data());
    if (!containerStream_->read(headerPtr, HEADER_SIZE).good()) {
        throw std::runtime_error("Failed to read header");
    }
    header_->read(headerBuffer);
}

void FileManager::readFilesTable() {
    size_t fTableSize = header_->getFileTableSize() + NONCE_SIZE + AUTH_TAG_SIZE;
    std::string fTableData(fTableSize, '\0');
    containerStream_->seekg(header_->getFileTableOffset(), std::ios::beg);
    char* fTableDataPtr = fTableData.data();
    if (!containerStream_->read(fTableDataPtr, fTableSize).good()) {
        throw std::runtime_error("Failed to read file table");
    }

    std::string fTableDataDecrypted(header_->getFileTableSize(), '\0');
    crypto_->decrypt(fTableDataPtr, fTableDataDecrypted.data(), header_->getFileTableSize());
    fileTable_.deserialize(fTableDataDecrypted);
}

void FileManager::readFiles(const std::string& pathToOutputFolder) {
    containerStream_->flush();
    for (const std::string& fName : filesList_) {
        std::ofstream output (pathToOutputFolder + "/" + fName, std::ios::binary);
        const FileEntry& fEntry = fileTable_.getFileInfoByName(fName);
        readChunks(output, fEntry);
        if (!checkSumVerify(fEntry)) {
            printf("FileManager: File '%s' decrypted unsuccessfully, wrong checksum\n", fName.c_str());
        }
        output.close();
    }
}

void FileManager::readChunks(std::ofstream& output, const FileEntry& file) {
    containerStream_->seekg(file.offset, std::ios::beg);
    std::vector<char> buf(ENCRYPTED_BLOCK_SIZE);
    std::vector<char> bufDecrypted (BLOCK_SIZE);
    size_t remaining = file.size;
    for (size_t i = 0; i < file.chunks; ++i) {
        size_t plainSize = std::min(remaining, static_cast<size_t>(BLOCK_SIZE));
        size_t encSize = plainSize + NONCE_SIZE + AUTH_TAG_SIZE;
        if (!containerStream_->read(buf.data(), encSize).good()) {
            throw std::runtime_error("Failed to extract file '" + file.name + "': \
                failed read chunk");
        }
        crypto_->decrypt(buf.data(), bufDecrypted.data(), plainSize);
        fileTable_.updateChecksum(bufDecrypted.data(), plainSize);
        if (!output.write(bufDecrypted.data(), plainSize).good()) {
            throw std::runtime_error("Failed to extract file '" + file.name + "': \
                failed write chunk");
        }
        remaining -= plainSize;
    }
}

bool FileManager::checkSumVerify(const FileEntry& file) {
    std::string checkSum = fileTable_.getChecksum();
    return checkSum == file.checksum_sha256;
}
