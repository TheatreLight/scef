#include "FileTable.h"
#include "Header.h"
#include "Logger.h"

#include "nlohmann/json.hpp"
#include "botan/hex.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <sstream>
#include <nlohmann/detail/conversions/to_json.hpp>
#include <nlohmann/json_fwd.hpp>

FileTable::FileTable() {
    funcSHA_ = Botan::HashFunction::create("SHA-256");
}

void FileTable::updateChecksum(const void* chunk, size_t size) {
    funcSHA_->update(reinterpret_cast<const uint8_t*>(chunk), size);
}

std::string FileTable::getChecksum() {
    auto digest = funcSHA_->final();
    funcSHA_->clear();
    return Botan::hex_encode(digest);
}

void FileTable::resetChecksum() {
    funcSHA_->clear();
}

void FileTable::addFileEntry(const std::string& pathToFile, const std::string& checkSum,
                             size_t offset, size_t actual_size) {
    FileEntry file;
    std::string fileName = std::filesystem::path(pathToFile).filename().string();
    while (std::any_of(filesTable_.begin(), filesTable_.end(),
        [&fileName](const FileEntry& fileEntry){return fileName == fileEntry.name;})) {
            fileName = "(copy)" + fileName;
    }
    file.name = fileName;
    // Use the actual bytes read during writeChunks() — not a re-query of the filesystem.
    // This avoids a TOCTOU race if the source file changes between writing and recording.
    file.size = actual_size;
    size_t numChunks = file.size / BLOCK_SIZE + (file.size % BLOCK_SIZE != 0);
    file.chunks = numChunks;
    file.offset = offset;
    file.checksum_sha256 = checkSum;

    filesTable_.push_back(file);
    LOG_DEBUG("addFileEntry: '%s', size=%zu, chunks=%zu, offset=%zu, sha256=%.16s...",
              file.name.c_str(), file.size, file.chunks, file.offset,
              file.checksum_sha256.c_str());
}

std::string FileTable::serialize() {
    nlohmann::json j;
    j["next_write_offset"] = next_write_offset_;
    j["files"] = nlohmann::json::array();
    for (const auto& file : filesTable_) {
        nlohmann::json tmp;
        tmp["name"] = file.name;
        tmp["size"] = file.size;
        tmp["offset"] = file.offset;
        tmp["chunks"] = file.chunks;
        tmp["checksum_sha256"] = file.checksum_sha256;
        j["files"].push_back(tmp);
    }
    return j.dump();
}

void FileTable::deserialize(const std::string& data) {
    nlohmann::json tmp = nlohmann::json::parse(data);
    filesTable_.clear();
    // next_write_offset is present in containers written by this implementation.
    // Older containers (or containers without files) may omit it — default to 0.
    next_write_offset_ = tmp.value("next_write_offset", uint64_t{0});
    for (const auto& file : tmp["files"]) {
        FileEntry entry;
        entry.name = file["name"].get<std::string>();
        entry.size = file["size"].get<size_t>();
        entry.offset = file["offset"].get<size_t>();
        entry.chunks = file["chunks"].get<size_t>();
        entry.checksum_sha256 = file["checksum_sha256"].get<std::string>();
        filesTable_.push_back(entry);
    }
}

std::string FileTable::to_string(bool isFull) const {
    std::ostringstream ss;
    ss << "=== SCEF File Table ===\n";
    ss << "file_count: " << filesTable_.size() << "\n";
    for (size_t i = 0; i < filesTable_.size(); ++i) {
        const auto& f = filesTable_[i];
        ss << "--- File [" << i << "] ---\n";
        ss << "  name:            " << f.name << "\n";
        ss << "  size:            " << f.size << "\n";
        if (isFull) {
            ss << "  offset:          " << f.offset << "\n";
            ss << "  chunks:          " << f.chunks << "\n";
            ss << "  checksum_sha256: " << f.checksum_sha256 << "\n";
        }
    }
    return ss.str();
}

void FileTable::reset() {
    filesTable_.clear();
}

const FileEntry& FileTable::getFileInfoByName(const std::string& fName) {
    auto iter = std::find_if(filesTable_.begin(), filesTable_.end(),
        [&fName](const FileEntry& fEntry){return fEntry.name == fName;});
    if (iter != filesTable_.end()) {
        return *iter;
    }
    throw std::runtime_error("There is no such file in current container or wrong file name.");
}

const std::vector<FileEntry>& FileTable::getFilesTable() const {
    return filesTable_;
}
