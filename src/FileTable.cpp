#include "FileTable.h"
#include "Header.h"
#include "Logger.h"

#include "nlohmann/json.hpp"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <sstream>
#include <unordered_set>
#include <nlohmann/detail/conversions/to_json.hpp>
#include <nlohmann/json_fwd.hpp>

FileTable::FileTable() {
    LOG_INFO("FileTable::FileTable()");
}

FileTable::~FileTable() {
    LOG_INFO("FileTable::~FileTable()");
}

void FileTable::addFileEntry(const std::string& pathToFile, const std::string& checksum,
    uint64_t offset, uint64_t actual_size)
{
    LOG_INFO("Call FileTable::addFileEntry()");

    // Build a set of existing names for O(1) collision lookup.
    std::unordered_set<std::string> existingNames;
    existingNames.reserve(filesTable_.size());
    for (const auto& e : filesTable_) {
        existingNames.insert(e.name);
    }

    // Resolve duplicate names using numeric suffix: "file.txt", "file (2).txt", "file (3).txt".
    // Extension = last dot only; files with no dot get suffix appended before end-of-string.
    std::filesystem::path fsPath = std::filesystem::path(pathToFile).filename();
    std::string stem      = fsPath.stem().string();
    std::string extension = fsPath.extension().string(); // includes the dot, or empty
    std::string fileName  = stem + extension;

    if (existingNames.count(fileName)) {
        for (uint64_t n = 2; ; ++n) {
            std::string candidate = stem + " (" + std::to_string(n) + ")" + extension;
            if (!existingNames.count(candidate)) {
                fileName = candidate;
                break;
            }
        }
    }

    FileEntry file;
    file.name = fileName;
    // Use the actual bytes read during writeChunks() — not a re-query of the filesystem.
    // This avoids a TOCTOU race if the source file changes between writing and recording.
    file.size   = actual_size;
    file.chunks = (actual_size == 0) ? 0
                : (actual_size / BLOCK_SIZE + (actual_size % BLOCK_SIZE != 0));
    file.offset = offset;
    file.checksum = checksum;

    filesTable_.push_back(file);
    LOG_DEBUG("FileTable::addFileEntry: '%s', size=%llu, chunks=%llu, offset=%llu, checksum=%.16s...",
              file.name.c_str(),
              static_cast<unsigned long long>(file.size),
              static_cast<unsigned long long>(file.chunks),
              static_cast<unsigned long long>(file.offset),
              file.checksum.c_str());
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
        tmp["checksum"] = file.checksum;
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
        entry.name             = file["name"].get<std::string>();
        entry.size             = file["size"].get<uint64_t>();
        entry.offset           = file["offset"].get<uint64_t>();
        entry.chunks           = file["chunks"].get<uint64_t>();
        entry.checksum         = file["checksum"].get<std::string>();
        filesTable_.push_back(entry);
    }

    // F-5: If next_write_offset is 0 but entries exist, the field was absent in
    // an older container or the table was partially reconstructed. Recompute to
    // prevent add() from overwriting offset 0 (the primary header slot).
    if (next_write_offset_ == 0 && !filesTable_.empty()) {
        uint64_t recomputed = 0;
        for (const auto& entry : filesTable_) {
            uint64_t entryEnd = entry.offset + entry.chunks * ENCRYPTED_BLOCK_SIZE;
            if (entryEnd > recomputed) {
                recomputed = entryEnd;
            }
        }
        if (recomputed > 0) {
            LOG_WARN("FileTable::deserialize: next_write_offset absent; "
                     "recomputed from file entries as %llu",
                     static_cast<unsigned long long>(recomputed));
            next_write_offset_ = recomputed;
        }
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
            ss << "  checksum:        " << f.checksum << "\n";
        }
    }
    return ss.str();
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
