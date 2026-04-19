#ifndef PIPELINE_TYPES_H
#define PIPELINE_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

struct ChunkTask {
    uint64_t seq_no = 0;
    std::vector<char> data;
    size_t data_size = 0;
    bool end_of_file = false;
    std::string file_path;
    std::string file_checksum;
    uint64_t file_plain_size = 0;

    ChunkTask() = default;
    ChunkTask(const ChunkTask&) = delete;
    ChunkTask& operator=(const ChunkTask&) = delete;
    ChunkTask(ChunkTask&&) = default;
    ChunkTask& operator=(ChunkTask&&) = default;
};

struct ProcessedChunk {
    uint64_t seq_no = 0;
    std::vector<char> data;
    size_t data_size = 0;
    bool end_of_file = false;
    std::string file_path;
    std::string file_checksum;
    uint64_t file_plain_size = 0;
    std::string error;

    ProcessedChunk() = default;
    ProcessedChunk(const ProcessedChunk&) = delete;
    ProcessedChunk& operator=(const ProcessedChunk&) = delete;
    ProcessedChunk(ProcessedChunk&&) = default;
    ProcessedChunk& operator=(ProcessedChunk&&) = default;
};

#endif // PIPELINE_TYPES_H
