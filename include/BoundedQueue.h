#ifndef BOUNDED_QUEUE_H
#define BOUNDED_QUEUE_H

#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>

template<typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity) : capacity_(capacity) {}

    bool push(T item) {
        std::unique_lock lock(mtx_);
        not_full_.wait(lock, [this] { return queue_.size() < capacity_ || closed_; });
        if (closed_) return false;
        queue_.push(std::move(item));
        not_empty_.notify_one();
        return true;
    }

    std::optional<T> pop() {
        std::unique_lock lock(mtx_);
        not_empty_.wait(lock, [this] { return !queue_.empty() || closed_; });
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }

    void close() {
        std::lock_guard lock(mtx_);
        closed_ = true;
        not_full_.notify_all();
        not_empty_.notify_all();
    }

    bool closed() const {
        std::lock_guard lock(mtx_);
        return closed_;
    }

private:
    std::queue<T> queue_;
    size_t capacity_;
    mutable std::mutex mtx_;
    std::condition_variable not_full_;
    std::condition_variable not_empty_;
    bool closed_ = false;
};

#endif // BOUNDED_QUEUE_H
