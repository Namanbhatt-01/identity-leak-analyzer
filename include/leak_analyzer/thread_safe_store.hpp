#ifndef THREAD_SAFE_STORE_HPP
#define THREAD_SAFE_STORE_HPP

#include <vector>
#include <mutex>

namespace leak_analyzer {

template <typename T>
class ThreadSafeStore {
private:
    std::vector<T> items;
    mutable std::mutex store_mutex;

public:
    ThreadSafeStore() = default;
    ~ThreadSafeStore() = default;

    ThreadSafeStore(const ThreadSafeStore&) = delete;
    ThreadSafeStore& operator=(const ThreadSafeStore&) = delete;

    void insert(const T& item) {
        std::lock_guard<std::mutex> lock(store_mutex);
        items.push_back(item);
    }

    void insert_batch(const std::vector<T>& batch) {
        std::lock_guard<std::mutex> lock(store_mutex);
        items.insert(items.end(), batch.begin(), batch.end());
    }

    std::vector<T> get_all() const {
        std::lock_guard<std::mutex> lock(store_mutex);
        return items;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(store_mutex);
        items.clear();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(store_mutex);
        return items.size();
    }
};

} // namespace leak_analyzer

#endif // THREAD_SAFE_STORE_HPP
