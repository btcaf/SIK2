/**
 * Implementacja blokującej kolejki.
 */

#ifndef SIKRADIO_BLOCKING_QUEUE_HPP
#define SIKRADIO_BLOCKING_QUEUE_HPP

#include <queue>
#include <mutex>
#include <condition_variable>

template <typename T>
class Blocking_Queue {
public:
    void push(T const& value) {
        {
            std::lock_guard<std::mutex> lock{mut};
            queue.push(value);
        }
        cv.notify_one();
    }

    T pop() {
        std::unique_lock<std::mutex> lock(mut);
        cv.wait(lock, [this] { return !queue.empty(); });

        T result(std::move(queue.front()));
        queue.pop();
        return result;
    }
private:
    std::queue<T> queue;

    std::mutex mut;
    std::condition_variable cv;
};


#endif //SIKRADIO_BLOCKING_QUEUE_HPP
