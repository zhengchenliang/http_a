#pragma once

#include <cstdlib>
#include <cstddef>
#include <deque>
#include <memory>
#include <random>
#include <concepts>
#include <optional>
#include <algorithm>
#include <functional>
#include <atomic>
#include <thread>
#include <future>
#include <mutex>
#include <semaphore>
#include <type_traits>

/* --------------------------------------------- */

namespace pth
{
  template <typename Lock> concept is_lockable = requires(Lock &&lock)
  { // https://en.cppreference.com/w/cpp/named_req/Lockable
    lock.lock();
    lock.unlock();
    { lock.try_lock() } -> std::convertible_to<bool>;
  };
  namespace details
  {
    using pth_f = std::function<void()>; // C++20
  }
}

template <typename T, typename Lock = std::mutex> requires pth::is_lockable<Lock>
class pth_q // thread safe queue <T, Lock>
{
private:
  std::deque<T> the_queue{};
  mutable Lock the_mutex{};
public:
  using value_type = T;
  using size_type = typename std::deque<T>::size_type;
  pth_q() = default;
  pth_q(const pth_q&) = delete;
  pth_q& operator=(const pth_q&) = delete;
  pth_q(pth_q&&) = delete;
  pth_q& operator=(pth_q&&) = delete;
  inline void push_back(T&& value)
  {
    std::scoped_lock lock(the_mutex);
    the_queue.push_back(std::forward<T>(value));
  }
  inline void push_front(T&& value)
  {
    std::scoped_lock lock(the_mutex);
    the_queue.push_front(std::forward<T>(value));
  }
  inline bool empty() const noexcept
  {
    std::scoped_lock lock(the_mutex);
    return the_queue.empty();
  }
  inline size_type clear()
  {
    std::scoped_lock lock(the_mutex);
    auto size = the_queue.size();
    the_queue.clear();
    return size;
  }
  inline std::optional<T> pop_front()
  {
    std::scoped_lock lock(the_mutex);
    if (the_queue.empty()) return std::nullopt;
    std::optional<T> front = std::move(the_queue.front());
    the_queue.pop_front();
    return front;
  }
  inline std::optional<T> pop_back()
  {
    std::scoped_lock lock(the_mutex);
    if (the_queue.empty()) return std::nullopt;
    std::optional<T> back = std::move(the_queue.back());
    the_queue.pop_back();
    return back;
  }
  inline std::optional<T> steal_()
  {
    std::scoped_lock lock(the_mutex);
    if (the_queue.empty()) return std::nullopt;
    std::optional<T> back = std::move(the_queue.back());
    the_queue.pop_back();
    return back;
  }
};

/* --------------------------------------------- */

typedef void (*tfun_p)(void*);

template <typename Function = pth::details::pth_f, typename Thread = std::jthread>
requires std::invocable<Function> && std::is_same_v<void, std::invoke_result_t<Function>>
class pth_v
{
private:
  std::atomic<bool> resize_active{false};
  std::atomic<bool> inited{false};
  std::mutex resize_mutex;
  std::condition_variable resize_cv;
  struct task_item
  {
    pth_q<Function> tasks{};
    std::binary_semaphore signal{0};
  };
  std::vector<Thread> threads_v;
  std::deque<task_item> tasks_queue;
  std::atomic<size_t> next_thread_idx{0}; // round-robin assignment
  std::atomic<size_t> num_queues{0};
  std::atomic_int_fast64_t unassigned_tasks{0}, in_flight_tasks{0};
  std::atomic_bool threads_complete_signal{false};
public:
  template <typename InitFunc = std::function<void(std::size_t)>>
  requires std::invocable<InitFunc, std::size_t>
    && std::is_same_v<void, std::invoke_result_t<InitFunc, std::size_t>>
  explicit pth_v(const unsigned int& _thread_num = std::thread::hardware_concurrency()
    , InitFunc _init = [](std::size_t) {}
  ) { init_(_thread_num, std::move(_init)); }
  pth_v(const pth_v&) = delete;
  pth_v& operator=(const pth_v&) = delete;
  pth_v(pth_v&&) = delete;
  pth_v& operator=(pth_v&&) = delete;
  ~pth_v() { fina_(); }
  inline bool is_inited_() const noexcept { return inited.load(std::memory_order_acquire); }
  template <typename InitFunc = std::function<void(std::size_t)>>
  requires std::invocable<InitFunc, std::size_t>
    && std::is_same_v<void, std::invoke_result_t<InitFunc, std::size_t>>
  inline void init_(const unsigned int& _thread_num = std::thread::hardware_concurrency()
    , InitFunc _init = [](std::size_t) {}
  )
  {
    if (inited.load(std::memory_order_acquire)) fina_(); // re-init
    std::unique_lock resize_lock(resize_mutex);
    resize_active.store(true, std::memory_order_release);
    tasks_queue.resize(_thread_num);
    num_queues.store(_thread_num, std::memory_order_release);
    std::atomic<size_t> init_barrier{_thread_num};
    std::size_t cur_id = 0;
    for (std::size_t i = 0; i < _thread_num; ++i)
    {
      try
      {
        threads_v.emplace_back([&, id = cur_id, _init](const std::stop_token& _stop_tok)
        {
          try { std::invoke(_init, id); } catch (...) {} // user init function
          init_barrier.fetch_sub(1, std::memory_order_release);
          init_barrier.notify_all();
          std::random_device rd; // random stealing
          std::mt19937 gen(rd() ^ (id << 16)); // seed with thread ID
          std::uniform_int_distribution<size_t> dist;
          do
          {
            tasks_queue[id].signal.acquire(); // wait until signaled
            do
            {
              while (auto task = tasks_queue[id].tasks.pop_front())
              {
                unassigned_tasks.fetch_sub(1, std::memory_order_release);
                std::invoke(std::move(task.value())); // invoke the task
                in_flight_tasks.fetch_sub(1, std::memory_order_release);
              }
              const size_t n_queues = num_queues.load(std::memory_order_acquire);
              if (n_queues > 1)
              {
                const size_t max_attempts = std::min(size_t(4), n_queues - 1);
                for (size_t attempt = 0; attempt < max_attempts; ++attempt)
                {
                  size_t victim;
                  do
                  {
                    dist.param(std::uniform_int_distribution<size_t>::param_type(0, n_queues - 1));
                    victim = dist(gen);
                  } while (victim == id && n_queues > 1);
                  if (auto task = tasks_queue[victim].tasks.steal_()) // steal a task
                  {
                    unassigned_tasks.fetch_sub(1, std::memory_order_release);
                    std::invoke(std::move(task.value()));
                    in_flight_tasks.fetch_sub(1, std::memory_order_release);
                    break;
                  }
                }
              }
            } while (unassigned_tasks.load(std::memory_order_acquire) > 0);
            if (in_flight_tasks.load(std::memory_order_acquire) == 0) // all work done
            {
              threads_complete_signal.store(true, std::memory_order_release);
              threads_complete_signal.notify_one(); // release memory barrier
            }
          } while (!_stop_tok.stop_requested());
        });
        ++cur_id;
      }
      catch (...) // rollback on failure
      {
        tasks_queue.pop_back();
        num_queues.store(cur_id, std::memory_order_release);
        init_barrier.store(cur_id, std::memory_order_release); // adjust barrier for failed thread
      }
    }
    // wait for all threads to complete their init functions
    while (init_barrier.load(std::memory_order_acquire) > 0)
    {
      init_barrier.wait(init_barrier.load(std::memory_order_acquire), std::memory_order_acquire);
    }
    resize_active.store(false, std::memory_order_release);
    resize_cv.notify_all();
    inited.store(true, std::memory_order_release);
  }
  inline void fina_(bool _force = false)
  {
    if (!inited.load(std::memory_order_acquire)) return; // not initialized
    if (!_force) sync_();
    else clear_(); // best effort to clear all tasks
    for (std::size_t i = 0; i < threads_v.size(); ++i) // stop all threads
    {
      threads_v[i].request_stop();
      tasks_queue[i].signal.release();
      threads_v[i].join();
    }
    threads_v.clear();
    tasks_queue.clear();
    next_thread_idx.store(0, std::memory_order_relaxed);
    num_queues.store(0, std::memory_order_relaxed);
    unassigned_tasks.store(0, std::memory_order_relaxed);
    in_flight_tasks.store(0, std::memory_order_relaxed);
    threads_complete_signal.store(false, std::memory_order_relaxed);
    inited.store(false, std::memory_order_release);
  }
  template <typename InitFunc = std::function<void(std::size_t)>>
  requires std::invocable<InitFunc, std::size_t>
    && std::is_same_v<void, std::invoke_result_t<InitFunc, std::size_t>>
  inline void rebn_(const unsigned int& _thread_num = std::thread::hardware_concurrency(), InitFunc _init = [](std::size_t) {})
  {
    fina_(false);
    init_(_thread_num, std::move(_init));
  }
  inline auto size_() const { return threads_v.size(); }
  inline short more_(const size_t _more = 1)
  {
    if (_more == 0) return 0;
    std::unique_lock resize_lock(resize_mutex);
    resize_active.store(true, std::memory_order_release);
    std::size_t cur_id = threads_v.size();
    std::size_t added = 0;
    for (size_t i = 0; i < _more; ++i)
    {
      try
      {
        tasks_queue.emplace_back();
        threads_v.emplace_back([&, id = cur_id](const std::stop_token& _stop_tok)
        {
          std::random_device rd; // random stealing
          std::mt19937 gen(rd() ^ (id << 16)); // seed with thread ID
          std::uniform_int_distribution<size_t> dist;
          do
          {
            tasks_queue[id].signal.acquire(); // wait until signaled
            do
            {
              while (auto task = tasks_queue[id].tasks.pop_front())
              {
                unassigned_tasks.fetch_sub(1, std::memory_order_release);
                std::invoke(std::move(task.value()));
                in_flight_tasks.fetch_sub(1, std::memory_order_release);
              }
              const size_t n_queues = num_queues.load(std::memory_order_acquire);
              if (n_queues > 1)
              {
                const size_t max_attempts = std::min(size_t(4), n_queues - 1);
                for (size_t attempt = 0; attempt < max_attempts; ++attempt)
                {
                  size_t victim;
                  do
                  {
                    dist.param(std::uniform_int_distribution<size_t>::param_type(0, n_queues - 1));
                    victim = dist(gen);
                  } while (victim == id && n_queues > 1);
                  if (auto task = tasks_queue[victim].tasks.steal_()) // steal a task
                  {
                    unassigned_tasks.fetch_sub(1, std::memory_order_release);
                    std::invoke(std::move(task.value()));
                    in_flight_tasks.fetch_sub(1, std::memory_order_release);
                    break;
                  }
                }
              }
            } while (unassigned_tasks.load(std::memory_order_acquire) > 0);
            if (in_flight_tasks.load(std::memory_order_acquire) == 0) // all work done
            {
              threads_complete_signal.store(true, std::memory_order_release);
              threads_complete_signal.notify_one();
            }
          } while (!_stop_tok.stop_requested());
        });
        ++cur_id;
        ++added;
        num_queues.store(cur_id, std::memory_order_release);
      }
      catch (...) // rollback on failure
      {
        if (tasks_queue.size() > threads_v.size()) tasks_queue.pop_back();
        resize_active.store(false, std::memory_order_release);
        resize_cv.notify_all();
        return (added > 0) ? added : -1; // partial success or total failure
      }
    }
    resize_active.store(false, std::memory_order_release);
    resize_cv.notify_all();
    return 0;
  }
  inline short less_(const size_t _less = 1)
  {
    size_t current_size = threads_v.size();
    if (_less == 0 || _less >= current_size) return 1;
    std::unique_lock resize_lock(resize_mutex);
    resize_active.store(true, std::memory_order_release);
    sync_();
    size_t remaining_threads = current_size - _less;
    num_queues.store(remaining_threads, std::memory_order_release);
    for (size_t i = remaining_threads; i < current_size; ++i)
    {
      threads_v[i].request_stop();
      tasks_queue[i].signal.release();
    }
    for (size_t i = remaining_threads; i < current_size; ++i)
    {
      threads_v[i].join();
    }
    threads_v.resize(remaining_threads);
    tasks_queue.resize(remaining_threads);
    next_thread_idx.store(0, std::memory_order_relaxed);
    resize_active.store(false, std::memory_order_release);
    resize_cv.notify_all();
    return 0;
  }
  inline short resz_(const size_t _num)
  {
    size_t current_size = threads_v.size();
    if (_num == current_size) return 0;
    if (_num > current_size) return more_(_num - current_size);
    else return less_(current_size - _num);
  }
  inline short operator+=(const size_t _more) { return more_(_more); }
  inline short operator-=(const size_t _less) { return less_(_less); }
  inline short operator=(const size_t _num) { return resz_(_num); }
  template <typename Func
    , typename... Args
    , typename RetType = std::invoke_result_t<Func&&, Args&&...>
  > requires std::invocable<Func, Args...>
  inline std::future<RetType> load_(Func _func, Args... _args)
  {
    auto shared_promise = std::make_shared<std::promise<RetType>>();
    auto task = [func = std::move(_func), ... largs = std::move(_args), promise = shared_promise]() mutable
    {
      try
      {
        if constexpr (std::is_same_v<RetType, void>)
        {
          func(largs...);
          promise->set_value();
        }
        else promise->set_value(func(largs...));
      }
      catch (...) { promise->set_exception(std::current_exception()); }
    };
    auto future = shared_promise->get_future(); // future get before enqueuing the task
    enqueue_task_(std::move(task));
    return future;
  }
  template <typename Func, typename... Args> requires std::invocable<Func, Args...>
  inline void fire_(Func&& _func, Args&&... _args) // C++ style: lambda, std::function, or any callable
  {
    enqueue_task_(std::move(
      [func = std::forward<Func>(_func), ... largs = std::forward<Args>(_args)]() mutable
      -> decltype(auto)
      {
        try
        {
          if constexpr (std::is_same_v<void, std::invoke_result_t<Func&&, Args&&...>>) std::invoke(func, largs...);
          else std::ignore = std::invoke(func, largs...);
        } catch (...) {}
      }
    ));
  }
  inline void fire_(tfun_p _tfun, void* _targ) // C-style: void-return function pointer and void* argument
  {
    fire_([_tfun, _targ]() { _tfun(_targ); });
  }
  template <typename Func>
  inline void operator+=(Func&& _func) { fire_(std::forward<Func>(_func)); }
  inline size_t clear_()
  {
    size_t removed_task_count{0};
    for (auto& task_list : tasks_queue)
    {
      removed_task_count += task_list.tasks.clear();
    }
    in_flight_tasks.fetch_sub(removed_task_count, std::memory_order_release);
    unassigned_tasks.fetch_sub(removed_task_count, std::memory_order_release);
    return removed_task_count;
  }
  inline bool empty_() const noexcept
  {
    return in_flight_tasks.load(std::memory_order_acquire) == 0;
  }
  inline size_t pending_() const noexcept
  {
    return static_cast<size_t>(in_flight_tasks.load(std::memory_order_acquire));
  }
  inline void sync_()
  {
    if (in_flight_tasks.load(std::memory_order_acquire) == 0) return;
    while (true)
    {
      threads_complete_signal.wait(false);
      if (in_flight_tasks.load(std::memory_order_acquire) == 0) return;
      threads_complete_signal.store(false, std::memory_order_relaxed);
    }
  }
private:
  template <typename Func>
  inline void enqueue_task_(Func&& _f)
  {
    if (resize_active.load(std::memory_order_acquire))
    {
      std::unique_lock lock(resize_mutex);
      resize_cv.wait(lock, [this]()
        {
          return !resize_active.load(std::memory_order_acquire);
        }
      );
    }
    const size_t n_queues = num_queues.load(std::memory_order_acquire);
    if (n_queues == 0) return;
    const size_t i = next_thread_idx.fetch_add(1, std::memory_order_relaxed) % n_queues; // round-robin
    unassigned_tasks.fetch_add(1, std::memory_order_release);
    const auto prev_in_flight = in_flight_tasks.fetch_add(1, std::memory_order_release);
    if (prev_in_flight == 0) threads_complete_signal.store(false, std::memory_order_release);
    tasks_queue[i].tasks.push_back(std::forward<Func>(_f));
    tasks_queue[i].signal.release();
  }
};
using pth_t = pth_v<>;

/* --------------------------------------------- */