#pragma once

/**
 * rest_api.hh — REST API helpers and data structures
 *
 * Demonstrates:
 *   - In-memory CRUD store
 *   - JSON serialization
 *   - Response utilities
 */

#include "../include/http_a_server.hh"
#include <shared_mutex>
#include <optional>

/* --------------------------------------------- */

// Generic in-memory store with thread-safe CRUD
template <typename T>
class store_t
{
private:
  mutable std::shared_mutex mtx;
  std::unordered_map<std::string, T> data;
  uint64_t next_id = 1;

public:
  inline std::string create_(const T& _item)
  {
    std::unique_lock lock(mtx);
    std::string id = std::to_string(next_id++);
    data[id] = _item;
    return id;
  }

  inline std::optional<T> read_(const std::string& _id) const
  {
    std::shared_lock lock(mtx);
    auto it = data.find(_id);
    if (it != data.end()) return it->second;
    return std::nullopt;
  }

  inline std::vector<std::pair<std::string, T>> list_() const
  {
    std::shared_lock lock(mtx);
    std::vector<std::pair<std::string, T>> result;
    result.reserve(data.size());
    for (const auto& [id, item] : data)
    {
      result.emplace_back(id, item);
    }
    return result;
  }

  inline bool update_(const std::string& _id, const T& _item)
  {
    std::unique_lock lock(mtx);
    auto it = data.find(_id);
    if (it == data.end()) return false;
    it->second = _item;
    return true;
  }

  inline bool remove_(const std::string& _id)
  {
    std::unique_lock lock(mtx);
    return data.erase(_id) > 0;
  }

  inline size_t count_() const
  {
    std::shared_lock lock(mtx);
    return data.size();
  }

  inline void clear_()
  {
    std::unique_lock lock(mtx);
    data.clear();
    next_id = 1;
  }
};

/* --------------------------------------------- */

// Example entity
struct item_t
{
  std::string name;
  std::string description;
  double price;
  bool active;

  item_t() : price(0), active(true) {}
  item_t(const std::string& _name, const std::string& _desc, double _price)
    : name(_name), description(_desc), price(_price), active(true) {}

  nlohmann::json to_json_() const
  {
    return {
      {"name", name},
      {"description", description},
      {"price", price},
      {"active", active}
    };
  }

  static item_t from_json_(const nlohmann::json& _j)
  {
    item_t item;
    if (_j.contains("name")) item.name = _j["name"].get<std::string>();
    if (_j.contains("description")) item.description = _j["description"].get<std::string>();
    if (_j.contains("price")) item.price = _j["price"].get<double>();
    if (_j.contains("active")) item.active = _j["active"].get<bool>();
    return item;
  }
};

/* --------------------------------------------- */

// Response helpers
namespace rest
{
  inline void ok_(http_s& _s, const nlohmann::json& _data)
  {
    _s.status_(200);
    _s.send_json_(_data);
  }

  inline void created_(http_s& _s, const std::string& _id, const nlohmann::json& _data)
  {
    nlohmann::json response = _data;
    response["id"] = _id;
    _s.status_(201);
    _s.send_json_(response);
  }

  inline void no_content_(http_s& _s)
  {
    _s.status_(204);
    _s.send_("");
  }

  inline void bad_request_(http_s& _s, const std::string& _msg = "Bad Request")
  {
    _s.status_(400);
    _s.send_json_({{"error", _msg}});
  }

  inline void not_found_(http_s& _s, const std::string& _msg = "Not Found")
  {
    _s.status_(404);
    _s.send_json_({{"error", _msg}});
  }

  inline void method_not_allowed_(http_s& _s)
  {
    _s.status_(405);
    _s.send_json_({{"error", "Method Not Allowed"}});
  }

  inline void internal_error_(http_s& _s, const std::string& _msg = "Internal Server Error")
  {
    _s.status_(500);
    _s.send_json_({{"error", _msg}});
  }

  // Extract ID from path like "/items/123" -> "123"
  inline std::string path_id_(const std::string& _path)
  {
    size_t last_slash = _path.rfind('/');
    if (last_slash == std::string::npos || last_slash == _path.size() - 1)
    {
      return "";
    }
    return _path.substr(last_slash + 1);
  }

  // Parse JSON body safely
  inline std::optional<nlohmann::json> parse_json_(const http_q& _q)
  {
    try
    {
      if (_q.body.empty()) return std::nullopt;
      return nlohmann::json::parse(_q.body);
    }
    catch (...)
    {
      return std::nullopt;
    }
  }
}

/* --------------------------------------------- */

