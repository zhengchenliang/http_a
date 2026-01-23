/**
 * rest_api.cc — RESTful API server example
 *
 * Demonstrates:
 *   - Full CRUD operations (GET, POST, PUT, DELETE)
 *   - JSON request/response handling
 *   - Path parameter extraction
 *   - In-memory data store
 *   - Error handling patterns
 *
 * Build: cmake --build . --target rest_api
 * Run:   ./rest_api [port]
 *
 * API Endpoints:
 *   GET    /api/items       — List all items
 *   GET    /api/items/      — Get item by ID (e.g., /api/items/1)
 *   POST   /api/items       — Create new item
 *   PUT    /api/items/      — Update item by ID
 *   DELETE /api/items/      — Delete item by ID
 *   GET    /api/health      — Health check
 */

#include "rest_api.hh"

// Global store
store_t<item_t> items;

int main(int argc, char** argv)
{
  int port = (argc > 1) ? std::atoi(argv[1]) : 8080;

  http_a app;

  // Health check
  app.get_("/api/health", [](const http_q& _q, http_s& _s)
  {
    rest::ok_(_s, {
      {"status", "healthy"},
      {"items_count", items.count_()}
    });
  }, true);

  // GET /api/items — List all items
  app.get_("/api/items", [](const http_q& _q, http_s& _s)
  {
    std::string rest_path = _q.url_rest_();

    // Check if requesting specific item: /api/items/123
    if (!rest_path.empty() && rest_path != "/")
    {
      std::string id = rest::path_id_(rest_path);
      if (id.empty())
      {
        rest::bad_request_(_s, "Invalid item ID");
        return;
      }
      auto item = items.read_(id);
      if (!item)
      {
        rest::not_found_(_s, "Item not found");
        return;
      }
      nlohmann::json response = item->to_json_();
      response["id"] = id;
      rest::ok_(_s, response);
      return;
    }

    // List all items
    auto all = items.list_();
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& [id, item] : all)
    {
      nlohmann::json obj = item.to_json_();
      obj["id"] = id;
      arr.push_back(obj);
    }
    rest::ok_(_s, {{"items", arr}, {"count", arr.size()}});
  }, true);

  // POST /api/items — Create new item
  app.post_("/api/items", [](const http_q& _q, http_s& _s)
  {
    auto json = rest::parse_json_(_q);
    if (!json)
    {
      rest::bad_request_(_s, "Invalid JSON body");
      return;
    }

    try
    {
      item_t item = item_t::from_json_(*json);
      if (item.name.empty())
      {
        rest::bad_request_(_s, "Name is required");
        return;
      }
      std::string id = items.create_(item);
      rest::created_(_s, id, item.to_json_());
    }
    catch (const std::exception& e)
    {
      rest::bad_request_(_s, e.what());
    }
  }, true);

  // PUT /api/items/ — Update item
  app.put_("/api/items", [](const http_q& _q, http_s& _s)
  {
    std::string id = rest::path_id_(_q.url_rest_());
    if (id.empty())
    {
      rest::bad_request_(_s, "Item ID required in path");
      return;
    }

    auto json = rest::parse_json_(_q);
    if (!json)
    {
      rest::bad_request_(_s, "Invalid JSON body");
      return;
    }

    // Check if item exists
    auto existing = items.read_(id);
    if (!existing)
    {
      rest::not_found_(_s, "Item not found");
      return;
    }

    try
    {
      // Merge with existing
      item_t item = *existing;
      if (json->contains("name")) item.name = (*json)["name"].get<std::string>();
      if (json->contains("description")) item.description = (*json)["description"].get<std::string>();
      if (json->contains("price")) item.price = (*json)["price"].get<double>();
      if (json->contains("active")) item.active = (*json)["active"].get<bool>();

      items.update_(id, item);
      nlohmann::json response = item.to_json_();
      response["id"] = id;
      rest::ok_(_s, response);
    }
    catch (const std::exception& e)
    {
      rest::bad_request_(_s, e.what());
    }
  }, true);

  // DELETE /api/items/ — Delete item
  app.delete_("/api/items", [](const http_q& _q, http_s& _s)
  {
    std::string id = rest::path_id_(_q.url_rest_());
    if (id.empty())
    {
      rest::bad_request_(_s, "Item ID required in path");
      return;
    }

    if (items.remove_(id))
    {
      rest::no_content_(_s);
    }
    else
    {
      rest::not_found_(_s, "Item not found");
    }
  }, true);

  // Seed some initial data
  items.create_(item_t("Widget", "A useful widget", 9.99));
  items.create_(item_t("Gadget", "An amazing gadget", 19.99));
  items.create_(item_t("Gizmo", "A mysterious gizmo", 29.99));

  // Setup and run
  app.listen_("0.0.0.0", port);
  app.signal_();

  std::cout << "REST API server listening on http://0.0.0.0:" << port << std::endl;
  std::cout << std::endl;
  std::cout << "Endpoints:" << std::endl;
  std::cout << "  GET    /api/health       — Health check" << std::endl;
  std::cout << "  GET    /api/items        — List all items" << std::endl;
  std::cout << "  GET    /api/items/{id}   — Get item by ID" << std::endl;
  std::cout << "  POST   /api/items        — Create item" << std::endl;
  std::cout << "  PUT    /api/items/{id}   — Update item" << std::endl;
  std::cout << "  DELETE /api/items/{id}   — Delete item" << std::endl;
  std::cout << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  curl http://localhost:" << port << "/api/items" << std::endl;
  std::cout << "  curl http://localhost:" << port << "/api/items/1" << std::endl;
  std::cout << "  curl -X POST -d '{\"name\":\"Test\",\"price\":5.99}' http://localhost:" << port << "/api/items" << std::endl;
  std::cout << std::endl;
  std::cout << "Press Ctrl+C to stop." << std::endl;

  app.serve_();

  std::cout << "Server stopped." << std::endl;
  return 0;
}

