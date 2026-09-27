// =============================================================================
// client_context.cpp — see client_context.h.
// =============================================================================
#include "client_context.h"

#include "crypto.h"

namespace p2p {

void ClientContext::storeGroupKey(const std::string& groupId,
                                  const std::string& keyHex) {
  std::vector<uint8_t> key = fromHex(keyHex);
  if (key.size() != kGroupKeyLen) return;  // malformed — ignore
  std::lock_guard<std::mutex> guard(m);
  groupKeys[groupId] = std::move(key);
}

std::vector<uint8_t> ClientContext::groupKey(const std::string& groupId) {
  std::lock_guard<std::mutex> guard(m);
  auto it = groupKeys.find(groupId);
  return it == groupKeys.end() ? std::vector<uint8_t>{} : it->second;
}

}  // namespace p2p
