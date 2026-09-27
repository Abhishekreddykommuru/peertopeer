// =============================================================================
// peer_protocol.h — the crypto shared by both ends of a peer connection.
//
// Before a single piece moves, downloader and seeder run a mutual
// challenge-response over the group transfer key Kg (32 random bytes minted
// at create_group, handed only to members by the tracker over encrypted
// session channels):
//
//   D -> S : PeerHello     [group, file, nonceD]
//   S -> D : PeerChallenge [nonceS, HMAC(Kg, "seeder"|nonceD|nonceS|group|file)]
//   D -> S : PeerProof     [        HMAC(Kg, "downloader"|nonceD|nonceS|group|file)]
//   S -> D : PeerOk        []
//   both   : channel key = KDF(HMAC(Kg, nonceD|nonceS), "peer-chan")
//            -> piece traffic AES-256-CTR encrypted
//
// Properties:
//   * only group members can DOWNLOAD pieces (seeder verifies the proof),
//   * only group members can SERVE pieces (downloader verifies first — you
//     cannot be tricked into fetching from an impostor, and piece SHA1s
//     from the tracker backstop content integrity anyway),
//   * nonces make every session's proofs and key fresh: recording one
//     session gives an eavesdropper nothing replayable.
// =============================================================================
#pragma once

#include <string>
#include <vector>

#include "crypto.h"

namespace p2p {

inline std::string peerProof(const std::vector<uint8_t>& groupKey,
                             const std::string& role,
                             const std::string& nonceD,
                             const std::string& nonceS,
                             const std::string& group,
                             const std::string& file) {
  std::string msg =
      role + "|" + nonceD + "|" + nonceS + "|" + group + "|" + file;
  return toHex(hmacSha1(groupKey.data(), groupKey.size(),
                        reinterpret_cast<const uint8_t*>(msg.data()),
                        msg.size()));
}

inline Key256 peerChannelKey(const std::vector<uint8_t>& groupKey,
                             const std::string& nonceD,
                             const std::string& nonceS) {
  std::string mix = nonceD + nonceS;
  Sha1Digest secret = hmacSha1(groupKey.data(), groupKey.size(),
                               reinterpret_cast<const uint8_t*>(mix.data()),
                               mix.size());
  return deriveKey256(secret.data(), secret.size(), "peer-chan");
}

}  // namespace p2p
