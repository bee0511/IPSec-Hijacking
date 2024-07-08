#include "session.h"

#include <arpa/inet.h>  // for inet_addr and htons
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <numeric>
#include <span>
#include <utility>

// #define DUMP_PACKET 1
// #define SHOW_ENCAPSULATE 1

extern bool running;
using namespace std;
Session::Session(const std::string& iface, ESPConfig&& cfg)
    : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};
  addr_ll.sll_family = AF_PACKET;
  addr_ll.sll_protocol = htons(ETH_P_ALL);
  addr_ll.sll_ifindex = if_nametoindex(iface.c_str());
  checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), sizeof(sockaddr_ll)), "Bind failed");
}

Session::~Session() {
  shutdown(sock, SHUT_RDWR);
  close(sock);
}

void Session::run() {
  epoll_event triggeredEvent[2];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sock;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

  std::string secret;
  std::cout << "You can start to send the message...\n";
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        std::getline(std::cin, secret);
      } else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) encapsulate("");
        if (!secret.empty() && state.recvPacket) {
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}

void Session::dissect(ssize_t rdcnt) {
  auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote
  dissectIPv4(payload);
}

void Session::dissectIPv4(std::span<uint8_t> buffer) {
  if (buffer.size() < sizeof(iphdr)) {
    std::cerr << "Packet too short for IP header\n";
    return;
  }

  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());

  // Set the IP source and destination address
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(hdr.saddr), src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(hdr.daddr), dst_ip, INET_ADDRSTRLEN);

  // Set the protocol number and payload length
  auto pro = hdr.protocol;
  auto hdrlen = hdr.ihl * 4;
  auto plen = ntohs(hdr.tot_len) - hdrlen;

  std::map<int, std::string> protocol_names = {
      {IPPROTO_IP, "IP"},   {IPPROTO_ICMP, "ICMP"}, {IPPROTO_TCP, "TCP"},
      {IPPROTO_UDP, "UDP"}, {IPPROTO_IPV6, "IPv6"}, {IPPROTO_ESP, "ESP"},
  };

  // Set `recvPacket = true` if we are receiving packet from remote
  if (strcmp(dst_ip, config.local.c_str()) == 0) {
    state.recvPacket = true;
#if DUMP_PACKET
    // Dump IP packet
    std::cout << "-------------dissectIPv4--------------\n";
    std::cout << "Source IP: " << src_ip << "\n";
    std::cout << "Destination IP: " << dst_ip << "\n";
    std::cout << "Protocol: " << protocol_names[pro] << "\n";
    std::cout << "Payload Length: " << plen << "\n";
#endif
  } else {
    state.recvPacket = false;
    // Track current IP id
    state.ipId = hdr.id;
  }

  auto payload = buffer.last(buffer.size() - hdrlen);
  if (hdr.protocol == IPPROTO_ESP) dissectESP(payload);
}

void Session::dissectESP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  int hashLength = config.aalg->hashLength();
  // Strip hash
  buffer = buffer.subspan(sizeof(ESPHeader), buffer.size() - sizeof(ESPHeader) - hashLength);
  std::vector<uint8_t> data;
  // Decrypt payload
  if (!config.ealg->empty()) {
    data = config.ealg->decrypt(buffer);
    buffer = std::span{data.data(), data.size()};
  }
  // TODO:
  // Track ESP sequence number
  if (state.recvPacket == false) {
    state.espseq = ntohl(hdr.seq);
  }
  // Extract the ESP trailer from the decrypted data
  auto trailer_buffer = buffer.last(sizeof(ESPTrailer));
  // Remove the ESP trailer from the buffer
  // The size of the buffer is reduced by the size of the ESPTrailer and the padding length
  // The padding length is stored in the first byte of the trailer_buffer and is cast to int for the subtraction operation
  // Why cast uint8_t to int? Because the uint8_t is unsigned, the subtraction may overflow.
  buffer = buffer.first(buffer.size() - sizeof(ESPTrailer) - (int)trailer_buffer[0]);

// Dump ESP packet
#if DUMP_PACKET
  std::cout << "-------------dissectESP--------------\n";
  std::cout << "SPI: " << ntohl(hdr.spi) << "\n";
  std::cout << "Sequence Number: " << ntohl(hdr.seq) << "\n";
  std::cout << "Padding Length: " << (int)trailer_buffer[0] << "\n";
  std::cout << "Next Header: " << (int)trailer_buffer[1] << "\n";
  std::cout << "Payload Length: " << buffer.size() << "\n";
#endif

  // Call dissectTCP(payload) if next protocol is TCP
  if ((int)trailer_buffer[1] == IPPROTO_TCP) dissectTCP(buffer);
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);

// Dump TCP packet
#if DUMP_PACKET
  std::cout << "-------------dissectTCP--------------\n";
  std::cout << "Source Port: " << ntohs(hdr.source) << "\n";
  std::cout << "Destination Port: " << ntohs(hdr.dest) << "\n";
  std::cout << "Sequence Number: " << ntohl(hdr.seq) << "\n";
  std::cout << "Acknowledge Number: " << ntohl(hdr.ack_seq) << "\n";
  std::cout << "Data Offset: " << hdr.doff << "\n";
  std::cout << "Window: " << ntohs(hdr.window) << "\n";
  std::cout << "Checksum: " << ntohs(hdr.check) << "\n";
  std::cout << "Urgent Pointer: " << ntohs(hdr.urg_ptr) << "\n";
  std::cout << "Payload Length: " << payload.size() << "\n";
  std::cout << "-------------------------------------\n";
#endif
  // Track tcp parameters
  state.tcpseq = ntohl(hdr.seq);
  state.tcpseq += payload.size();
  state.tcpackseq = ntohl(hdr.ack_seq);
  state.srcPort = ntohs(hdr.source);
  state.dstPort = ntohs(hdr.dest);

  // Is ACK message?
  if (payload.empty()) return;
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
    state.sendAck = true;
    state.espseq++;
    state.ipId++;
  }
}

void Session::encapsulate(const std::string& payload) {
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}

uint16_t Session::cal_ipv4_cksm(struct iphdr iphdr) {
  uint16_t* iphdr_ptr = reinterpret_cast<uint16_t*>(&iphdr);
  size_t hdr_len = iphdr.ihl * 4;
  uint32_t sum = 0;

  // Calculate the checksum for the IP header
  while (hdr_len > 1) {
    sum += *iphdr_ptr++;
    hdr_len -= 2;
  }

  // Deal with odd header len
  if (hdr_len) {
    sum += (*iphdr_ptr) & htons(0xFF00);
  }

  // If the sum is greater than 16 bits, add the carry
  if (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return ~sum;
}

int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO: Fill IP header
  hdr.version = 4;
  hdr.ihl = 5;
  hdr.ttl = 64;
  hdr.id = ntohs(ntohs(state.ipId) + 1);
  hdr.protocol = IPPROTO_ESP;
  hdr.frag_off = htons(0x4000);
  hdr.saddr = inet_addr(config.local.c_str());
  hdr.daddr = inet_addr(config.remote.c_str());

  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));

  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);
  hdr.tot_len = htons(payloadLength);
  hdr.check = 0;  // Set hdr.check to 0 before calculating checksum
  hdr.check = cal_ipv4_cksm(hdr);

#if SHOW_ENCAPSULATE
  std::cout << "-------------encapsulateIPv4--------------\n";
  std::cout << "Source IP: " << ipToString(hdr.saddr) << "\n";
  std::cout << "Destination IP: " << ipToString(hdr.daddr) << "\n";
  std::cout << "Protocol: " << hdr.protocol << "\n";
  std::cout << "Payload Length: " << payloadLength << "\n";
  std::cout << "-------------------------------------\n";
#endif

  return payloadLength;
}

int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  // TODO: Fill ESP header
  hdr.spi = htonl(config.spi);
  hdr.seq = htonl(state.espseq + 1);
  int payloadLength = encapsulateTCP(nextBuffer, payload);

  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);
  // Calculate padding size
  uint8_t padLength = (4 - ((payloadLength + sizeof(ESPTrailer)) % 4)) % 4;

  // Fill the padding with a monotonically increasing sequence starting from 1
  std::iota(endBuffer.begin(), endBuffer.begin() + padLength, 1);

  // Update the payload length
  payloadLength += padLength;

  // ESP trailer
  endBuffer[padLength] = padLength;
  endBuffer[padLength + 1] = IPPROTO_TCP;
  payloadLength += sizeof(ESPTrailer);

  // Do encryption
  if (!config.ealg->empty()) {
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    std::copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength = result.size();
  }
  payloadLength += sizeof(ESPHeader);

  if (!config.aalg->empty()) {
    // TODO: Fill in config.aalg->hash()'s parameter
    // parameter: ESP header + ESP payload (TCP header + TCP payload) + ESP trailer (padding and next header)
    auto result = config.aalg->hash(buffer.first(payloadLength));
    std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    payloadLength += result.size();
  }

#if SHOW_ENCAPSULATE
  std::cout << "-------------encapsulateESP--------------\n";
  std::cout << "SPI: " << ntohl(hdr.spi) << "\n";
  std::cout << "Sequence Number: " << ntohl(hdr.seq) << "\n";
  std::cout << "Padding Length: " << (int)endBuffer[padLength] << "\n";
  std::cout << "Next Header: " << (int)endBuffer[padLength + 1] << "\n";
  std::cout << "Payload Length: " << payloadLength << "\n";
#endif

  return payloadLength;
}

uint16_t Session::cal_tcp_cksm(struct tcphdr tcphdr, const std::string& payload) {
  // Calculate the TCP pseudo-header checksum
  // Pseudo Header: Source IP + Destination IP + Protocol + L4 Header Length
  uint32_t ip_src = inet_addr(config.local.c_str());
  uint32_t ip_dst = inet_addr(config.remote.c_str());
  uint16_t tcphdr_len = tcphdr.th_off * 4;
  uint16_t tcp_len = tcphdr_len + payload.size();
  uint32_t sum = 0;

  sum += (ip_src >> 16) & 0xFFFF;  // High 16 bits of source IP
  sum += ip_src & 0xFFFF;          // Low 16 bits of source IP
  sum += (ip_dst >> 16) & 0xFFFF;  // High 16 bits of destination IP
  sum += ip_dst & 0xFFFF;          // Low 16 bits of destination IP
  sum += htons(IPPROTO_TCP);
  sum += htons(tcp_len);

  // Allocate memory of size equal to the TCP header length plus the payload size
  uint8_t* buf
      = reinterpret_cast<uint8_t*>(malloc((tcphdr_len + payload.size()) * sizeof(uint8_t)));

  // Copy the TCP header into the allocated buffer
  memcpy(buf, &tcphdr, tcphdr_len);

  // Copy the payload into the buffer, right after the TCP header
  memcpy(buf + tcphdr_len, payload.c_str(), payload.size());

  // Cast the buffer to a uint16_t pointer for subsequent checksum calculation
  uint16_t* pl_ptr = reinterpret_cast<uint16_t*>(buf);

  // Calculate the checksum for the TCP header and payload
  while (tcp_len > 1) {
    sum += *pl_ptr++;
    tcp_len -= 2;
  }

  // Deal with odd header len
  if (tcp_len) {
    sum += (*pl_ptr) & htons(0xFF00);
  }

  // If the sum is greater than 16 bits, add the carry
  if (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  // Take the one's complement of the sum to get the final checksum
  return ~sum;
}

int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  if (!payload.empty()) hdr.psh = 1;
  // TODO: Fill TCP header
  hdr.ack = 1;
  hdr.doff = 5;
  hdr.dest = htons(state.srcPort);
  hdr.source = htons(state.dstPort);
  hdr.ack_seq = htonl(state.tcpseq);
  hdr.seq = htonl(state.tcpackseq);

  hdr.window = htons(502);
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }
  // Update TCP sequence number
  state.tcpseq += payload.size();

  payloadLength += sizeof(tcphdr);

  // Compute checksum
  hdr.check = 0;  // Set hdr.check to 0 before calculating checksum
  hdr.check = cal_tcp_cksm(hdr, payload);

#if SHOW_ENCAPSULATE
  std::cout << "-------------encapsulateTCP--------------\n";
  std::cout << "Source Port: " << ntohs(hdr.source) << "\n";
  std::cout << "Destination Port: " << ntohs(hdr.dest) << "\n";
  std::cout << "Sequence Number: " << ntohl(hdr.seq) << "\n";
  std::cout << "Acknowledge Number: " << ntohl(hdr.ack_seq) << "\n";
  std::cout << "Data Offset: " << hdr.doff << "\n";
  std::cout << "Window: " << ntohs(hdr.window) << "\n";
  std::cout << "Checksum: " << ntohs(hdr.check) << "\n";
  std::cout << "Urgent Pointer: " << ntohs(hdr.urg_ptr) << "\n";
  std::cout << "Payload Length: " << payloadLength << "\n";
  std::cout << "Payload Content: " << payload << "\n";
#endif

  return payloadLength;
}
