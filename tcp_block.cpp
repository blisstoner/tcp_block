#include <ifaddrs.h>
#include <libnet.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <algorithm>

const int ETHERNET_HEADER_LEN = 14;
const int IP_HEADER_LEN = 20;
const int TCP_HEADER_LEN = 20;
const int IP_ADDRESS_LEN = 4;
const int MAC_ADDRESS_LEN = 6;

void i2byte_s(uint8_t* b, uint16_t i){
  *(b++) = i >> 8;
  *b = i & 0xff;
}

void i2byte_l(uint8_t* b, uint32_t i){
  *(b++) = i >> 24;
  *(b++) = (i >> 16) & 0xff;
  *(b++) = (i >> 8) & 0xff;
  *b = i & 0xff;
}
void set_eth_hdr(struct libnet_ethernet_hdr* eth_hdr, uint8_t* ether_dhost,
                 uint8_t* ether_shost, uint16_t ether_type) {
  memcpy(eth_hdr->ether_dhost, ether_dhost, MAC_ADDRESS_LEN);
  memcpy(eth_hdr->ether_shost, ether_shost, MAC_ADDRESS_LEN);
  eth_hdr->ether_type = ether_type;
}
void eth_hdr_to_packet(uint8_t* packet, struct libnet_ethernet_hdr* eth_hdr) {
  memcpy(packet, eth_hdr->ether_dhost, MAC_ADDRESS_LEN);
  memcpy(packet + MAC_ADDRESS_LEN, eth_hdr->ether_shost, MAC_ADDRESS_LEN);
  packet[2 * MAC_ADDRESS_LEN] = eth_hdr->ether_type >> 8;
  packet[2 * MAC_ADDRESS_LEN + 1] = eth_hdr->ether_type & 0xff;
}
void packet_to_eth_hdr(const uint8_t* p, struct libnet_ethernet_hdr* eth_hdr) {
  for (int i = 0; i < MAC_ADDRESS_LEN; i++)
    eth_hdr->ether_dhost[i] = (uint8_t) * (p++);
  for (int i = 0; i < MAC_ADDRESS_LEN; i++)
    eth_hdr->ether_shost[i] = (uint8_t) * (p++);
  eth_hdr->ether_type = ntohs(
      *static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
}

int packet_to_ip_hdr(const uint8_t* p, struct libnet_ipv4_hdr* ip_hdr) {
  ip_hdr->ip_v = (uint8_t)((*p) >> 4);
  ip_hdr->ip_hl = (uint8_t)((*(p++) & 0xf));
  ip_hdr->ip_tos = (uint8_t) * (p++);
  ip_hdr->ip_len = ntohs(
      *static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  ip_hdr->ip_id = ntohs(
      *static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  ip_hdr->ip_off = ntohs(
      *static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  ip_hdr->ip_ttl = (uint8_t) * (p++);
  ip_hdr->ip_p = (uint8_t) * (p++);
  ip_hdr->ip_sum = ntohs(
      *static_cast<uint16_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 2;
  ip_hdr->ip_src.s_addr = ntohl(
      *static_cast<uint32_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 4;
  ip_hdr->ip_dst.s_addr = ntohl(
      *static_cast<uint32_t*>(static_cast<void*>((const_cast<uint8_t*>(p)))));
  p += 4;
  if (ip_hdr->ip_hl < 5) {
    printf("[!]wrong IHL value(%d) in IP header\n", ip_hdr->ip_hl);
    return -1;
  }
  if (ip_hdr->ip_hl > 5) {
    uint32_t option_len = (ip_hdr->ip_hl - 5) << 2;
    uint8_t ip_option[option_len];  // maybe it will use in someday..?
    for (int i = 0; i < option_len; i++) ip_option[i] = (uint8_t) * (p++);
  }
  return 0;
}

void ip_hdr_to_packet(uint8_t* p, libnet_ipv4_hdr* ip_hdr){
  *(p++) = (ip_hdr->ip_v << 4) | (ip_hdr->ip_hl);
  *(p++) = ip_hdr->ip_tos;
  i2byte_s(p, ip_hdr->ip_len); p += 2;
  i2byte_s(p, ip_hdr->ip_id); p += 2;
  i2byte_s(p, ip_hdr->ip_off); p += 2;
  *(p++) = ip_hdr->ip_ttl;
  *(p++) = ip_hdr->ip_p;
  i2byte_s(p, ip_hdr->ip_sum); p += 2;
  i2byte_l(p, ip_hdr->ip_src.s_addr); p += 4;
  i2byte_l(p, ip_hdr->ip_dst.s_addr);
}

int packet_to_tcp_hdr(const uint8_t *p, struct libnet_tcp_hdr *tcp_hdr) {
  tcp_hdr->th_sport = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  tcp_hdr->th_dport = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  tcp_hdr->th_seq = ntohl(*static_cast<uint32_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 4;
  tcp_hdr->th_ack = ntohl(*static_cast<uint32_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 4;
  tcp_hdr->th_off = (uint8_t)((*p) >> 4);
  tcp_hdr->th_x2 = (uint8_t)((*(p++)) & 0xf);
  tcp_hdr->th_flags = (uint8_t) * (p++);
  tcp_hdr->th_win = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  tcp_hdr->th_sum = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  tcp_hdr->th_urp = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  if (tcp_hdr->th_off < 5) {
    printf("[!]wrong tcp offset(%d)\n", tcp_hdr->th_off);
    return -1;
  }
  uint32_t option_len = (tcp_hdr->th_off - 5) << 2;
  uint8_t tcp_option[option_len];
  for (int i = 0; i < option_len; i++) tcp_option[i] = (uint8_t) * (p++);
  return 0;
}

void tcp_hdr_to_packet(uint8_t* p, struct libnet_tcp_hdr* tcp_hdr){
  i2byte_s(p,tcp_hdr->th_sport); p += 2;
  i2byte_s(p, tcp_hdr->th_dport); p += 2;
  i2byte_l(p, tcp_hdr->th_seq); p += 4;
  i2byte_l(p, tcp_hdr->th_ack); p += 4;
  *(p++) = (tcp_hdr->th_off << 4) | (tcp_hdr->th_x2);
  *(p++) = tcp_hdr->th_flags;
  i2byte_s(p, tcp_hdr->th_win); p += 2;
  i2byte_s(p, tcp_hdr->th_sum); p += 2;
  i2byte_s(p, tcp_hdr->th_urp); p += 2;  
}

int is_http(const uint8_t *data, uint32_t len) {
  if (len < 8) return 0;
  const char *http_method[6] = {"GET", "POST",   "HEAD",
                                "PUT", "DELETE", "OPTIONS"};
  uint32_t http_method_size[6] = {3, 4, 4, 3, 6, 7};
  int i = 0;
  while (i < 6) {
    if (memcmp(data, http_method[i], http_method_size[i]) == 0) return 1;
    i++;
  }
  return 0;
}

void tcp_block(pcap_t* handle){
  char* redir_msg = "HTTP/1.1 302 Redirect\r\nLocation: http://blog.encrypted.gg\r\n\r\n";
  uint32_t redir_msg_len = strlen(redir_msg);
  while (1) {
    struct pcap_pkthdr* header;
    const uint8_t* p;
    int res = pcap_next_ex(handle, &header, &p);
    if (res == 0) continue;
    if (res == -1 || res == -2) {
      printf("[!] An error has been occured. Terminated\n");
      return;
    }
    int len = header->caplen;
    libnet_ethernet_hdr eth_hdr;
    if (len < ETHERNET_HEADER_LEN) continue;
    packet_to_eth_hdr(p, &eth_hdr);
    if (eth_hdr.ether_type != ETHERTYPE_IP) continue;
    libnet_ipv4_hdr ip_hdr;
    if(len < ETHERNET_HEADER_LEN+IP_HEADER_LEN) continue;
    if(packet_to_ip_hdr(p+ETHERNET_HEADER_LEN,&ip_hdr) != 0) continue;
    libnet_tcp_hdr tcp_hdr;
    if (ip_hdr.ip_p != IPPROTO_TCP) continue;
    if(packet_to_tcp_hdr(p + ETHERNET_HEADER_LEN + (ip_hdr.ip_hl << 2), &tcp_hdr) != 0) continue;
    const uint8_t* tcp_data = p + (ip_hdr.ip_hl << 2) + (tcp_hdr.th_off << 2) + ETHERNET_HEADER_LEN;
    uint32_t data_len = len - (ip_hdr.ip_hl << 2) - (tcp_hdr.th_off << 2) - ETHERNET_HEADER_LEN;
    libnet_ethernet_hdr eth_hdr_back;
    memcpy(eth_hdr_back.ether_dhost, eth_hdr.ether_shost, MAC_ADDRESS_LEN);
    memcpy(eth_hdr_back.ether_shost, eth_hdr.ether_dhost, MAC_ADDRESS_LEN);
    eth_hdr_back.ether_type = eth_hdr.ether_type;
    libnet_ipv4_hdr ip_hdr_back;
    memcpy(&ip_hdr_back, &ip_hdr, sizeof(libnet_ipv4_hdr));
    std::swap(ip_hdr_back.ip_src, ip_hdr_back.ip_dst);
    libnet_tcp_hdr tcp_hdr_back;
    memcpy(&tcp_hdr_back, &tcp_hdr, sizeof(libnet_tcp_hdr));
    std::swap(tcp_hdr_back.th_sport, tcp_hdr_back.th_dport);
    std::swap(tcp_hdr_back.th_ack, tcp_hdr_back.th_seq);
    tcp_hdr_back.th_off = 5;
    tcp_hdr_back.th_ack += data_len;
    if(is_http(tcp_data, data_len)){ // backward FIN
      uint8_t fin_msg[ETHERNET_HEADER_LEN+IP_HEADER_LEN+TCP_HEADER_LEN+redir_msg_len];
      ip_hdr_back.ip_len = IP_HEADER_LEN+TCP_HEADER_LEN+redir_msg_len;
      tcp_hdr_back.th_flags = 0b10001; // ACK, FIN
      eth_hdr_to_packet(fin_msg, &eth_hdr_back);
      ip_hdr_to_packet(fin_msg+ETHERNET_HEADER_LEN, &ip_hdr_back);
      tcp_hdr_to_packet(fin_msg+ETHERNET_HEADER_LEN+IP_HEADER_LEN, &tcp_hdr_back);
      memcpy(fin_msg+ ETHERNET_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN,redir_msg, redir_msg_len);
      pcap_sendpacket(handle, fin_msg, ETHERNET_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN+redir_msg_len);

      //      uint8_t tmp[1500] = {};
      //      tcp_hdr_to_packet(tmp, &tcp_hdr);
      //      libnet_tcp_hdr tmp_tcp_hdr;
      //      memcpy(&tcp_hdr, &tmp_tcp_hdr, sizeof(libnet_tcp_hdr));

    } else {  // backward RST
      uint8_t rst_msg[ETHERNET_HEADER_LEN+IP_HEADER_LEN+TCP_HEADER_LEN];
      ip_hdr_back.ip_len = IP_HEADER_LEN+TCP_HEADER_LEN;
      tcp_hdr_back.th_flags = 0b10100; // ACK, RST
      eth_hdr_to_packet(rst_msg, &eth_hdr_back);
      ip_hdr_to_packet(rst_msg+ETHERNET_HEADER_LEN, &ip_hdr_back);
      tcp_hdr_to_packet(rst_msg+ETHERNET_HEADER_LEN+IP_HEADER_LEN, &tcp_hdr_back);
      pcap_sendpacket(handle, rst_msg, ETHERNET_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN);    
    }
    // forward RST
    ip_hdr.ip_len = IP_HEADER_LEN + TCP_HEADER_LEN;
    tcp_hdr.th_off = 5;
    tcp_hdr.th_flags = 0b10100; // ACK, RST
    tcp_hdr.th_seq += data_len;
    uint8_t rst_msg[ETHERNET_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN];
    eth_hdr_to_packet(rst_msg, &eth_hdr_back);
    ip_hdr_to_packet(rst_msg+ETHERNET_HEADER_LEN, &ip_hdr);
    tcp_hdr_to_packet(rst_msg+ETHERNET_HEADER_LEN+IP_HEADER_LEN, &tcp_hdr);
    pcap_sendpacket(handle, rst_msg, ETHERNET_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN);    
  }
}

void usage() {
  printf("syntax: tcp_block <interface>");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

  // pcap_t *handle = pcap_open_offline("20180927_arp.pcap", errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  tcp_block(handle);
  pcap_close(handle);
  return 0;
}
