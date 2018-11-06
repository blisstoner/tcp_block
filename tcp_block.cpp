#include <ifaddrs.h>
#include <libnet.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

const int ETHERNET_HEADER_LEN = 14;
const int IP_HEADER_LEN = 20;
const int TCP_HEADER_LEN = 20;
const int IP_ADDRESS_LEN = 4;
const int MAC_ADDRESS_LEN = 6;

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

int packet_to_tcp_hdr(const uint8_t *p, struct libnet_tcp_hdr *tcp_hdr) {
  tcp_hdr->th_sport = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  tcp_hdr->th_dport = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  tcp_hdr->th_seq = ntohs(*static_cast<uint32_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 4;
  tcp_hdr->th_ack = ntohs(*static_cast<uint32_t *>(
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

void tcp_block(pcap_t* handle){
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
    if(packet_to_tcp_hdr(p + (ip_hdr.ip_hl << 2), &tcp_hdr) != 0) continue;
    const uint8_t* tcp_data = p + (ip_hdr.ip_hl << 2) + (tcp_hdr.th_off << 2) + ETHERNET_HEADER_LEN;
    int data_len = len - (ip_hdr.ip_hl << 2) - (tcp_hdr.th_off << 2) - ETHERNET_HEADER_LEN;
    if()
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
  }
  forgy_arp_response_feedback(handle, sender_ip, target_ip, pair, my_ip,
                              my_mac);

  pcap_close(handle);
  return 0;
}
