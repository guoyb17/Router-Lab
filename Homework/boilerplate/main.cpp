#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern void getTable(std::vector<RoutingTableEntry*>& ans);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a,
                                     0x0103000a};

int main(int argc, char *argv[]) {
  // 0a. 初始化 HAL，打开调试信息
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes 创建若干条 /24 直连路由
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00FFFFFF, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,     // big endian, means direct
        .metric = 0       // small endian
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    // 获取当前时间，处理定时任务
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 30 * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      // 每 30s 做什么
      // 例如：超时？发 RIP Request/Response？
      printf("30s Timer\n");
      last_time = time;
    }

    // 轮询
    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // if (res > 0)
    // 1. 检查是否是合法的 IP 包，可以用你编写的 validateIPChecksum 函数，还需要一些额外的检查
    // 2. 检查目的地址，如果是路由器自己的 IP（或者是 RIP 的组播地址），进入 3a；否则进入 3b
    // 3a.1 检查是否是合法的 RIP 包，可以用你编写的 disassemble 函数检查并从中提取出数据
    // 3a.2 如果是 Response 包，就调用你编写的 query 和 update 函数进行查询和更新，
    //      注意此时的 RoutingTableEntry 可能要添加新的字段（如metric、timestamp），
    //      如果有路由更新的情况，可能需要构造出 RipPacket 结构体，调用你编写的 assemble 函数，
    //      再把 IP 和 UDP 头补充在前面，通过 HAL_SendIPPacket 把它发到别的网口上
    // 3a.3 如果是 Request 包，就遍历本地的路由表，构造出一个 RipPacket 结构体，
    //      然后调用你编写的 assemble 函数，另外再把 IP 和 UDP 头补充在前面，
    //      通过 HAL_SendIPPacket 发回询问的网口
    // 3b.1 此时目的 IP 地址不是路由器本身，则调用你编写的 query 函数查询，
    //      如果查到目的地址，如果是直连路由， nexthop 改为目的 IP 地址，
    //      用 HAL_ArpGetMacAddress 获取 nexthop 的 MAC 地址，如果找到了，
    //      就调用你编写的 forward 函数进行 TTL 和 Checksum 的更新，
    //      通过 HAL_SendIPPacket 发到指定的网口，
    //      在 TTL 减到 0 的时候建议构造一个 ICMP Time Exceeded 返回给发送者；
    //      如果没查到目的地址的路由，建议返回一个 ICMP Destination Network Unreachable；
    //      如果没查到下一跳的 MAC 地址，HAL 会自动发出 ARP 请求，在对方回复后，下次转发时就知道了

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr = (packet[12] << 24) + (packet[13] << 16) + (packet[14] << 8) + packet[15],
              dst_addr = (packet[16] << 24) + (packet[17] << 16) + (packet[18] << 8) + packet[19];
    uint16_t src_port = (packet[20] << 8) + packet[21];
    // TODO: extract src_addr and dst_addr from packet [x]
    // big endian

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    in_addr_t multicast_addr = 0xE0000009;
    if (memcmp(&dst_addr, &multicast_addr, sizeof(in_addr_t)) == 0) {
      dst_is_me = true;
    }
    // TODO: Handle rip multicast address(224.0.0.9)? [x]

    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          // TODO: fill resp [x]
          std::vector<RoutingTableEntry*> ans;
          getTable(ans);
          int k_total = ans.size() / RIP_MAX_ENTRY;
          for (int k = 0; k <= k_total; k++) {
            RipPacket resp;
            resp.command = rip.command;
            resp.numEntries = 0;
            for (int i = 0; (i < RIP_MAX_ENTRY) && (k * RIP_MAX_ENTRY + i < ans.size()); i++) {
              resp.entries[resp.numEntries].addr = ans[i]->addr;
              resp.entries[resp.numEntries].mask = (1 << (ans[i]->len + 1)) - 1;
              resp.entries[resp.numEntries].metric = ans[i]->metric;
              resp.entries[resp.numEntries].nexthop = ans[i]->nexthop;
              resp.numEntries++;
            }
            // assemble
            // IP
            output[0] = 0x45;
            output[1] = 0x0;
            // TODO: length of IP: output 2, 3 [x]
            output[4] = 0;
            output[5] = 0;
            output[6] = 0;
            output[7] = 0;
            output[8] = 0x1;
            // UDP
            output[9] = 0x21;
            // TODO: checksum of IP: output 10, 11 [x]
            output[12] = dst_addr >> 24;
            output[13] = (dst_addr >> 16) & 0xff;
            output[14] = (dst_addr >> 8) & 0xff;
            output[15] = dst_addr & 0xff;
            output[16] = src_addr >> 24;
            output[17] = (src_addr >> 16) & 0xff;
            output[18] = (src_addr >> 8) & 0xff;
            output[19] = src_addr & 0xff;
            // port = 520
            output[20] = 0x02;
            output[21] = 0x08;
            output[22] = src_port >> 8;
            output[23] = src_port & 0xff;
            // TODO: length of UDP: output 24, 25 [x]
            // TODO: checksum of UDP: output 26, 27 [x]
            // RIP
            uint32_t rip_len = assemble(&resp, &output[20 + 8]);

            uint16_t udp_len = rip_len + 8;
            output[24] = udp_len >> 8;
            output[25] = udp_len & 0xff;

            uint16_t ip_len = rip_len + 20 + 8;
            output[2] = ip_len >> 8;
            output[3] = ip_len & 0xff;

            // checksum calculation for ip and udp
            // if you don't want to calculate udp checksum, set it to zero
            output[26] = 0;
            output[27] = 0;
            uint16_t header_len = 20;
            uint32_t cnt = 0;
            for (uint16_t i = 0; i + 1 < header_len; i += 2) {
              uint16_t tmp = i == 10 ? 0 : packet[i];
              tmp = tmp << 8;
              tmp += i == 10 ? 0 : packet[i + 1];
              cnt += tmp;
              while (0xffff < cnt) {
                uint16_t tmps = cnt >> 16;
                cnt = (cnt & 0xffff) + tmps;
              }
            }
            cnt = ~cnt & 0xffff;
            output[10] = (cnt >> 8) & 0xff;
            output[11] = cnt & 0xff;
            // send it back
            HAL_SendIPPacket(if_index, output, ip_len, src_mac);
          }
        } else {
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update [ ]
          // triggered updates? ref. RFC2453 3.10.1
        }
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // TODO: you might want to check ttl=0 case [x]
          if (output[8] == 0) {
            output[20] = 11;
            output[21] = 0;
            // TODO: checksum of ICMP: output 22, 23 [x]
            uint16_t icmp_checksum = 11;
            icmp_checksum = ~icmp_checksum;
            output[22] = icmp_checksum >> 8;
            output[23] = icmp_checksum & 0xff;
            output[24] = 0;
            output[25] = 0;
            output[26] = 0;
            output[27] = 0;
            for (int j = 8; j < 64; j++) output[20 + j] = 0;
            res = 20 + 64;
          }
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found: ICMP Destination Network Unreachable
        // TODO: optionally you can send ICMP Host Unreachable [ ]
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
