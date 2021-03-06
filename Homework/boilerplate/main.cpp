#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <iostream>
// #define DISPLAY_MULTICAST
// #define DISPLAY_REQUEST
// #define DISPLAY_RESPONSE
// #define DISPLAY_UPDATE
// #define GROUP_DEBUG
#ifdef GROUP_DEBUG
uint64_t frame_cnt;
#endif

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t* metric);
extern void getTable(std::vector<RoutingTableEntry*>& ans);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
#define METRIC_COST 1
#define METRIC_INF 16
in_addr_t MULTICAST_IP = 0x090000E0;
macaddr_t MULTICAST_MAC = { 0x09, 0x00, 0x00, 0x5E, 0x00, 0x01 };
#define TIMEOUT 180
#define GARBAGE_COLLECTION 120

uint8_t packet[2048];
uint8_t output[2048];
// 0: 192.168.3.2 // ori: 10.0.0.1
// 1: 192.168.4.1 // ori: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a,
                                     0x0103000a}; // ori: 0x0100000a, 0x0101000a, 0x0102000a, 0x0103000a

int main(int argc, char *argv[]) {
  // 0a. 初始化 HAL，打开调试信息
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

#ifdef GROUP_DEBUG
  frame_cnt = 0;
#endif

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
        .nexthop = 0,     // big endian, 0 means direct
        .metric = 1,      // small endian
        .timestamp = HAL_GetTicks()
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    // 获取当前时间，处理定时任务
    uint64_t time = HAL_GetTicks();
    // when testing, you can change 30s to 5s
    if (time > last_time + 30 * 1000) {
      // TODO: send complete routing table to every interface [x]
      // ref. RFC2453 Section 3.8
      // TODO: split horizon [x]
      std::vector<RoutingTableEntry*> ans;
      getTable(ans);
      int k_total = ans.size() / RIP_MAX_ENTRY;
      // send complete routing table to every interface
      for (uint32_t if_index = 0; if_index < N_IFACE_ON_BOARD; if_index++) {
        for (int k = 0; k <= k_total; k++) {
          RipPacket resp;
          resp.command = 2;
          resp.numEntries = 0;
          for (int i = 0; (i < RIP_MAX_ENTRY) && (k * RIP_MAX_ENTRY + i < ans.size()); i++) {
            resp.entries[resp.numEntries].addr = ans[i]->addr;
            resp.entries[resp.numEntries].mask = (1 << ans[i]->len) - 1;
            resp.entries[resp.numEntries].metric =
            ((ans[i]->metric & 0xff) << 24) + (((ans[i]->metric >> 8) & 0xff) << 16)
            + (((ans[i]->metric >> 16) & 0xff) << 8) + (ans[i]->metric >> 24);
            resp.entries[resp.numEntries].nexthop = ans[i]->nexthop; // ori: ans[i]->nexthop
            resp.numEntries++;
          }
          // assemble
          // IP
          output[0] = 0x45;
          output[1] = 0x0;
          output[4] = 0;
          output[5] = 0;
          output[6] = 0;
          output[7] = 0;
          output[8] = 0x1;
          // UDP
          output[9] = 0x11;
          output[12] = addrs[if_index] & 0xff;
          output[13] = (addrs[if_index] >> 8) & 0xff;
          output[14] = (addrs[if_index] >> 16) & 0xff;
          output[15] = addrs[if_index] >> 24;
          output[16] = MULTICAST_IP & 0xff;
          output[17] = (MULTICAST_IP >> 8) & 0xff;
          output[18] = (MULTICAST_IP >> 16) & 0xff;
          output[19] = MULTICAST_IP >> 24;
          // port = 520
          output[20] = 0x02;
          output[21] = 0x08;
          output[22] = 0x02; // TODO: ???
          output[23] = 0x08;
          // RIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);
          // printf("rip_len = %x\n", rip_len);

          uint16_t udp_len = rip_len + 8;
          // printf("udp_len = %x\n", udp_len);
          output[24] = udp_len >> 8;
          output[25] = udp_len & 0xff;

          uint16_t ip_len = rip_len + 20 + 8;
          // printf("ip_len = %x\n", ip_len);
          output[2] = ip_len >> 8;
          output[3] = ip_len & 0xff;

          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          output[26] = 0;
          output[27] = 0;
          uint16_t header_len = 20;
          uint32_t cnt = 0;
          output[10] = 0;
          output[11] = 0;
          for (uint16_t i = 0; i + 1 < header_len; i += 2) {
            uint16_t tmp = i == 10 ? 0 : output[i];
            tmp = tmp << 8;
            tmp += i == 10 ? 0 : output[i + 1];
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
#ifdef DISPLAY_MULTICAST
          std::cout << "checksum = 0x" << std::ios::hex << (cnt & 0xffff) << std::ios::dec
          << ", it's " << (validateIPChecksum(output, ip_len) ? "true." : "false.") << std::endl;
          std::cout << "Sending response of multicast: if_index: " << if_index << std::endl;
          for (int k = 0; k < resp.numEntries; k++) {
            RipEntry re = resp.entries[k];
            std::cout << (re.addr & 0xff) << '.' << ((re.addr >> 8) & 0xff) << '.'
            << ((re.addr >> 16) & 0xff) << '.' << ((re.addr >> 24) & 0xff) << ' '
            << (re.mask & 0xff) << '.' << ((re.mask >> 8) & 0xff) << '.'
            << ((re.mask >> 16) & 0xff) << '.' << ((re.mask >> 24) & 0xff) << ' '
            << " metric = " << (re.metric >> 24)
            + (((re.metric >> 16) & 0xff) << 8)
            + (((re.metric >> 8) & 0xff) << 16)
            + ((re.metric & 0xff) << 24)
            << " nexthop = " << (re.nexthop & 0xff) << '.' << ((re.nexthop >> 8) & 0xff) << '.'
            << ((re.nexthop >> 16) & 0xff) << '.' << ((re.nexthop >> 24) & 0xff) << std::endl;
          }
#endif
          HAL_SendIPPacket(if_index, output, ip_len, MULTICAST_MAC);
        }
      }
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      // 每 30s 做什么
      // for (RoutingTableEntry* rte : ans) {
      //   if (time > rte->timestamp + (TIMEOUT + GARBAGE_COLLECTION) * 1000) {
      //     update(false, *rte);
      //   }
      //   else if (time > rte->timestamp + TIMEOUT * 1000) {
      //     if (rte->metric != METRIC_INF) {
      //       rte->metric = METRIC_INF;
      //       update(true, *rte);
      //     }
      //   }
      // }
      // 例如：超时？发 RIP Request/Response？
      printf("30s Timer\n");
      for (RoutingTableEntry* i : ans) {
        std::cout << (i->addr & 0xff) << '.' << ((i->addr >> 8) & 0xff) << '.'
        << ((i->addr >> 16) & 0xff) << '.' << ((i->addr >> 24) & 0xff) << '/' << i->len
        << " dev " << i->if_index << " proto Router-Lab"
        // << " metric " << i->metric
        << std::endl;
      }
      // TODO: print complete routing table to stdout/stderr [x]
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
    in_addr_t src_addr = (packet[15] << 24) + (packet[14] << 16) + (packet[13] << 8) + packet[12],
              dst_addr = (packet[19] << 24) + (packet[18] << 16) + (packet[17] << 8) + packet[16];
    uint16_t src_port = (packet[21] << 8) + packet[20];
    // TODO: extract src_addr and dst_addr from packet (big endian) [x]
    // big endian

#ifdef GROUP_DEBUG
    std::cout << "Received packet: Frame #" << frame_cnt++ << ", \nsrc: "
    << (src_addr & 0xff) << '.' << ((src_addr >> 8) & 0xff) << '.'
    << ((src_addr >> 16) & 0xff) << '.' << ((src_addr >> 24) & 0xff) << ", dst: "
    << (dst_addr & 0xff) << '.' << ((dst_addr >> 8) & 0xff) << '.'
    << ((dst_addr >> 16) & 0xff) << '.' << ((dst_addr >> 24) & 0xff) << std::endl;
#endif

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    if (memcmp(&dst_addr, &MULTICAST_IP, sizeof(in_addr_t)) == 0) {
      dst_is_me = true;
    }
    // TODO: Handle rip multicast address(224.0.0.9) [x]
#ifdef GROUP_DEBUG
    std::cout << "dst_is_me = " << (dst_is_me ? "true" : "false") << std::endl;
#endif

    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // std::cout << "Got a request..." << std::endl;
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          // TODO: fill resp [x]
          // TODO: split horizon [x]
#ifdef GROUP_DEBUG
          std::cout << "This is a RIP request." << std::endl;
#endif
          std::vector<RoutingTableEntry*> ans;
          getTable(ans);
          int k_total = ans.size() / RIP_MAX_ENTRY;
          for (int k = 0; k <= k_total; k++) {
            // TODO: fill resp [x]
            RipPacket resp;
            resp.command = 2;
            resp.numEntries = 0;
            for (int i = 0; (i < RIP_MAX_ENTRY) && (k * RIP_MAX_ENTRY + i < ans.size())
            && ans[i]->if_index != if_index; i++) {
              resp.entries[resp.numEntries].addr = ans[i]->addr;
              resp.entries[resp.numEntries].mask = (1 << ans[i]->len) - 1;
              resp.entries[resp.numEntries].metric =
              ((ans[i]->metric & 0xff) << 24) + (((ans[i]->metric >> 8) & 0xff) << 16)
              + (((ans[i]->metric >> 16) & 0xff) << 8) + (ans[i]->metric >> 24);
              resp.entries[resp.numEntries].nexthop = ans[i]->nexthop;
              resp.numEntries++;
            }
            // assemble
            // IP
            // TODO: fill IP headers [x]
            output[0] = 0x45;
            output[1] = 0x0;
            // TODO: length of IP: output 2, 3 [x]
            output[4] = 0;
            output[5] = 0;
            output[6] = 0;
            output[7] = 0;
            output[8] = 0x1;
            // UDP
            output[9] = 0x11;
            // TODO: checksum of IP: output 10, 11 [x]
            output[12] = dst_addr & 0xff;
            output[13] = (dst_addr >> 8) & 0xff;
            output[14] = (dst_addr >> 16) & 0xff;
            output[15] = dst_addr >> 24;
            output[16] = src_addr & 0xff;
            output[17] = (src_addr >> 8) & 0xff;
            output[18] = (src_addr >> 16) & 0xff;
            output[19] = src_addr >> 24;
            // port = 520
            // TODO: fill UDP headers [x]
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
            output[10] = 0;
            output[11] = 0;
            for (uint16_t i = 0; i + 1 < header_len; i += 2) {
              uint16_t tmp = i == 10 ? 0 : output[i];
              tmp = tmp << 8;
              tmp += i == 10 ? 0 : output[i + 1];
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
#ifdef DISPLAY_REQUEST
            std::cout << "checksum = 0x" << std::ios::hex << (cnt & 0xffff) << std::ios::dec
            << ", it's " << (validateIPChecksum(output, ip_len) ? "true." : "false.") << std::endl;
            std::cout << "Sending response of request: if_index: " << if_index << std::endl;
            for (int k = 0; k < resp.numEntries; k++) {
              RipEntry re = resp.entries[k];
              std::cout << (re.addr & 0xff) << '.' << ((re.addr >> 8) & 0xff) << '.'
              << ((re.addr >> 16) & 0xff) << '.' << ((re.addr >> 24) & 0xff) << ' '
              << (re.mask & 0xff) << '.' << ((re.mask >> 8) & 0xff) << '.'
              << ((re.mask >> 16) & 0xff) << '.' << ((re.mask >> 24) & 0xff) << ' '
              << " metric = " << (re.metric >> 24)
              + (((re.metric >> 16) & 0xff) << 8)
              + (((re.metric >> 8) & 0xff) << 16)
              + ((re.metric & 0xff) << 24)
              << " nexthop = " << (re.nexthop & 0xff) << '.' << ((re.nexthop >> 8) & 0xff) << '.'
              << ((re.nexthop >> 16) & 0xff) << '.' << ((re.nexthop >> 24) & 0xff) << std::endl;
            }
#endif
            HAL_SendIPPacket(if_index, output, ip_len, src_mac);
          }
        } else {
#ifdef GROUP_DEBUG
          std::cout << "This is a RIP response." << std::endl;
#endif
#ifdef DISPLAY_RESPONSE
          std::cout << "Got a response from "
          << (src_addr & 0xff) << '.' << ((src_addr >> 8) & 0xff) << '.'
          << ((src_addr >> 16) & 0xff) << '.' << ((src_addr >> 24) & 0xff) << std::endl;
          for (int k = 0; k < rip.numEntries; k++) {
            RipEntry re = rip.entries[k];
            std::cout << (re.addr & 0xff) << '.' << ((re.addr >> 8) & 0xff) << '.'
            << ((re.addr >> 16) & 0xff) << '.' << ((re.addr >> 24) & 0xff) << ' '
            << (re.mask & 0xff) << '.' << ((re.mask >> 8) & 0xff) << '.'
            << ((re.mask >> 16) & 0xff) << '.' << ((re.mask >> 24) & 0xff) << ' '
            << " metric = " << (re.metric >> 24)
            + (((re.metric >> 16) & 0xff) << 8)
            + (((re.metric >> 8) & 0xff) << 16)
            + ((re.metric & 0xff) << 24)
            << " nexthop = " << (re.nexthop & 0xff) << '.' << ((re.nexthop >> 8) & 0xff) << '.'
            << ((re.nexthop >> 16) & 0xff) << '.' << ((re.nexthop >> 24) & 0xff) << std::endl;
          }
#endif
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = MIN (metric + cost, infinity)
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry? metric, timestamp
          // TODO: update routing table [x]
          // HINT: what is missing from RoutingTableEntry?
          // you might want to use `query` and `update` but beware of the difference between exact match and longest prefix match
          RipPacket update_rip;
          update_rip.command = 2;
          update_rip.numEntries = 0;
          // TODO: use query and update [x]
          for (uint32_t i = 0; i < rip.numEntries; i++) {
            uint32_t new_metric = (rip.entries[i].metric >> 24)
            + (((rip.entries[i].metric >> 16) & 0xff) << 8)
            + (((rip.entries[i].metric >> 8) & 0xff) << 16)
            + ((rip.entries[i].metric & 0xff) << 24);
            if (!((1 <= new_metric && new_metric <= METRIC_INF))) {
#ifdef GROUP_DEBUG
              std::cout << "Changed to little endian, rip.entries[i].metric = " << new_metric << ", which is invalid!" << std::endl;
#endif
              continue;
            }
            rip.entries[i].nexthop = src_addr;
            if (new_metric >= METRIC_INF) new_metric = METRIC_INF;
            else new_metric += METRIC_COST;
            uint32_t found_nexthop, found_if_index, found_metric;
            if (query(rip.entries[i].addr, &found_nexthop, &found_if_index, &found_metric)) {
              // TODO: reset timer [x]
#ifdef DISPLAY_UPDATE
              std::cout << "Found: nexthop = " << (found_nexthop & 0xff) << '.'
              << ((found_nexthop >> 8) & 0xff) << '.' << ((found_nexthop >> 16) & 0xff)
              << '.' << ((found_nexthop >> 24) & 0xff)
              << ", if_index = " << found_if_index
              << ", metric = " << found_metric << std::endl;
#endif
              if (found_nexthop == rip.entries[i].nexthop && new_metric != METRIC_INF) {
                RoutingTableEntry new_entry;
                new_entry.addr = rip.entries[i].addr;
                new_entry.if_index = if_index;
                new_entry.metric = new_metric;
                new_entry.nexthop = found_nexthop;
                new_entry.timestamp = HAL_GetTicks();
                for (new_entry.len = 0; new_entry.len < 32; new_entry.len++) {
                  if (((1 << new_entry.len) & rip.entries[i].mask) == 0) break;
                }
                update(new_metric != METRIC_INF, new_entry); // directly delete if INF
                if (new_metric != METRIC_INF) {
                  RipEntry tmp;
                  tmp.addr = new_entry.addr;
                  tmp.mask = rip.entries[i].mask;
                  tmp.metric = (new_metric >> 24)
                  + (((new_metric >> 16) & 0xff) << 8)
                  + (((new_metric >> 8) & 0xff) << 16)
                  + ((new_metric & 0xff) << 24);
                  tmp.nexthop = rip.entries[i].nexthop;
                  update_rip.entries[update_rip.numEntries++] = tmp;
                }
              }
              else if (new_metric <= found_metric) {
                // TODO: select neighbor [x]
                RoutingTableEntry new_entry;
                new_entry.addr = rip.entries[i].addr;
                new_entry.if_index = if_index;
                new_entry.metric = new_metric;
                new_entry.nexthop = rip.entries[i].nexthop;
                new_entry.timestamp = HAL_GetTicks();
                for (new_entry.len = 0; new_entry.len < 32; new_entry.len++) {
                  if (((1 << new_entry.len) & rip.entries[i].mask) == 0) break;
                }
                update(true, new_entry);
                if (new_metric != METRIC_INF) {
                  RipEntry tmp;
                  tmp.addr = new_entry.addr;
                  tmp.mask = rip.entries[i].mask;
                  tmp.metric = (new_metric >> 24)
                  + (((new_metric >> 16) & 0xff) << 8)
                  + (((new_metric >> 8) & 0xff) << 16)
                  + ((new_metric & 0xff) << 24);
                  tmp.nexthop = rip.entries[i].nexthop;
                  update_rip.entries[update_rip.numEntries++] = tmp;
                }
              }
            }
            else {
              // TODO: not existed before [x]
              RoutingTableEntry new_entry;
              new_entry.addr = rip.entries[i].addr;
              new_entry.if_index = if_index;
              new_entry.metric = new_metric;
              new_entry.nexthop = src_addr;
              new_entry.timestamp = HAL_GetTicks();
              for (new_entry.len = 0; new_entry.len < 32; new_entry.len++) {
                if (((1 << new_entry.len) & rip.entries[i].mask) == 0) break;
              }
#ifdef DISPLAY_UPDATE
              std::cout << "New route: " << new_entry.addr << ' ' << new_entry.metric
              << ' ' << new_entry.len << std::endl;
#endif
              update(true, new_entry);
#ifdef DISPLAY_UPDATE
              std::vector<RoutingTableEntry*> ans;
              getTable(ans);
              for (RoutingTableEntry* i : ans) {
                std::cout << (i->addr & 0xff) << '.' << ((i->addr >> 8) & 0xff) << '.'
                << ((i->addr >> 16) & 0xff) << '.' << ((i->addr >> 24) & 0xff) << '/' << i->len
                << " dev " << i->if_index << " proto Router-Lab scope link"
                << " metric " << i->metric
                << std::endl;
              }
#endif
            }
          }
          // TODO: triggered updates? ref. RFC2453 3.10.1 [x]
          // TODO: split horizon [x]
          if (update_rip.numEntries > 0) {
            for (uint32_t j = 0; j < N_IFACE_ON_BOARD; j++) {
              if (j != if_index) {
                // assemble
                // IP
                output[0] = 0x45;
                output[1] = 0x0;
                output[4] = 0;
                output[5] = 0;
                output[6] = 0;
                output[7] = 0;
                output[8] = 0x1;
                // UDP
                output[9] = 0x11; // ori: 0x21
                output[12] = addrs[j] & 0xff;
                output[13] = (addrs[j] >> 8) & 0xff;
                output[14] = (addrs[j] >> 16) & 0xff;
                output[15] = addrs[j] >> 24;
                output[16] = MULTICAST_IP & 0xff;
                output[17] = (MULTICAST_IP >> 8) & 0xff;
                output[18] = (MULTICAST_IP >> 16) & 0xff;
                output[19] = MULTICAST_IP >> 24;
                // port = 520
                output[20] = 0x02;
                output[21] = 0x08;
                output[22] = 0x02; // TODO: ???
                output[23] = 0x08;
                // RIP
                uint32_t rip_len = assemble(&update_rip, &output[20 + 8]);

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
                output[10] = 0;
                output[11] = 0;
                for (uint16_t i = 0; i + 1 < header_len; i += 2) {
                  uint16_t tmp = i == 10 ? 0 : output[i];
                  tmp = tmp << 8;
                  tmp += i == 10 ? 0 : output[i + 1];
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
#ifdef DISPLAY_UPDATE
                std::cout << "checksum = 0x" << std::ios::hex << (cnt & 0xffff) << std::ios::dec
                << ", it's " << (validateIPChecksum(output, ip_len) ? "true." : "false.") << std::endl;
                std::cout << "Sending response of update: if_index: " << j << std::endl;
                for (int k = 0; k < update_rip.numEntries; k++) {
                  RipEntry re = update_rip.entries[k];
                  std::cout << (re.addr & 0xff) << '.' << ((re.addr >> 8) & 0xff) << '.'
                  << ((re.addr >> 16) & 0xff) << '.' << ((re.addr >> 24) & 0xff) << ' '
                  << (re.mask & 0xff) << '.' << ((re.mask >> 8) & 0xff) << '.'
                  << ((re.mask >> 16) & 0xff) << '.' << ((re.mask >> 24) & 0xff) << ' '
                  << " metric = " << (re.metric >> 24)
                  + (((re.metric >> 16) & 0xff) << 8)
                  + (((re.metric >> 8) & 0xff) << 16)
                  + ((re.metric & 0xff) << 24)
                  << " nexthop = " << (re.nexthop & 0xff) << '.' << ((re.nexthop >> 8) & 0xff) << '.'
                  << ((re.nexthop >> 16) & 0xff) << '.' << ((re.nexthop >> 24) & 0xff) << std::endl;
                }
#endif
                HAL_SendIPPacket(j, output, ip_len, MULTICAST_MAC);
              }
            }
          }
        }
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if, found_metric;
      if (query(dst_addr, &nexthop, &dest_if, &found_metric)) {
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
          // TODO: check ttl=0 case [x]
          if (output[8] == 0) {
#ifdef GROUP_DEBUG
            std::cout << "ttl = 0! Time exceed!" << std::endl;
#endif
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
            output[2] = res & 0xff;
            output[3] = (res >> 8) & 0xff;
            output[8] = 0xff;
            for (int i = 0; i < 4; i++) {
              uint8_t tmp = output[12 + i];
              output[12 + i] = output[16 + i];
              output[16 + i] = tmp;
            }
            uint32_t cnt = 0;
            output[10] = 0;
            output[11] = 0;
            for (uint16_t i = 0; i + 1 < 20; i += 2) {
              uint16_t tmp = output[i];
              tmp = tmp << 8;
              tmp += output[i + 1];
              cnt += tmp;
              while (0xffff < cnt) {
                uint16_t tmps = cnt >> 16;
                cnt = (cnt & 0xffff) + tmps;
              }
            }
            uint16_t cnt16 = ~cnt & 0xffff;
            output[10] = cnt16 >> 8;
            output[11] = cnt16 & 0xff;
          }
          // std::cout << "Forward: checksum = 0x" << std::ios::hex << (((output[10] << 8) + output[11]) & 0xffff) << std::ios::dec
          // << ", it's " << (validateIPChecksum(output, res) ? "true." : "false.") << std::endl;
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else {
          // not found
          // you can drop it
          printf("ARP not found for nexthop %x\n", nexthop);
        }
      } else {
        // not found: ICMP Destination Network Unreachable
        memcpy(output, packet, res);
        // TODO: optionally you can send ICMP Host Unreachable [x]
        output[20] = 3;
        output[21] = 1;
        uint16_t icmp_checksum = 4;
        icmp_checksum = ~icmp_checksum;
        output[22] = icmp_checksum >> 8;
        output[23] = icmp_checksum & 0xff;
        output[24] = 0;
        output[25] = 0;
        output[26] = 0;
        output[27] = 0;
        for (int j = 8; j < 64; j++) output[20 + j] = 0;
        res = 20 + 64;
        output[2] = res & 0xff;
        output[3] = (res >> 8) & 0xff;
        output[8] = 0xff;
        for (int i = 0; i < 4; i++) {
          uint8_t tmp = output[12 + i];
          output[12 + i] = output[16 + i];
          output[16 + i] = tmp;
        }

        uint32_t cnt = 0;
        for (uint16_t i = 0; i + 1 < 20; i += 2) {
          uint16_t tmp = output[i];
          tmp = tmp << 8;
          tmp += output[i + 1];
          cnt += tmp;
          while (0xffff < cnt) {
            uint16_t tmps = cnt >> 16;
            cnt = (cnt & 0xffff) + tmps;
          }
        }
        uint16_t cnt16 = ~cnt & 0xffff;
        output[10] = cnt16 >> 8;
        output[11] = cnt16 & 0xff;
        HAL_SendIPPacket(dest_if, output, 20 + 64, src_mac);

        printf("IP not found for src %x dst %x\n", src_addr, dst_addr);
      }
    }
  }
  return 0;
}
