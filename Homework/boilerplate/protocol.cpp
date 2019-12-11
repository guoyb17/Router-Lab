#include "rip.h"
#include <stdint.h>
#include <stdlib.h>

#define UDP_HEAD 8
#define RIP_HEAD 4
#define RIP_ENTRY_LENGTH 20

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
    uint64_t timestamp;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  uint32_t totalLength = (packet[2] << 8) + packet[3];
  if (totalLength > len) return false;
  uint8_t headerLength = (packet[0] & 0xf) << 2;

  // check command
  uint8_t command = packet[headerLength + UDP_HEAD];
  if (command != 1 && command != 2) return false;
  output->command = command;
  uint8_t tmp = packet[headerLength + UDP_HEAD + 1];
  if (tmp != 2) return false;

  // Check ZERO
  tmp = packet[headerLength + UDP_HEAD + 2];
  if (tmp != 0) return false;
  tmp = packet[headerLength + UDP_HEAD + 3];
  if (tmp != 0) return false;

  uint32_t numEntries = (len - headerLength - UDP_HEAD - RIP_HEAD) / RIP_ENTRY_LENGTH;
  output->numEntries = numEntries;

  for (uint32_t entry = 0; entry < numEntries; entry++) {
    // check address family
    tmp = packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH];
    if (tmp != 0) return false;
    tmp = packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 1];
    if (!((command == 1 && tmp == 0) || (command == 2 && tmp == 2))) return false;

    // check tag
    tmp = packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 2];
    if (tmp != 0) return false;
    tmp = packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 3];
    if (tmp != 0) return false;

    // check metric
    uint32_t metricLittle
    = ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 16] << 24)
    + ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 17] << 16)
    + ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 18] << 8)
    + (uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 19];
    uint32_t metricBig
    = ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 19] << 24)
    + ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 18] << 16)
    + ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 17] << 8)
    + (uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 16];
    if (!(1 <= metricLittle && metricLittle <= 16)) return false;
    output->entries[entry].metric = metricBig;

    // check mask
    uint32_t mask
    = ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 11] << 24)
    + ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 10] << 16)
    + ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 9] << 8)
    + (uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 8];
    bool is1 = true;
    uint8_t checkBit = 0;
    while(is1 && (checkBit < 32)) {
      if ((mask & (((uint32_t)1) << checkBit)) == 0) is1 = false;
      else checkBit++;
    }
    while(!is1 && (checkBit < 32)) {
      if ((mask & (((uint32_t)1) << checkBit)) != 0) return false;
      else checkBit++;
    }
    output->entries[entry].mask = mask;

    uint32_t addr
    = ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 7] << 24)
    + ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 6] << 16)
    + ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 5] << 8)
    + (uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 4];
    output->entries[entry].addr = addr;

    uint32_t nexthop
    = ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 15] << 24)
    + ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 14] << 16)
    + ((uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 13] << 8)
    + (uint32_t)packet[headerLength + UDP_HEAD + RIP_HEAD + entry * RIP_ENTRY_LENGTH + 12];
    output->entries[entry].nexthop = nexthop;
  }

  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  buffer[0] = rip->command;
  buffer[1] = 0x02;
  buffer[2] = 0x00;
  buffer[3] = 0x00;
  uint32_t ans = RIP_HEAD;

  for (uint32_t entry = 0; entry < rip->numEntries; entry++) {
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH] = 0x00;
    if (rip->command == 1) buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 1] = 0x00;
    else if (rip->command == 2) buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 1] = 0x02;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 2] = 0x00;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 3] = 0x00;

    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 7] = (rip->entries[entry].addr & 0xff000000) >> 24;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 6] = (rip->entries[entry].addr & 0x00ff0000) >> 16;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 5] = (rip->entries[entry].addr & 0x0000ff00) >> 8;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 4] = rip->entries[entry].addr & 0x000000ff;

    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 11] = (rip->entries[entry].mask & 0xff000000) >> 24;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 10] = (rip->entries[entry].mask & 0x00ff0000) >> 16;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 9] = (rip->entries[entry].mask & 0x0000ff00) >> 8;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 8] = rip->entries[entry].mask & 0x000000ff;

    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 15] = (rip->entries[entry].nexthop & 0xff000000) >> 24;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 14] = (rip->entries[entry].nexthop & 0x00ff0000) >> 16;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 13] = (rip->entries[entry].nexthop & 0x0000ff00) >> 8;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 12] = rip->entries[entry].nexthop & 0x000000ff;

    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 19] = (rip->entries[entry].metric & 0xff000000) >> 24;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 18] = (rip->entries[entry].metric & 0x00ff0000) >> 16;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 17] = (rip->entries[entry].metric & 0x0000ff00) >> 8;
    buffer[RIP_HEAD + entry * RIP_ENTRY_LENGTH + 16] = rip->entries[entry].metric & 0x000000ff;

    ans += RIP_ENTRY_LENGTH;
  }
  return ans;
}
