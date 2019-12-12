#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  if (packet[8] == 0) return false;
  uint16_t header_len = packet[0] & 0xf;
  header_len = header_len << 2;
  uint16_t ori_checksum = packet[10];
  ori_checksum = (ori_checksum << 8) + packet[11];
  packet[10] = 0;
  packet[11] = 0;
  uint32_t cnt = 0;
  for (uint16_t i = 0; i + 1 < header_len; i += 2) {
    uint16_t tmp = packet[i];
    tmp = tmp << 8;
    tmp += packet[i + 1];
    cnt += tmp;
    while (0xffff < cnt) {
      uint16_t tmps = cnt >> 16;
      cnt = (cnt & 0xffff) + tmps;
    }
  }
  uint16_t cnt16 = ~cnt & 0xffff;
  if (cnt16 != ori_checksum) return false;

  // uint16_t m0 = (packet[8] << 8) + packet[9];
  packet[8] -= 1;
  // uint16_t m1 = m0 - 0x100;

  // cnt16 = ~cnt16;
  // m0 = ~m0;
  // uint32_t tmp = cnt16 + m0 + m1;
  // if (0xffff < tmp) cnt16 = (tmp >> 16) + (tmp & 0xffff);
  // else cnt16 = tmp;
  // cnt16 = ~cnt16;
  uint32_t cnt = 0;
  for (uint16_t i = 0; i + 1 < header_len; i += 2) {
    uint16_t tmp = packet[i];
    tmp = tmp << 8;
    tmp += packet[i + 1];
    cnt += tmp;
    while (0xffff < cnt) {
      uint16_t tmps = cnt >> 16;
      cnt = (cnt & 0xffff) + tmps;
    }
  }
  uint16_t cnt16 = ~cnt & 0xffff;

  packet[11] = cnt16 & 0xff;
  packet[10] = (cnt16 >> 8) & 0xff;
  return true;
}
