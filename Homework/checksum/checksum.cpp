#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  uint16_t header_len = packet[0] & 0xf;
  header_len = header_len << 2;
  uint16_t ori_checksum = packet[10];
  ori_checksum = (ori_checksum << 8) + packet[11];
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
  return cnt == ori_checksum;
}
