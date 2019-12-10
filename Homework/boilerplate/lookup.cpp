#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <fstream>

#include <vector>
using namespace std;

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
	uint32_t metric; // 小端序，到下一路由器的权值
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

/**
* Guo Yuanbo, Tsinghua Univ., All rights reserved.
* @brief Trie tree template
* @author Guo Yuanbo
* @email guoyb17@mails.tsinghua.edu.cn
* @version 0.1
* @date 2019-11-24
* @update 2019-11-24
* @warning the tree does NOT maintain Info (see below)
*/
// Trie-Node class template
// Char: dict keyword (e.g. a-zA-Z0-9 for dictionary, 0/1 for IP address, etc.)
//     Char needs:
//     *   method int seq()   - to get sequence of this Char
//     *   static member size - to get number of kinds of Char
//     *   operator==         - to compare Char sequence
// Info: node info, may be use to store the entire word or other things (e.g. route info)
//     Info needs:
//     *   operator==         - to compare whether two Info are identical
//     *   method of copy     - to give Info to node
//         operator<<         - DEBUG only: output stream
// [WARN] The tree does NOT maintain Info!
//        Make sure Info keeps valid while tree working!
//        Also make sure memory managed properly outside the tree if necessary!
template <class Char, class Info>
class Trie {

    Info* info = nullptr; // also marks that there is a word ending up here
	Trie(const Trie&) = delete;
	Trie& operator=(const Trie& b) = delete;
	Trie* next = nullptr;

public:

	inline static const int size() { return Char::size; }

	Trie(Info* i = nullptr) {
		info = i;
		next = nullptr;
	}

	bool empty() { return info == nullptr && next == nullptr; }

	void insert(Char** word, Info* iinfo) { // word needs to end up with nullptr as a sign
		if (word[0] == nullptr) {
			if (info == nullptr) info = new Info;
			*info = *iinfo; // will overwrite previous info
			return;
		}
		if (next == nullptr) next = new Trie[size()];
		next[word[0]->seq()].insert(&word[1], iinfo);
	}

	/**
	 * @return
	 * 0 - matched and deleted
	 * 1 - this node is clear
	 * -1 - not matched due to null info
	 * -2 - NOT IN USE
	 * -3 - ERROR not matched due to no children
	 * -4 - recursively not matched
	*/
	int remove(Char** word) {
		if (word[0] == nullptr) {
			if (info != nullptr) {
				delete info;
				info = nullptr;
				if (next == nullptr) return 1;
				else return 0;
			}
			else return -1;
		}
		if (next == nullptr) return -3;
		int ans = next[word[0]->seq()].remove(&word[1]);
		if (ans == 1) {
			for (int i = 0; i < size(); i++) {
				if (!next[i].empty()) return 0;
			}
			delete[] next;
			next = nullptr;
			if (info == nullptr) return 1;
			else return 0;
		}
		else if (ans == 0) return 0;
		else return -4;
	}

	/**
	 * @param ans collect all prefix-matched info
	 *     [NOTE] ans <- vec [short ... long] match; NO guarantee for total match!
	 * @return true if this call found ans, false if not
	 */
	bool lookup_pre(Char** word, vector<const Info*>& ans) {
		if (word[0] == nullptr) {
			if (info != nullptr) {
				ans.push_back(info);
				return true;
			}
			else return false;
		}
		
		bool tflag = true;
		if (info != nullptr) ans.push_back(info);
		else tflag = false;
		if (next == nullptr) return tflag;
		return next[word[0]->seq()].lookup_pre(&word[1], ans) || tflag;
	}

	/**
	 * @param ans collect all info and return
	 */
	void get_all(vector<Info*>& ans) {
		if (info != nullptr) {
			ans.push_back(info);
		}
		if (next != nullptr) {
			for (int i = 0; i < size(); i++) {
				if (!next[i].empty()) {
					next[i].get_all(ans);
				}
			}
		}
	}
};

struct Bin {
    uint8_t bin;

    static const int size = 2;

    int seq() {
        if (bin == 0) return 0;
        else if (bin == 1) return 1;
        else throw "INVALID_BIN";
    }
};

bool operator==(const Bin& a, const Bin& b) { return a.bin == b.bin; }
bool operator==(const RoutingTableEntry& a, const RoutingTableEntry& b) {
    if (a.addr != b.addr) return false;
    if (a.if_index != b.if_index) return false;
    if (a.len != b.len) return false;
    if (a.nexthop != b.nexthop) return false;
	if (a.metric != b.metric) return false;
    return true;
}

void mk_word(RoutingTableEntry& info, Bin**& ans) { // ans contains both addr and len
    if (ans == nullptr) ans = new Bin*[info.len + 1];
    uint8_t ip[4];
    ip[0] = info.addr & 0xff;
    ip[1] = (info.addr & 0xff00) >> 8;
    ip[2] = (info.addr & 0xff0000) >> 16;
    ip[3] = (info.addr & 0xff000000) >> 24;
    
    for (uint32_t j = 0; j < info.len; j++) {
        ans[j] = new Bin;
        ans[j]->bin = ((ip[j / 8] & (0x1 << (7 - j % 8))) == 0) ? 0 : 1;
    }
    ans[info.len] = nullptr;
}

void mk_word(uint32_t& info, Bin**& ans) {
	if (ans == nullptr) ans = new Bin*[32 + 1];
	uint8_t ip[4];
	ip[0] = info & 0xff;
	ip[1] = (info & 0xff00) >> 8;
	ip[2] = (info & 0xff0000) >> 16;
	ip[3] = (info & 0xff000000) >> 24;

	for (uint32_t j = 0; j < 32; j++) {
		ans[j] = new Bin;
		ans[j]->bin = ((ip[j / 8] & (0x1 << (7 - j % 8))) == 0) ? 0 : 1;
	}
	ans[32] = nullptr;
}

Trie<Bin, RoutingTableEntry> rtable(nullptr);

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
    Bin** ans = nullptr;
    mk_word(entry, ans);
    if (insert) rtable.insert(ans, &entry);
    else rtable.remove(ans);
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
    Bin** ans = nullptr;
    mk_word(addr, ans);
    vector<const RoutingTableEntry*> list;
    rtable.lookup_pre(ans, list);
    if (list.empty()) return false;
    const RoutingTableEntry value = *list[list.size() - 1];
    *nexthop = value.nexthop;
    *if_index = value.if_index;
    return true;
}

/**
 * @brief 获取当前的完整路由表
 * @param ans 返回完整路由表
 */
void getTable(vector<RoutingTableEntry*>& ans) {
	rtable.get_all(ans);
}
