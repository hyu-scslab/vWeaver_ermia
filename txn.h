#pragma once

#include <stdint.h>
#include <sys/types.h>

#include <vector>

#ifdef HYU_ZIGZAG /* HYU_ZIGZAG */
#include <cstring>
#endif /* HYU_ZIGZAG */
#ifdef HYU_EVAL /* HYU_EVAL */
#include <stdio.h>
#endif /* HYU_EVAL */

#include "dbcore/xid.h"
#include "dbcore/sm-config.h"
#include "dbcore/sm-oid.h"
#include "dbcore/sm-log.h"
#include "dbcore/sm-object.h"
#include "dbcore/sm-rc.h"
#include "masstree/masstree_btree.h"
#include "macros.h"
#include "str_arena.h"
#include "tuple.h"

#include <sparsehash/dense_hash_map>
using google::dense_hash_map;

namespace ermia {

#ifdef HYU_ZIGZAG /* HYU_ZIGZAG */
struct next_key_info_t {
	OID oid;
	Masstree::leaf<masstree_params> *leaf;
	Masstree::leaf<masstree_params>::permuter_type perm;
	int ki; // -1 is end of leaf, -2 is insertion case
};
#endif /* HYU_ZIGZAG */

// A write-set entry is essentially a pointer to the OID array entry
// begin updated. The write-set is naturally de-duplicated: repetitive
// updates will leave only one entry by the first update. Dereferencing
// the entry pointer results a fat_ptr to the new object.
struct write_record_t {
  fat_ptr *entry;
#ifdef HYU_ZIGZAG /* HYU_ZIGZAG */
	varstr key;
	IndexDescriptor *idx_desc;
	OID oid;
	next_key_info_t next_key_info;
	write_record_t(fat_ptr *e, const varstr *k, IndexDescriptor *index_desc,
								OID o, next_key_info_t nk_info) {
		entry = e;
		key.l = k->l;
		key.p = k->p;
		idx_desc = index_desc;
		oid = o;
		memcpy(&next_key_info, &nk_info, sizeof(next_key_info_t));
	}
	write_record_t() : entry(nullptr), idx_desc(nullptr) {}
#else /* HYU_ZIGZAG */
  write_record_t(fat_ptr *entry) : entry(entry) {}
  write_record_t() : entry(nullptr) {}
#endif /* HYU_ZIGZAG */
  inline Object *get_object() { return (Object *)entry->offset(); }
};

struct write_set_t {
  static const uint32_t kMaxEntries = 256;
  uint32_t num_entries;
  write_record_t entries[kMaxEntries];
  write_set_t() : num_entries(0) {}
#ifdef HYU_ZIGZAG /* HYU_ZIGZAG */
  inline void emplace_back(fat_ptr *oe, const varstr *k,
													IndexDescriptor *index_desc, OID oid,
													next_key_info_t next_key_info) {
    ALWAYS_ASSERT(num_entries < kMaxEntries);
    new (&entries[num_entries]) write_record_t(oe, k, index_desc, oid,
																							next_key_info);
    ++num_entries;
    ASSERT(entries[num_entries - 1].entry == oe);
  }
#else /* HYU_ZIGZAG */
  inline void emplace_back(fat_ptr *oe) {
    ALWAYS_ASSERT(num_entries < kMaxEntries);
    new (&entries[num_entries]) write_record_t(oe);
    ++num_entries;
    ASSERT(entries[num_entries - 1].entry == oe);
  }
#endif /* HYU_ZIGZAG */
  inline uint32_t size() { return num_entries; }
  inline void clear() { num_entries = 0; }
  inline write_record_t &operator[](uint32_t idx) { return entries[idx]; }
};

class transaction {
  friend class ConcurrentMasstreeIndex;
  friend class sm_oid_mgr;

public:
  typedef TXN::txn_state txn_state;
#ifdef HYU_EVAL /* HYU_EVAL */
	FILE* fp;
	bool check;
	uint64_t update_cost;
	uint64_t vridgy_cost;
	uint64_t kridgy_cost;
#endif /* HYU_EVAL */

#if defined(SSN) || defined(SSI) || defined(MVOCC)
  typedef std::vector<dbtuple *> read_set_t;
#endif

  enum {
    // use the low-level scan protocol for checking scan consistency,
    // instead of keeping track of absent ranges
    TXN_FLAG_LOW_LEVEL_SCAN = 0x1,

    // true to mark a read-only transaction- if a txn marked read-only
    // does a write, it is aborted. SSN uses it to implement to safesnap.
    // No bookeeping is done with SSN if this is enable for a tx.
    TXN_FLAG_READ_ONLY = 0x2,

    TXN_FLAG_READ_MOSTLY = 0x3,

    // A redo transaction running on a backup server using command logging.
    TXN_FLAG_CMD_REDO = 0x4,
  };

  inline bool is_read_mostly() { return flags & TXN_FLAG_READ_MOSTLY; }
  inline bool is_read_only() { return flags & TXN_FLAG_READ_ONLY; }

protected:
  inline txn_state state() const { return xc->state; }

  // the absent set is a mapping from (masstree node -> version_number).
  typedef dense_hash_map<const ConcurrentMasstree::node_opaque_t *, uint64_t > MasstreeAbsentSet;
  MasstreeAbsentSet masstree_absent_set;

 public:
  transaction(uint64_t flags, str_arena &sa);
  ~transaction();
  void initialize_read_write();

  inline void ensure_active() {
    volatile_write(xc->state, TXN::TXN_ACTIVE);
    ASSERT(state() == TXN::TXN_ACTIVE);
  }

  rc_t commit();
#ifdef SSN
  rc_t parallel_ssn_commit();
  rc_t ssn_read(dbtuple *tuple);
#elif defined SSI
  rc_t parallel_ssi_commit();
  rc_t ssi_read(dbtuple *tuple);
#elif defined MVOCC
  rc_t mvocc_commit();
  rc_t mvocc_read(dbtuple *tuple);
#else
  rc_t si_commit();
#endif

  bool MasstreeCheckPhantom();
  void Abort();

  OID PrepareInsert(OrderedIndex *index, varstr *value, dbtuple **out_tuple);
  void FinishInsert(OrderedIndex *index, OID oid, const varstr *key, varstr *value, dbtuple *tuple);
  bool TryInsertNewTuple(OrderedIndex *index, const varstr *key,
                         varstr *value, OID *inserted_oid);

#ifdef HYU_ZIGZAG /* HYU_ZIGZAG */
  rc_t Update(IndexDescriptor *index_desc, OID oid, const varstr *k, varstr *v,
							next_key_info_t next_key_info);
#else /* HYU_ZIGZAG */
  rc_t Update(IndexDescriptor *index_desc, OID oid, const varstr *k, varstr *v);
#endif /* HYU_ZIGZAG */

 public:
  // Reads the contents of tuple into v within this transaction context
  rc_t DoTupleRead(dbtuple *tuple, varstr *out_v);

  // expected public overrides

  inline str_arena &string_allocator() { return *sa; }
	// for test HYU
	inline sm_tx_log* GetLog() { return log; }

#if defined(SSN) || defined(SSI) || defined(MVOCC)
  inline read_set_t &GetReadSet() {
    thread_local read_set_t read_set;
    return read_set;
  }
#endif

  inline write_set_t &GetWriteSet() {
    thread_local write_set_t write_set;
    return write_set;
  }

#ifdef HYU_ZIGZAG /* HYU_ZIGZAG */
	// oid is for debug
	inline void add_to_write_set_zigzag(fat_ptr *entry, const varstr *k,
																			IndexDescriptor *index_desc, OID oid,
																			next_key_info_t next_key_info) {
#ifndef NDEBUG
    auto &write_set = GetWriteSet();
    for (uint32_t i = 0; i < write_set.size(); ++i) {
      auto &w = write_set[i];
      ASSERT(w.entry);
      ASSERT(w.entry != entry);
    }
#endif
    GetWriteSet().emplace_back(entry, k, index_desc, oid, next_key_info);
	}
#else /* HYU_ZIGZAG */
  inline void add_to_write_set(fat_ptr *entry) {
#ifndef NDEBUG
    auto &write_set = GetWriteSet();
    for (uint32_t i = 0; i < write_set.size(); ++i) {
      auto &w = write_set[i];
      ASSERT(w.entry);
      ASSERT(w.entry != entry);
    }
#endif
    GetWriteSet().emplace_back(entry);
  }
#endif /* HYU_ZIGZAG */

  inline TXN::xid_context *GetXIDContext() { return xc; }

 protected:
  const uint64_t flags;
  XID xid;
  TXN::xid_context *xc;
  sm_tx_log *log;
  str_arena *sa;
};

}  // namespace ermia
