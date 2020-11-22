#pragma once

#include "../varstr.h"
#include "epoch.h"
#include "sm-common.h"

namespace ermia {
#ifdef HYU_VWEAVER /* HYU_VWEAVER */
#define MAX_LEVEL (255)
#endif /* HYU_VWEAVER */

#ifdef HYU_SKIPLIST /* HYU_SKIPLIST */
#define MAX_LEVEL (32)
#endif /* HYU_SKIPLIST */

struct dbtuple;
class sm_log_recover_mgr;

class Object {
 private:
  typedef epoch_mgr::epoch_num epoch_num;
  static const uint32_t kStatusMemory = 1;
  static const uint32_t kStatusStorage = 2;
  static const uint32_t kStatusLoading = 3;
  static const uint32_t kStatusDeleted = 4;

  // alloc_epoch_ and status_ must be the first two fields

  // When did we create this object?
  epoch_num alloc_epoch_;

  // Where exactly is the payload?
  uint32_t status_;

  // The object's permanent home in the log/chkpt
  fat_ptr pdest_;

  // The permanent home of the older version that's overwritten by me
  fat_ptr next_pdest_;

  // Volatile pointer to the next older version that's in memory.
  // There might be a gap between the versions represented by next_pdest_
  // and next_volatile_.
  fat_ptr next_volatile_;

  // Commit timestamp of this version. Type is XID (LOG) before (after)
  // commit. size_code refers to the whole object including header
  fat_ptr clsn_;

#ifdef HYU_VWEAVER /* HYU_VWEAVER */
  class VWeaver {
   public:
    // v_ridgy pointer in version chain
    fat_ptr v_ridgy_;

    // copy of v_ridgy version's clsn
    fat_ptr v_ridgy_clsn_;

    // k_ridgy pointer for VWEAVER
    fat_ptr k_ridgy_;

    // level of version
    uint8_t lv_;

    // level of v_ridgy version
    uint8_t v_ridgy_lv_;

    VWeaver()
        : v_ridgy_(NULL_PTR),
          v_ridgy_clsn_(NULL_PTR),
          k_ridgy_(NULL_PTR),
          lv_(1),
          v_ridgy_lv_(0) {}
  };

  VWeaver vweaver_;
#endif /* HYU_VWEAVER */

#ifdef HYU_SKIPLIST /* HYU_SKIPLIST */
  fat_ptr lv_pointer_;
  uint8_t lv_;
#endif /* HYU_SKIPLIST */

 public:
#ifdef HYU_SKIPLIST /* HYU_SKIPLIST */
  fat_ptr sentinel_;
#endif /* HYU_SKIPLIST */
  static fat_ptr Create(const varstr* tuple_value, bool do_write,
                        epoch_num epoch);

  Object()
      : alloc_epoch_(0),
        status_(kStatusMemory),
        pdest_(NULL_PTR),
        next_pdest_(NULL_PTR),
        next_volatile_(NULL_PTR),
#ifdef HYU_SKIPLIST /* HYU_SKIPLIST */
        clsn_(NULL_PTR),
        lv_pointer_(NULL_PTR),
        lv_(0),
        sentinel_(NULL_PTR) {}
#else /* HYU_SKIPLIST */
        //clsn_(NULL_PTR),
        //HYU_candidate_glsn(0) {}
        clsn_(NULL_PTR) {}
#endif /* HYU_SKIPLIST */

  Object(fat_ptr pdest, fat_ptr next, epoch_num e, bool in_memory)
      : alloc_epoch_(e),
        status_(in_memory ? kStatusMemory : kStatusStorage),
        pdest_(pdest),
        next_pdest_(next),
        next_volatile_(NULL_PTR),
#ifdef HYU_SKIPLIST /* HYU_SKIPLIST */
        clsn_(NULL_PTR),
        lv_pointer_(NULL_PTR),
        lv_(0),
        sentinel_(NULL_PTR) {}
#else /* HYU_SKIPLIST */
        //clsn_(NULL_PTR),
        //HYU_candidate_glsn(0) {}
        clsn_(NULL_PTR) {}
#endif /* HYU_SKIPLIST */

  inline bool IsDeleted() { return status_ == kStatusDeleted; }
  inline bool IsInMemory() { return status_ == kStatusMemory; }
  inline fat_ptr* GetPersistentAddressPtr() { return &pdest_; }
  inline fat_ptr GetPersistentAddress() { return pdest_; }
  inline fat_ptr GetClsn() { return volatile_read(clsn_); }
  inline void SetClsn(fat_ptr clsn) { volatile_write(clsn_, clsn); }
  inline fat_ptr GetNextPersistent() { return volatile_read(next_pdest_); }
  inline fat_ptr* GetNextPersistentPtr() { return &next_pdest_; }
  inline fat_ptr GetNextVolatile() { return volatile_read(next_volatile_); }
  inline fat_ptr* GetNextVolatilePtr() { return &next_volatile_; }
  inline void SetNextPersistent(fat_ptr next) {
    volatile_write(next_pdest_, next);
  }
  inline void SetNextVolatile(fat_ptr next) {
    volatile_write(next_volatile_, next);
  }
  inline epoch_num GetAllocateEpoch() { return alloc_epoch_; }
  inline void SetAllocateEpoch(epoch_num e) { alloc_epoch_ = e; }
  inline char* GetPayload() { return (char*)((char*)this + sizeof(Object)); }
  inline void SetStatus(uint32_t s) { volatile_write(status_, s); }
  inline dbtuple* GetPinnedTuple() {
    if (IsDeleted()) {
      return nullptr;
    }
    if (!IsInMemory()) {
      Pin();
    }
    return (dbtuple*)GetPayload();
  }

#ifdef HYU_VWEAVER /* HYU_VWEAVER */
  inline int TossCoin(uint64_t* seed) {
    *seed ^= *seed >> 12;
    *seed ^= *seed << 25;
    *seed ^= *seed >> 27;

    return (*seed * 2685821657736338717ULL) % 2;
  }
  inline uint8_t GetLevel() { return vweaver_.lv_; }
  inline void SetLevel(uint8_t level) { vweaver_.lv_ = level; }
  inline uint8_t GetVRidgyLevel() { return vweaver_.v_ridgy_lv_; }
  inline void SetVRidgyLevel(uint8_t level) { vweaver_.v_ridgy_lv_ = level; }
  inline fat_ptr GetVRidgyClsn() {
    return volatile_read(vweaver_.v_ridgy_clsn_);
  }
  inline fat_ptr GetVRidgy() { return volatile_read(vweaver_.v_ridgy_); }
  inline fat_ptr GetKRidgy() { return volatile_read(vweaver_.k_ridgy_); }
  inline void SetVRidgyClsn(fat_ptr clsn) {
    volatile_write(vweaver_.v_ridgy_clsn_, clsn);
  }
  inline void SetVRidgy(fat_ptr v_ridgy) {
    volatile_write(vweaver_.v_ridgy_, v_ridgy);
  }
  inline void SetKRidgy(fat_ptr k_ridgy) {
    volatile_write(vweaver_.k_ridgy_, k_ridgy);
  }
#endif /* HYU_VWEAVER */

#ifdef HYU_SKIPLIST /* HYU_SKIPLIST */
  inline int TossCoin2(uint64_t* seed) {
    *seed ^= *seed >> 12;
    *seed ^= *seed << 25;
    *seed ^= *seed >> 27;

    return (*seed * 2685821657736338717ULL) % 2;
  }
  inline uint8_t GetLv() { return lv_; }
  inline void SetLv(uint8_t level) { volatile_write(lv_, level); }
  inline fat_ptr GetSentinel() { return volatile_read(sentinel_); }
  inline fat_ptr GetLvPointer() { return volatile_read(lv_pointer_); }
  inline void SetSentinel(fat_ptr sentinel) {
    volatile_write(sentinel_, sentinel);
  }
  inline void SetLvPointer(fat_ptr lv_pointer) {
    volatile_write(lv_pointer_, lv_pointer);
  }
  void AllocLvPointer();
#endif /* HYU_SKIPLIST */

  fat_ptr GenerateClsnPtr(uint64_t clsn);
  void Pin(
      bool load_from_logbuf = false);  // Make sure the payload is in memory

/* HYU_VWEAVER || HYU_SKIPLIST */
#if defined(HYU_VWEAVER) || defined(HYU_SKIPLIST)
  OID rec_id;
#endif /* HYU_VWEAVER || HYU_SKIPLIST */
  //uint64_t HYU_candidate_glsn;
};

}  // namespace ermia
