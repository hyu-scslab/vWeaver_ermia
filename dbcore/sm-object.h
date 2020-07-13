#pragma once

#include "../varstr.h"
#include "epoch.h"
#include "sm-common.h"

namespace ermia {

#define MAX_LEVEL (255)

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

    // next-key shortcut for VWEAVER
    fat_ptr left_shortcut_;

    // level of version
    uint8_t lv_;

    // level of v_ridgy version
    uint8_t v_ridgy_lv_;

    VWeaver()
        : v_ridgy_(NULL_PTR),
          v_ridgy_clsn_(NULL_PTR),
          left_shortcut_(NULL_PTR),
          lv_(1),
          v_ridgy_lv_(0) {}
  };

  VWeaver vweaver_;
#endif /* HYU_VWEAVER */

 public:
  static fat_ptr Create(const varstr* tuple_value, bool do_write,
                        epoch_num epoch);

  Object()
      : alloc_epoch_(0),
        status_(kStatusMemory),
        pdest_(NULL_PTR),
        next_pdest_(NULL_PTR),
        next_volatile_(NULL_PTR),
        clsn_(NULL_PTR) {}

  Object(fat_ptr pdest, fat_ptr next, epoch_num e, bool in_memory)
      : alloc_epoch_(e),
        status_(in_memory ? kStatusMemory : kStatusStorage),
        pdest_(pdest),
        next_pdest_(next),
        next_volatile_(NULL_PTR),
        clsn_(NULL_PTR) {}

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
  inline fat_ptr GetLeftShortcut() {
    return volatile_read(vweaver_.left_shortcut_);
  }
  inline void SetVRidgyClsn(fat_ptr clsn) {
    volatile_write(vweaver_.v_ridgy_clsn_, clsn);
  }
  inline void SetVRidgy(fat_ptr v_ridgy) {
    volatile_write(vweaver_.v_ridgy_, v_ridgy);
  }
  inline void SetLeftShortcut(fat_ptr left) {
    volatile_write(vweaver_.left_shortcut_, left);
  }
#endif /* HYU_VWEAVER */
  fat_ptr GenerateClsnPtr(uint64_t clsn);
  void Pin(
      bool load_from_logbuf = false);  // Make sure the payload is in memory

#ifdef HYU_VWEAVER /* HYU_VWEAVER */
  OID rec_id;
#endif /* HYU_VWEAVER */
};

}  // namespace ermia
