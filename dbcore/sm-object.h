#pragma once

#include "epoch.h"
#include "sm-common.h"
#include "../varstr.h"


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

#if defined(HYU_ZIGZAG) || defined(HYU_VRIDGY_ONLY)
	// highway pointer in version chain
	fat_ptr highway_;

	// copy of highway version's clsn
	fat_ptr highway_clsn_;

	// next-key shortcut for ZIGZAG
	fat_ptr left_shortcut_;

	// level of version
	uint8_t lv_;

	// level of highway version
	uint8_t highway_lv_;
#endif /* HYU_ZIGZAG || HYU_VRIDGY_ONLY */


 public:
  static fat_ptr Create(const varstr* tuple_value, bool do_write,
                        epoch_num epoch);

  Object()
      : alloc_epoch_(0),
        status_(kStatusMemory),
        pdest_(NULL_PTR),
        next_pdest_(NULL_PTR),
        next_volatile_(NULL_PTR),
        clsn_(NULL_PTR),
#if defined(HYU_ZIGZAG) || defined(HYU_VRIDGY_ONLY)
				highway_(NULL_PTR),
				highway_clsn_(NULL_PTR),
				left_shortcut_(NULL_PTR),
				lv_(1),
				highway_lv_(0),
#endif /* HYU_ZIGZAG || HYU_VRIDGY_ONLY */
				HYU_gc_candidate_clsn_(0) {}

  Object(fat_ptr pdest, fat_ptr next, epoch_num e, bool in_memory)
      : alloc_epoch_(e),
        status_(in_memory ? kStatusMemory : kStatusStorage),
        pdest_(pdest),
        next_pdest_(next),
        next_volatile_(NULL_PTR),
        clsn_(NULL_PTR),
#if defined(HYU_ZIGZAG) || defined(HYU_VRIDGY_ONLY)
				highway_(NULL_PTR),
				highway_clsn_(NULL_PTR),
				left_shortcut_(NULL_PTR),
				lv_(1),
				highway_lv_(0),
#endif /* HYU_ZIGZAG || HYU_VRIDGY_ONLY */
				HYU_gc_candidate_clsn_(0) {}

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
#if defined(HYU_ZIGZAG) || defined(HYU_VRIDGY_ONLY)
	inline int TossCoin(uint64_t seed) {
		seed ^= seed >> 12;
		seed ^= seed << 25;
		seed ^= seed >> 27;

		return (seed * 2685821657736338717ULL) % 2;
	}
	inline uint8_t GetLevel() { return lv_; }
	inline void SetLevel(uint8_t level) { lv_ = level; }
	inline uint8_t GetHighwayLevel() { return highway_lv_; }
	inline void SetHighwayLevel(uint8_t level) { highway_lv_ = level; }
	inline fat_ptr GetHighwayClsn() { return volatile_read(highway_clsn_); }
	inline fat_ptr GetHighway() { return volatile_read(highway_); }
	inline fat_ptr GetLeftShortcut() { return volatile_read(left_shortcut_); }
	inline void SetHighwayClsn(fat_ptr clsn) { volatile_write(highway_clsn_, clsn); }
	inline void SetHighway(fat_ptr highway) { volatile_write(highway_, highway); }
	inline void SetLeftShortcut(fat_ptr left) { volatile_write(left_shortcut_, left); }
#endif /* HYU_ZIGZAG || HYU_VRIDGY_ONLY */
  fat_ptr GenerateClsnPtr(uint64_t clsn);
  void Pin(
      bool load_from_logbuf = false);  // Make sure the payload is in memory
	
	// HYU_GC
	uint64_t HYU_gc_candidate_clsn_;
#if defined(HYU_ZIGZAG) || defined(HYU_VRIDGY_ONLY)
	OID rec_id;
#endif /* HYU_ZIGZAG || HYU_VRIDGY_ONLY */
};
}  // namespace ermia
