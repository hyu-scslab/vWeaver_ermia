#include <fcntl.h>
#include <unistd.h>

#include <map>

#ifdef HYU_EVAL /* HYU_EVAL */
#include <sys/times.h>
#endif /* HYU_EVAL */

#include "../ermia.h"
#include "../txn.h"
#include "../util.h"

#include "burt-hash.h"
#include "sc-hash.h"
#include "sm-alloc.h"
#include "sm-chkpt.h"
#include "sm-config.h"
#include "sm-index.h"
#include "sm-log-recover-impl.h"
#include "sm-object.h"
#include "sm-oid-impl.h"

namespace ermia {
sm_oid_mgr *oidmgr = NULL;

struct thread_data {
  static size_t const NENTRIES = 4096;

  struct hasher : burt_hash {
    using burt_hash::burt_hash;
    using burt_hash::operator();
    uint32_t operator()(sm_allocator::thread_cache const &x) const {
      return operator()(x.f);
    }
  };
  struct cmpeq {
    using tcache = sm_allocator::thread_cache;
    bool operator()(tcache const &a, tcache const &b) const {
      return a.f == b.f;
    }
    bool operator()(tcache const &a, FID const &f) const { return a.f == f; }
  };
  typedef sc_hash_set<NENTRIES, sm_allocator::thread_cache, hasher, cmpeq>
      cache_map;
  cache_map caches;

  /* Threads stockpile stacks of free OIDs for files they have
     allocated from in the past. Stockpiled OIDs count as
     "allocated" during forward processing, but it's best to account
     for them during a checkpoint (GC will eventually find and
     recover allocated-but-unused OIDs, but we'd rather not have too
     many OIDs missing in the meantime)

     The checkpoint thread holds the allocator's mutex while copying
     its state, and holds the thread's mutex while scanning through
     the stockpiled OIDs at various threads to update the
     allocator's snapshot. This means the user thread can allocate
     and free OIDs while the scan is in progress (we rely on GC to
     reclaim any OIDs that go missing as a result).

     The user must grab a mutex to insert or remove FID caches from
     the set, though. Otherwise all kinds of "fun" things could
     happen. Like an insertion moving an existing entry so the
     checkpoint scan misses it. Or an eviction freeing a pile of
     OIDs that the checkpoint thread never learns about.
  */
  os_mutex mutex;
};

thread_local thread_data *tls = nullptr;

/* Used to make sure threads give back their caches on exit */
os_mutex_pod oid_mutex = os_mutex_pod::static_init();
sm_oid_mgr_impl *master;
std::map<pthread_t, thread_data *> *threads;
pthread_key_t pthread_key;

/* Wipe out all caches held by the calling thread, returning any OIDs
   they contain to the owning allocators. Separate the cache-draining
   from the cache-destroying so we only hold one latch at a time.
   Otherwise we risk deadlock: we would acquire the thread mutex
   before the allocator bucket mutexes, while a checkpoint thread
   would tend to do the opposite.
 */
void thread_revoke_caches(sm_oid_mgr_impl *om) {
  for (auto it = tls->caches.begin(); it != tls->caches.end(); ++it) {
    om->lock_file(it->f);
    DEFER(om->unlock_file(it->f));
    auto *alloc = om->get_allocator(it->f);
    alloc->drain_cache(&*it);
  }

  // now nuke the htab
  tls->mutex.lock();
  DEFER(tls->mutex.unlock());
  tls->caches.clear();
}

void thread_fini(sm_oid_mgr_impl *om) {
  auto tid = pthread_self();
  thread_revoke_caches(om);

  oid_mutex.lock();
  DEFER(oid_mutex.unlock());

  threads->erase(tid);
}

void thread_init() {
  auto tid = pthread_self();
  auto tmp = new thread_data{};
  DEFER_UNLESS(success, delete tmp);

  oid_mutex.lock();
  DEFER(oid_mutex.unlock());

  threads->emplace(tid, tmp);

  int err = pthread_setspecific(pthread_key, tmp);
  THROW_IF(err, os_error, errno, "pthread_setspecific failed");
  success = true;

  tls = tmp;
}

/* Find (or create, if necessary) the thread-local cache for the
   requested FID
 */
thread_data::cache_map::iterator thread_cache(sm_oid_mgr_impl *om, FID f) {
  if (not tls) thread_init();

  /* Attempt to insert [f] into the cache. If present, return the
     corresponding cache. If not present, create a new cache and
     return it. If the cache is full, we'll find that out, too.
   */
  auto rval = tls->caches.find_and_emplace(f, f);
  if (rval.second == -1) {
    /* Not present, cache full. Time to clean house. We could get
       fancy and remove entries strategically... or we can nuke it
       and start over. Overflow should be rare with most
       workloads, so we go with the latter for now.
     */
    thread_revoke_caches(om);
    rval = tls->caches.find_and_emplace(f, f);
    ASSERT(not rval.second);
  }

  return rval.first;
}

OID thread_allocate(sm_oid_mgr_impl *om, FID f) {
  // correct cache entry definitely exists now... but may be empty
  auto it = thread_cache(om, f);
  ASSERT(it->f == f);
  if (not it->nentries) {
    om->lock_file(f);
    DEFER(om->unlock_file(f));
    auto *alloc = om->get_allocator(f);
    if (not alloc->fill_cache(&*it)) {
      auto cbump = alloc->propose_capacity(1);
      oid_array *oa = om->get_array(f);
      oa->ensure_size(cbump);
      alloc->head.capacity_mark = cbump;
      alloc->fill_cache(&*it);
    }
    ASSERT(it->nentries);
  }
  return it->entries[--it->nentries];
}

void thread_free(sm_oid_mgr_impl *om, FID f, OID o) {
  // cache entry exists, but may be full
  auto it = thread_cache(om, f);
  if (not it->space_remaining()) {
    om->lock_file(it->f);
    DEFER(om->unlock_file(it->f));
    auto *alloc = om->get_allocator(it->f);
    alloc->drain_cache(&*it);
    ASSERT(it->space_remaining());
  }

  it->entries[it->nentries++] = o;
}

fat_ptr oid_array::make() {
  /* Ask for a dynarray with size 1 byte, which gets rounded up to
     one page.
   */
  dynarray d = make_oid_dynarray();
  void *ptr = d.data();
  auto *rval = new (ptr) oid_array(std::move(d));
  return fat_ptr::make(rval, 1);
}

void oid_array::destroy(oid_array *oa) { oa->~oid_array(); }

oid_array::oid_array(dynarray &&self) : _backing_store(std::move(self)) {
  ASSERT(this == (void *)_backing_store.data());
}

void oid_array::ensure_size(size_t n) {
  _backing_store.ensure_size(OFFSETOF(oid_array, _entries[n]));
}

sm_oid_mgr_impl::sm_oid_mgr_impl() {
  /* Bootstrap the OBJARRAY, which contains everything (including
     itself). Then seed it with OID arrays for allocators and
     metadata
   */
  // TODO: DEFER deletion of these arrays if constructor throws
  fat_ptr ptr = oid_array::make();
  files = ptr;
  *files->get(OBJARRAY_FID) = ptr;
  ASSERT(oid_get(OBJARRAY_FID, OBJARRAY_FID) == ptr);
  oid_put(OBJARRAY_FID, ALLOCATOR_FID, oid_array::make());
  oid_put(OBJARRAY_FID, METADATA_FID, oid_array::make());

  /* Instantiate the FID allocator and pre-allocate internal files.
   */
  auto *alloc = sm_allocator::make();
  alloc->head.hiwater_mark = FIRST_FREE_FID;
  auto cap = alloc->head.capacity_mark;
  oid_array *oa = ptr;
  oa->ensure_size(cap);
  auto p = fat_ptr::make(alloc, 1);
  oid_put(ALLOCATOR_FID, OBJARRAY_FID, p);
  ASSERT(get_allocator(OBJARRAY_FID) == p);

  // initialize (or reclaim) thread-local machinery
  oid_mutex.lock();
  DEFER(oid_mutex.unlock());
  DIE_IF(master, "Multiple OID managers found.");
  if (not threads) {
    auto fini = [](void *arg) -> void {
      auto *om = (sm_oid_mgr_impl *)arg;
      if (om == master) thread_fini(om);
    };

    threads = make_new();

    int err = pthread_key_create(&pthread_key, fini);
    DIE_IF(err, "pthread_key_create failed with errno=%d", errno);
  }
  master = this;
}

sm_oid_mgr_impl::~sm_oid_mgr_impl() {
  oid_mutex.lock();
  DEFER(oid_mutex.unlock());

  master = NULL;

  /* Nuke the contents of any lingering thread-local caches for this
     FID. Don't remove the entry because that would require grabbing
     more mutexes.
  */

  for (auto &kv : *threads) {
    auto *tdata = kv.second;
    tdata->mutex.lock();
    DEFER(tdata->mutex.unlock());
    for (auto &tc : tdata->caches) tc.nentries = 0;
  }
}

FID sm_oid_mgr_impl::create_file(bool needs_alloc) {
  /* Let the thread-local allocator choose an FID; with that in
     hand, we create the corresponding OID array and allocator.
   */
  auto f = thread_allocate(this, OBJARRAY_FID);
  ASSERT(not file_exists(f));
  auto ptr = oid_array::make();
  oid_put(OBJARRAY_FID, f, ptr);
  if (needs_alloc) {
    auto *alloc = sm_allocator::make();
    auto p = fat_ptr::make(alloc, 1);
    oid_put(ALLOCATOR_FID, f, p);

    auto cap = alloc->head.capacity_mark;
    oid_array *oa = ptr;
    oa->ensure_size(cap);
  }
  return f;
}

/* Create a file with given FID f.
 * WARNING: this is for recovery use only; there's no CC for it.
 * Caller has full responsibility.
 */
void sm_oid_mgr_impl::recreate_file(FID f) {
  if (file_exists(f)) {
    LOG(FATAL) << "File already exists. Is this a secondary index?";
  }
  auto ptr = oid_array::make();
  oid_put(OBJARRAY_FID, f, ptr);
  ASSERT(file_exists(f));
  DLOG(INFO) << "[Recovery] recreate file " << f;
  // Allocator doesn't exist for now, need to call
  // recreate_allocator(f) later after we figured
  // out the high watermark by scanning the log.
}

/* Create the allocator for a given FID f.
 * This also bootstraps the OID array that contains FIDs.
 * WARNING: for recovery only; no CC for it.
 * Caller has full responsibility.
 */
void sm_oid_mgr_impl::recreate_allocator(FID f, OID m) {
  static std::mutex recreate_lock;

  recreate_lock.lock();
  DEFER(recreate_lock.unlock());

  // Callers might be
  // 1. oidmgr when recovering from a chkpt
  // 2. logmgr when recovering from the log
  // Whomever calls later will need to avoid allocating new allocators
  sm_allocator *alloc = (sm_allocator *)oid_get(ALLOCATOR_FID, f).offset();
  if (not alloc) {
    alloc = sm_allocator::make();
    auto p = fat_ptr::make(alloc, 1);
#ifndef NDEBUG
    // Special case: internal files are already initialized
    if (f != ALLOCATOR_FID and f != OBJARRAY_FID and f != METADATA_FID)
      ASSERT(oid_get(ALLOCATOR_FID, f) == NULL_PTR);
#endif
    oid_put(ALLOCATOR_FID, f, p);
  } else {
    // else the oidmgr should already recreated this allocator for f
    // when recovering from a chkpt file, then if we're entering here
    // that means we got some newer himark by scanning the log.
    // But note this new himark might be larger than the one we got
    // from the chkpt: this is the one that really got allocated, while
    // the one we got from chkpt was the real *himark* at runtime -
    // not all of the OIDs below it were allocated,  so chances are we
    // will still find the existing mark is high enough already, unless
    // after the chkpt the OID cache was depleted and we allocated after
    // refilling it.
  }

  // if m == 0, then the table hasn't been inserted, no need to mess with it
  if (not m) return;

  if (m <= alloc->head.capacity_mark and m <= alloc->head.hiwater_mark) return;

  // Set capacity_mark = hiwater_mark = m, the cache machinery
  // will do the rest (note the +64 to avoid duplicates)
  alloc->head.capacity_mark = alloc->head.hiwater_mark = (m + 64);
  ASSERT(file_exists(f));
  fat_ptr ptr = oid_get(OBJARRAY_FID, f);
  oid_array *oa = ptr;
  ASSERT(oa);
  oa->ensure_size(alloc->head.capacity_mark);
  DLOG(INFO) << "[Recovery] recreate allocator " << f << ", himark=" << m;
}

void sm_oid_mgr_impl::destroy_file(FID f) {
  /* As with most resources, a file should only be reclaimed once it
     has not only been deleted logically, but also become
     unreachable by any in-flight transaction. At that point, only
     GC will see it and so there is no need for low-level CC, other
     than avoiding structural hazards in the allocator that manages
     FIDs.
   */
  {
    /* Nuke the contents of any lingering thread-local caches for
       this FID. Don't remove the entry because that would require
       grabbing more mutexes.
     */
    oid_mutex.lock();
    DEFER(oid_mutex.unlock());

    for (auto &kv : *threads) {
      auto *tdata = kv.second;
      tdata->mutex.lock();
      DEFER(tdata->mutex.unlock());
      auto it = tdata->caches.find(f);
      if (it != tdata->caches.end()) it->nentries = 0;
    }
  }
  {
    fat_ptr *ptr = oid_access(OBJARRAY_FID, f);
    oid_array *oa = *ptr;
    ASSERT(oa);
    oid_array::destroy(oa);
    *ptr = NULL_PTR;
  }
  {
    fat_ptr *ptr = oid_access(ALLOCATOR_FID, f);
    sm_allocator *alloc = *ptr;
    if (alloc) {
      sm_allocator::destroy(alloc);
      *ptr = NULL_PTR;
    }
  }
  // TODO: delete metadata? or force caller to do it before now?

  // one allocator controls all three files
  thread_free(this, OBJARRAY_FID, f);
}

oid_array *sm_oid_mgr::get_array(FID f) { return get_impl(this)->get_array(f); }

void sm_oid_mgr::create() {
  // Create an empty oidmgr, with initial internal files
  oidmgr = new sm_oid_mgr_impl{};
  oidmgr->dfd = dirent_iterator(config::log_dir.c_str()).dup();
}

void sm_oid_mgr::PrimaryTakeChkpt() {
  ASSERT(!config::is_backup_srv());
  // Now the real work. The format of a chkpt file is:
  // [number of indexes]
  // [primary index 1 name length, name, tuple/key FID, himark]
  // [primary index 2 name length, name, tuple/key FID, himark]
  // ...
  // [2nd index 1 name length, name, FID, himark]
  // [2nd index 2 name length, name, FID, himark]
  // ...
  //
  // [index 1 himark]
  // [index 1 tuple_fid, key_fid]
  // [OID1, key and/or data]
  // [OID2, key and/or data]
  // [index 1 himark]
  // ...
  // same thing for index 2
  // ...

  // Write the number of indexes
  // TODO(tzwang): handle dynamically created tables/indexes
  uint64_t chkpt_size = 0;
  uint32_t num_idx = IndexDescriptor::NumIndexes();
  chkptmgr->write_buffer(&num_idx, sizeof(uint32_t));
  chkpt_size += sizeof(uint32_t);

  // Write details about each primary index, then secondary index
  // so that during recovery we have primary indexes first and then
  // 2nd indexes can refer to the FID of the corresponding primary.
  bool handling_2nd = false;
iterate_index:
  for (auto &fm : IndexDescriptor::name_map) {
    IndexDescriptor *id = fm.second;
    if (!((id->IsPrimary() && !handling_2nd) || (!id->IsPrimary() && handling_2nd))) {
      continue;
    }
    size_t len = id->GetName().length();
    FID tuple_fid = id->GetTupleFid();
    FID key_fid = id->GetKeyFid();
    auto *alloc = get_impl(this)->get_allocator(tuple_fid);
    OID himark = alloc->head.hiwater_mark;

    // [Name length, name, tuple/key FID, himark]
    chkptmgr->write_buffer(&len, sizeof(size_t));
    chkptmgr->write_buffer((void *)id->GetName().c_str(), len);
    chkptmgr->write_buffer(&tuple_fid, sizeof(FID));
    chkptmgr->write_buffer(&key_fid, sizeof(FID));
    chkptmgr->write_buffer(&himark, sizeof(OID));
    chkpt_size += (sizeof(size_t) + len + sizeof(FID) + sizeof(OID));
  }
  if (!handling_2nd) {
    handling_2nd = true;
    goto iterate_index;
  }
  LOG(INFO) << "[Checkpoint] header size: " << chkpt_size;

  // Write keys and/or tuples for each index, primary first
  for (auto &fm : IndexDescriptor::name_map) {
    IndexDescriptor *id = fm.second;
    FID tuple_fid = id->GetTupleFid();
    // Find the high watermark of this file and dump its
    // backing store up to the size of the high watermark
    auto *alloc = get_impl(this)->get_allocator(tuple_fid);
    OID himark = alloc->head.hiwater_mark;

    // Write himark
    chkptmgr->write_buffer(&himark, sizeof(OID));

    // Write the tuple FID to note which table these OIDs to follow belongs to
    chkptmgr->write_buffer(&tuple_fid, sizeof(FID));

    // Key FID
    FID key_fid = id->GetKeyFid();
    chkptmgr->write_buffer(&key_fid, sizeof(FID));

    auto *oa = fm.second->GetTupleArray();
    auto *ka = fm.second->GetKeyArray();
    ASSERT(oa);
    ASSERT(ka);

    // Now write the [OID, payload] pairs. Record both OID and keys for
    // primary indexes; keys only for 2nd indexes.
    uint64_t nrecords = 0;
    bool is_primary = id->IsPrimary();
    for (OID oid = 0; oid < himark; oid++) {
      // Checkpoints need not be consistent: grab the latest committed
      // version and leave.
      fat_ptr ptr = oid_get(oa, oid);
    retry:
      if (not ptr.offset()) {
        continue;
      }

      Object *obj = (Object *)ptr.offset();
      fat_ptr next = obj->GetNextVolatile();
      fat_ptr clsn = obj->GetClsn();
      if (clsn == NULL_PTR) {
        // Stepping on a dead tuple, see details in oid_get_version.
        ptr = oid_get(oa, oid);
        goto retry;
      } else if (clsn.asi_type() != fat_ptr::ASI_LOG) {
        // Someone is still working on this version
        ptr = next;
        goto retry;
      }

      ASSERT(obj->GetClsn().offset());
      ASSERT(obj->GetClsn().asi_type() == fat_ptr::ASI_LOG);

      fat_ptr pdest = obj->GetPersistentAddress();
      if (pdest.offset() == 0) {
        // must be a delete, skip it
        continue;
      }

      nrecords++;
      // Write OID
      chkptmgr->write_buffer(&oid, sizeof(OID));

      // Key
      fat_ptr key_ptr = oid_get(ka, oid);
      varstr *key = (varstr *)key_ptr.offset();
      ALWAYS_ASSERT(key);
      ALWAYS_ASSERT(key->l);
      ALWAYS_ASSERT(key->p);
      chkptmgr->write_buffer(&key->l, sizeof(uint32_t));
      chkptmgr->write_buffer(key->data(), key->size());

      // Tuple data if it's the primary index
      if (fm.second->IsPrimary()) {
        if (!obj->IsInMemory()) {
          obj->Pin();
        }
        uint8_t size_code = ptr.size_code();
        ALWAYS_ASSERT(size_code != INVALID_SIZE_CODE);
        auto data_size = decode_size_aligned(size_code);
        data_size = decode_size_aligned(size_code);
        ALWAYS_ASSERT(obj->GetPinnedTuple()->size <=
                      data_size - sizeof(Object) - sizeof(dbtuple));
        chkptmgr->write_buffer(&size_code, sizeof(uint8_t));
        // It's already there if we're digging out a tuple from a previous chkpt
        chkptmgr->write_buffer((char *)obj, data_size);
        ALWAYS_ASSERT(obj->GetClsn().asi_type() == fat_ptr::ASI_LOG);
        ALWAYS_ASSERT(obj->GetPinnedTuple()->size <=
                      data_size - sizeof(Object) - sizeof(dbtuple));
        chkpt_size += (sizeof(OID) + sizeof(uint8_t) + data_size);
      }
    }
    // Write himark to denote end
    chkptmgr->write_buffer(&himark, sizeof(OID));
    LOG(INFO) << "[Checkpoint] " << id->GetName() << " (" << tuple_fid << ", "
              << key_fid << ") himark=" << himark << ", wrote " << chkpt_size
              << " bytes, " << nrecords << " records";
  }
  chkptmgr->sync_buffer();
}

sm_allocator *sm_oid_mgr::get_allocator(FID f) {
  return get_impl(this)->get_allocator(f);
}

void sm_oid_mgr::start_warm_up() {
  std::thread t(sm_oid_mgr::warm_up);
  t.detach();
}

void sm_oid_mgr::warm_up() {
  // REVISIT
  /*
    ASSERT(oidmgr);
    std::cout << "[Warm-up] Started\n";
    {
        util::scoped_timer t("data warm-up");
        // Go over each OID entry and ensure_tuple there
        for (auto &fm : IndexDescriptor::fid_map) {
            auto* id = fm.second;
            auto *alloc = oidmgr->get_allocator(id->GetTupleFid());
            OID himark = alloc->head.hiwater_mark;
            FID fid = fm.first;
            oid_array *oa = oidmgr->get_array(fid);
            for (OID oid = 0; oid < himark; oid++)
                oidmgr->ensure_tuple(oa, oid, 0);
        }
    }
    */
}

FID sm_oid_mgr::create_file(bool needs_alloc) {
  return get_impl(this)->create_file(needs_alloc);
}

void sm_oid_mgr::recreate_file(FID f) {
  return get_impl(this)->recreate_file(f);
}

void sm_oid_mgr::recreate_allocator(FID f, OID m) {
  return get_impl(this)->recreate_allocator(f, m);
}

bool sm_oid_mgr::file_exists(FID f) { return get_impl(this)->file_exists(f); }

void sm_oid_mgr::destroy_file(FID f) { get_impl(this)->destroy_file(f); }

OID sm_oid_mgr::alloc_oid(FID f) {
/* FIXME (tzwang): OID=0's original intent was to denote
 * NULL, but I'm not sure what it's for currently; probably
 * it's used by the index (e.g., if we have OID=0 recorded
 * in some leaf node, that means the tuple was deleted).
 * So I just skip OID=1 to be allocated here. Need to find
 * out how the index treats OID=0. Meanwhile, it's totally
 * OK for the version chain's OID array to use OID=0.
 */
alloc:
  auto o = thread_allocate(get_impl(this), f);
  if (unlikely(o == 0)) goto alloc;

  ASSERT(oid_get(f, o) == NULL_PTR);
  return o;
}

fat_ptr sm_oid_mgr::free_oid(FID f, OID o) {
  auto *self = get_impl(this);
  auto *ptr = self->oid_access(f, o);
  auto rval = *ptr;
  *ptr = NULL_PTR;
  thread_free(self, f, o);
  return rval;
}

fat_ptr sm_oid_mgr::oid_get(FID f, OID o) {
  return *get_impl(this)->oid_access(f, o);
}

fat_ptr *sm_oid_mgr::oid_get_ptr(FID f, OID o) {
  return get_impl(this)->oid_access(f, o);
}

void sm_oid_mgr::oid_put(FID f, OID o, fat_ptr p) {
  *get_impl(this)->oid_access(f, o) = p;
}

void sm_oid_mgr::oid_put_new(FID f, OID o, fat_ptr p) {
  auto *entry = get_impl(this)->oid_access(f, o);
  ALWAYS_ASSERT(*entry == NULL_PTR);
  *entry = p;
}

void sm_oid_mgr::oid_put_new_if_absent(FID f, OID o, fat_ptr p) {
  auto *entry = get_impl(this)->oid_access(f, o);
  if (*entry == NULL_PTR) {
    *entry = p;
  }
}

#if defined(HYU_ZIGZAG) || defined(HYU_VRIDGY_ONLY)
/* bool @out 	true if success to submit highway chain */
bool sm_oid_mgr::SubmitHighwayChain(Object* new_obj, fat_ptr old_ptr) {
	fat_ptr next_ptr = volatile_read(old_ptr);
	Object* new_object = new_obj;
	Object* next = (Object*)next_ptr.offset();
	uint64_t hw_level;
	uint64_t my_level = (uint64_t)new_object->GetLevel();
	uint64_t watermark = volatile_read(MM::gc_lsn);
	fat_ptr clsn;

	// If coin toss result is tail, get lowest level.
	// v_ridgy is same as next
	if (my_level == 1) {
		clsn = next->GetClsn();

		if (watermark > LSN::from_ptr(clsn).offset())
			return false;

		ASSERT(next->GetClsn().asi_type() == fat_ptr::ASI_LOG);

		new_object->SetHighway(next_ptr);
		new_object->SetHighwayClsn(next->GetClsn());
		new_object->SetHighwayLevel(next->GetLevel());
		
		return true;
	}

	// If coin toss result is head, go stacking. We have to find v_ridgy through
	// traversing next's v_ridgy. If a version's level is same or bigger than my
	// level, connecting v_ridgy.
	while (1) {
		hw_level = (uint64_t)next->GetHighwayLevel();

		if (hw_level >= my_level) {

			clsn = next->GetHighwayClsn();

			if (clsn.asi_type() != fat_ptr::ASI_LOG ||
					watermark > LSN::from_ptr(clsn).offset())
				return false;
		
			// if new version try to set highway with GCed object, stop
			Object* highway = (Object*)(next->GetHighway().offset());
			if (highway->GetClsn()._ptr == 0 || highway->GetClsn().asi_type() != fat_ptr::ASI_LOG ||
					LSN::from_ptr(highway->GetClsn()).offset() != LSN::from_ptr(clsn).offset()) {
				return false;
			}

			if ((uint64_t)highway->GetLevel() < my_level) return false;

			new_object->SetHighway(next->GetHighway());
			new_object->SetHighwayClsn(highway->GetClsn());
			new_object->SetHighwayLevel(highway->GetLevel());
			//new_object->SetHighwayClsn(next->GetHighwayClsn());
			//new_object->SetHighwayLevel(next->GetHighwayLevel());
			return true;
		} else {
			next_ptr = next->GetHighway();
			if (next_ptr == NULL_PTR)
				break;

			Object* highway = (Object*)(next->GetHighway().offset());
			if (highway->GetClsn() == NULL_PTR || highway->GetClsn().asi_type() != fat_ptr::ASI_LOG ||
					LSN::from_ptr(highway->GetClsn()).offset() != LSN::from_ptr(next->GetHighwayClsn()).offset()) {
				return false;
			}

			next = (Object*)next_ptr.offset();

			uint64_t hwlv = (uint64_t)next->GetHighwayLevel();
			if (hwlv < hw_level)
				break;
		}
	}
	return false;
}
#endif /* HYU_ZIGZAG || HYU_VRIDGY_ONLY */

fat_ptr sm_oid_mgr::PrimaryTupleUpdate(FID f, OID o, const varstr *value,
                                       TXN::xid_context *updater_xc,
                                       fat_ptr *new_obj_ptr) {
  return PrimaryTupleUpdate(get_impl(this)->get_array(f), o, value, updater_xc,
                            new_obj_ptr);
}

// For primary server only - guaranteed to have no gaps between versions,
// i.e., pdest_next_ matches volatile_next_.
fat_ptr sm_oid_mgr::PrimaryTupleUpdate(oid_array *oa, OID o,
                                       const varstr *value,
                                       TXN::xid_context *updater_xc,
                                       fat_ptr *new_obj_ptr) {
  ASSERT(!config::is_backup_srv() || (config::command_log && config::replay_threads));
	auto *ptr = oa->get(o);
start_over:
  fat_ptr head = volatile_read(*ptr);
  ASSERT(head.asi_type() == 0);
  Object *old_desc = (Object *)head.offset();
	Object *for_debug = old_desc;
  ASSERT(old_desc != nullptr);
  ASSERT(head.size_code() != INVALID_SIZE_CODE);
  dbtuple *version = (dbtuple *)old_desc->GetPayload();
  bool overwrite = false;

	if (old_desc == nullptr) {
		return NULL_PTR;
	}
  auto clsn = old_desc->GetClsn();
  if (clsn == NULL_PTR) {
    // stepping on an unlinked version?
    goto start_over;
  } else if (clsn.asi_type() == fat_ptr::ASI_XID) {
    /* Grab the context for this XID. If we're too slow,
       the context might be recycled for a different XID,
       perhaps even *while* we are reading the
       context. Copy everything we care about and then
       (last) check the context's XID for a mismatch that
       would indicate an inconsistent read. If this
       occurs, just start over---the version we cared
       about is guaranteed to have a LSN now.
     */
    auto holder_xid = XID::from_ptr(clsn);
    XID updater_xid = volatile_read(updater_xc->owner);

    // in-place update case (multiple updates on the same record  by same
    // transaction)
    if (holder_xid == updater_xid) {
      overwrite = true;
      goto install;
    }

    TXN::xid_context *holder = TXN::xid_get_context(holder_xid);
    if (not holder) {
#ifndef NDEBUG
      auto t = old_desc->GetClsn().asi_type();
      ASSERT(t == fat_ptr::ASI_LOG or oid_get(oa, o) != head);
#endif
      goto start_over;
    }
    ASSERT(holder);
    auto state = volatile_read(holder->state);
    auto owner = volatile_read(holder->owner);
    holder = NULL;  // use cached values instead!

    // context still valid for this XID?
    if (unlikely(owner != holder_xid)) {
      goto start_over;
    }
    ASSERT(holder_xid != updater_xid);
    if (state == TXN::TXN_CMMTD) {
      // Allow installing a new version if the tx committed (might
      // still hasn't finished post-commit). Note that the caller
      // (ie do_tree_put) should look at the clsn field of the
      // returned version (prev) to see if this is an overwrite
      // (ie xids match) or not (xids don't match).
      ASSERT(holder_xid != updater_xid);
      goto install;
    }
    return NULL_PTR;
  }
  // check dirty writes
  else {
    ASSERT(clsn.asi_type() == fat_ptr::ASI_LOG);
#ifndef RC
    // First updater wins: if some concurrent tx committed first,
    // I have to abort. Same as in Oracle. Otherwise it's an isolation
    // failure: I can modify concurrent transaction's writes.
    if (LSN::from_ptr(clsn).offset() >= updater_xc->begin) return NULL_PTR;
#endif
    goto install;
  }

install:
  // remove uncommitted overwritten version
  // (tx's repetitive updates, keep the latest one only)
  // Note for this to be correct we shouldn't allow multiple txs
  // working on the same tuple at the same time.

  *new_obj_ptr = Object::Create(value, false, updater_xc->begin_epoch);
  ASSERT(new_obj_ptr->asi_type() == 0);
  Object *new_object = (Object *)new_obj_ptr->offset();
  new_object->SetClsn(updater_xc->owner.to_ptr());
	// HYU_GC
	//new_object->HYU_gc_candidate_clsn_ = volatile_read(MM::gc_lsn);
	// HYU_GC end
  if (overwrite) {
    new_object->SetNextPersistent(old_desc->GetNextPersistent());
    new_object->SetNextVolatile(old_desc->GetNextVolatile());		
#if defined(HYU_ZIGZAG) || defined(HYU_VRIDGY_ONLY)
		new_object->SetHighway(old_desc->GetHighway());
		new_object->SetHighwayClsn(old_desc->GetHighwayClsn());
		new_object->SetLevel(old_desc->GetLevel());
		new_object->SetHighwayLevel(old_desc->GetHighwayLevel());
		new_object->rec_id = old_desc->rec_id;
#endif /* HYU_ZIGZAG || HYU_VRIDGY_ONLY */
    // I already claimed it, no need to use cas then
    volatile_write(ptr->_ptr, new_obj_ptr->_ptr);
    __sync_synchronize();
    return head;
  } else {
    fat_ptr pa = old_desc->GetPersistentAddress();
    while (pa == NULL_PTR) {
      pa = old_desc->GetPersistentAddress();
    }
    new_object->SetNextPersistent(pa);
    new_object->SetNextVolatile(head);

#if defined(HYU_ZIGZAG) || defined(HYU_VRIDGY_ONLY)
#ifdef HYU_EVAL /* HYU_EVAL */
		int64_t start_time, latency;
		struct timespec vridgy_time;
		if (!updater_xc->xct->check) {
			clock_gettime(CLOCK_MONOTONIC, &vridgy_time);
			start_time = (int64_t)vridgy_time.tv_nsec;
		}
#endif /* HYU_EVAL */
			// In this case, we have to set highway shortcut
			int go_up = new_object->TossCoin(pa._ptr);
			uint8_t lv;
			if (go_up) {
				lv = old_desc->GetLevel();
				uint64_t chk = (uint64_t)lv;
				if (chk == MAX_LEVEL)
					lv = 1;
				else
					lv++;

				new_object->SetLevel(lv);
			} else {
				lv = 1;
				new_object->SetLevel(lv);
			}

			bool submit = SubmitHighwayChain(new_object, head);
			new_object->rec_id = o;
			__sync_synchronize();
#endif /* HYU_ZIGZAG || HYU_VRIDGY_ONLY */

    if (__sync_bool_compare_and_swap(&ptr->_ptr, head._ptr,
                                     new_obj_ptr->_ptr)) {
#ifdef HYU_ZIGZAG /* HYU_ZIGZAG */
#ifdef HYU_EVAL /* HYU_EVAL */
			if (!updater_xc->xct->check) {
				clock_gettime(CLOCK_MONOTONIC, &vridgy_time);
				latency = (int64_t)vridgy_time.tv_nsec - start_time;
				updater_xc->xct->vridgy_cost = latency;
				updater_xc->xct->check = true;
			}
#endif /* HYU_EVAL */
#endif /* HYU_ZIGZAG */
      // Succeeded installing a new version, now only I can modify the
      // chain, try recycle some objects
      if (config::enable_gc) {
        MM::gc_version_chain(ptr);
      }
      return head;
    } else {
      MM::deallocate(*new_obj_ptr);
    }
  }
  return NULL_PTR;
}

dbtuple *sm_oid_mgr::oid_get_latest_version(FID f, OID o) {
  return oid_get_latest_version(get_impl(this)->get_array(f), o);
}

#ifdef HYU_ZIGZAG /* HYU_ZIGZAG */
#ifdef HYU_DEBUG /* HYU_DEBUG */
dbtuple *sm_oid_mgr::oid_get_version_zigzag_debug(FID f, OID o, TXN::xid_context *visitor_xc, uint64_t *cnt) {
  ASSERT(f);
  return oid_get_version_zigzag_debug(get_impl(this)->get_array(f), o, visitor_xc, cnt);
}
#endif /* HYU_DEBUG */
dbtuple *sm_oid_mgr::oid_get_version_zigzag(FID f, OID o, TXN::xid_context *visitor_xc) {
  ASSERT(f);
  return oid_get_version_zigzag(get_impl(this)->get_array(f), o, visitor_xc);
}
#endif /* HYU_ZIGZAG */

#ifdef HYU_DEBUG /* HYU_DEBUG */
dbtuple *sm_oid_mgr::oid_get_version_debug(FID f, OID o, TXN::xid_context *visitor_xc, uint64_t *cnt) {
  ASSERT(f);
  return oid_get_version_debug(get_impl(this)->get_array(f), o, visitor_xc, cnt);
}
#endif /* HYU_DEBUG */
dbtuple *sm_oid_mgr::oid_get_version(FID f, OID o, TXN::xid_context *visitor_xc) {
  ASSERT(f);
  return oid_get_version(get_impl(this)->get_array(f), o, visitor_xc);
}

dbtuple *sm_oid_mgr::BackupGetVersion(oid_array *ta, oid_array *pa, OID o,
                                      TXN::xid_context *xc) {
  if (config::full_replay || config::command_log) {
		return oid_get_version(ta, o, xc);
  }
  fat_ptr pdest_head_ptr = NULL_PTR;
retry:
  // See if we can find a fresh enough version in the tuple array
  fat_ptr active_head_ptr = volatile_read(*ta->get(o));
  ASSERT(active_head_ptr.asi_type() == 0);
  Object *active_head_obj = (Object *)active_head_ptr.offset();
  uint64_t active_head_lsn =
      active_head_obj == nullptr ? 0 : active_head_obj->GetClsn().offset();
  ASSERT(!active_head_obj ||
         active_head_obj->GetClsn().offset() ==
             active_head_obj->GetPersistentAddress().offset());
  if (active_head_lsn >= xc->begin) {
    // First version not visible to me, so no need to look at the pdest
    // array, versions indexed by the tuple array are enough.
		return oid_get_version(ta, o, xc);
  } else {
    // First version visible to me, but not sure if there will be newer
    // versions available for me to read, must look at the pdest array
    // and dig out them from the log.
    // Note: ptrs point to the log directly, making the lsns comparable
    if (pdest_head_ptr == NULL_PTR) {
      // Don't refresh pdest ptr, to save some resource
      pdest_head_ptr = volatile_read(*pa->get(o));
    }
    fat_ptr ptr = pdest_head_ptr;
    ASSERT(ptr.offset() == 0 || ptr.offset() >= active_head_lsn);
    if (ptr.offset() == 0 || ptr.offset() == active_head_lsn) {
      // Nothing new in the pdest array
      return active_head_obj ? active_head_obj->GetPinnedTuple() : nullptr;
    }

    ALWAYS_ASSERT(ptr.asi_type() == fat_ptr::ASI_LOG);
    ALWAYS_ASSERT(ptr.offset() > active_head_lsn);

    // Dig out the first version until the latest one visible to me
    Object *prev_obj = nullptr;
    fat_ptr install_ptr = NULL_PTR;
    Object *ret_obj = active_head_obj;
    while (ptr.offset() > active_head_lsn) {
      ASSERT(ptr.asi_type() == fat_ptr::ASI_LOG);  // Digging things out
      size_t sz = sizeof(Object) + sizeof(dbtuple) +
                  decode_size_aligned(ptr.size_code());
      sz = align_up(sz);
      Object *obj = (Object *)MM::allocate(sz);
      // FIXME(tzwang): figure out how GC/epoch works with this
      new (obj) Object(ptr, NULL_PTR, 0, false);  // Update next_ later
      // TODO(tzawng): allow pinning the header part only (ie the varstr
      // embedded in the payload) as the only purpose of Pin() here is to
      // get to know the pdest of the overwritten version. (perhaps doesn't
      // matter especially if using disk/SSD).
      ASSERT(obj->GetNextPersistent() == NULL_PTR);
      obj->Pin();  // obj.next_pdest becomes available after Pin()
      ASSERT(obj->GetClsn().offset());
      ASSERT(obj->GetClsn().offset() == obj->GetPersistentAddress().offset());
      ASSERT(obj->GetNextPersistent() == NULL_PTR ||
             obj->GetNextPersistent().asi_type() == fat_ptr::ASI_LOG);

      // Setup volatile backward pointers
      obj->SetNextVolatile(active_head_ptr);  // Default, might change later
      if (prev_obj) {
        prev_obj->SetNextVolatile(
            fat_ptr::make(obj, encode_size_aligned(sz), 0));
      } else {
        install_ptr = fat_ptr::make(obj, encode_size_aligned(sz), 0);
      }
      uint64_t clsn = obj->GetClsn().offset();
      ASSERT(clsn > active_head_lsn);
      if (xc->begin > clsn) {
        // Done, no need to dig further
        ASSERT(ret_obj == active_head_obj);
        ret_obj = obj;
        break;
      }
      prev_obj = obj;
      ptr = obj->GetNextPersistent();
      ASSERT((active_head_obj && ptr.offset()) || !active_head_obj);
    }
    ASSERT(ptr.offset() == active_head_lsn ||
           ptr.offset() > active_head_lsn && ret_obj != active_head_obj);

    // Install the chain on the tuple array slot (plain write as we locked it)
    ALWAYS_ASSERT(install_ptr != NULL_PTR);
    ALWAYS_ASSERT(install_ptr.asi_type() == 0);

    bool success = __sync_bool_compare_and_swap(
        &ta->get(o)->_ptr, active_head_ptr._ptr, install_ptr._ptr);
    if (!success) {
      fat_ptr to_free = install_ptr;
      while (to_free != active_head_ptr) {
        Object *to_free_obj = (Object *)to_free.offset();
        fat_ptr next = to_free_obj->GetNextVolatile();
        MM::deallocate(to_free);
        to_free = next;
      }
      goto retry;
    }
    return ret_obj ? ret_obj->GetPinnedTuple() : nullptr;
  }
}

void sm_oid_mgr::oid_get_version_backup(fat_ptr &ptr,
                                        fat_ptr &tentative_next,
                                        Object *prev_obj,
                                        Object *&cur_obj,
                                        TXN::xid_context *visitor_xc) {
  fat_ptr prev_next_ptr = NULL_PTR;
  Object *prev_next_obj = NULL_PTR;
  if (prev_obj) {
    ASSERT(prev_obj->GetClsn().offset());
    // See if we can just follow the volatile pointer without touching the
    // log
    prev_next_ptr = prev_obj->GetNextVolatile();
    prev_next_obj = (Object *)prev_next_ptr.offset();
    ASSERT(prev_next_obj->GetClsn().offset() ==
           prev_next_obj->GetPersistentAddress().offset());
    if (prev_next_obj->GetClsn().offset() == prev_obj->GetNextPersistent().offset() ||
        prev_next_obj->GetClsn().offset() >= visitor_xc->begin) {
      // No gap or not visible
      ptr = prev_next_ptr;
    }
  }
  if (ptr.asi_type() == fat_ptr::ASI_LOG) {
    ASSERT(ptr.size_code() != INVALID_SIZE_CODE);
    size_t alloc_sz = align_up(decode_size_aligned(ptr.size_code()) + sizeof(Object));
    cur_obj = (Object *)MM::allocate(alloc_sz);
    new (cur_obj) Object(ptr, NULL_PTR, visitor_xc->begin_epoch, false);
    cur_obj->Pin();  // After this next_pdest_ is valid
    ASSERT(cur_obj->GetClsn().offset());
    ASSERT(prev_obj);
    ASSERT(prev_obj->GetClsn().offset());
    ASSERT(prev_obj->GetClsn().offset() != cur_obj->GetClsn().offset());
    fat_ptr vnext = prev_obj->GetNextVolatile();
    cur_obj->SetNextVolatile(vnext);
    fat_ptr newptr = fat_ptr::make(cur_obj, ptr.size_code(), 0);
    if (!__sync_bool_compare_and_swap(&prev_obj->GetNextVolatilePtr()->_ptr,
                                      vnext._ptr, newptr._ptr)) {
      // If this CAS failed, then it must be somebody else who installed
      // this immediate version
      cur_obj = (Object *)prev_obj->GetNextVolatile().offset();
      ASSERT(cur_obj);
      ASSERT(cur_obj->GetClsn().offset() == ptr.offset());
      ASSERT(cur_obj->GetPersistentAddress().offset() == ptr.offset());
      MM::deallocate(newptr);
    }
  } else {
    ASSERT(ptr.asi_type() == 0);
    cur_obj = (Object *)ptr.offset();
  }
  ASSERT(cur_obj->GetClsn().offset());
  ASSERT(!prev_obj || prev_obj->GetClsn().offset());
  ASSERT(!prev_obj ||
         prev_obj->GetClsn().offset() > cur_obj->GetClsn().offset());
  tentative_next = cur_obj->GetNextPersistent();
  ASSERT(tentative_next == NULL_PTR ||
         tentative_next.asi_type() == fat_ptr::ASI_LOG);
}

#ifdef HYU_DEBUG /* HYU_DEBUG */
// For tuple arrays only, i.e., entries are guaranteed to point to Objects.
dbtuple *sm_oid_mgr::oid_get_version_debug(oid_array *oa, OID o,
                                    			TXN::xid_context *visitor_xc,
																					uint64_t *cnt) {
  fat_ptr *entry = oa->get(o);
	uint64_t point_cnt = 0;
start_over:
  fat_ptr ptr = volatile_read(*entry);
  ASSERT(ptr.asi_type() == 0);
  Object *prev_obj = nullptr;
  while (ptr.offset()) {
    Object *cur_obj = nullptr;
    // Must read next_ before reading cur_obj->_clsn:
    // the version we're currently reading (ie cur_obj) might be unlinked
    // and thus recycled by the memory allocator at any time if it's not
    // a committed version. If so, cur_obj->_next will be pointing to some
    // other object in the allocator's free object pool - we'll probably
    // end up at la-la land if we followed this _next pointer value...
    // Here we employ some flavor of OCC to solve this problem:
    // the aborting transaction that will unlink cur_obj will update
    // cur_obj->_clsn to NULL_PTR, then deallocate(). Before reading
    // cur_obj->_clsn, we (as the visitor), first dereference pp to get
    // a stable value that "should" contain the right address of the next
    // version. We then read cur_obj->_clsn to verify: if it's NULL_PTR
    // that means we might have read a wrong _next value that's actually
    // pointing to some irrelevant object in the allocator's memory pool,
    // hence must start over from the beginning of the version chain.
    fat_ptr tentative_next = NULL_PTR;
    // If this is a backup server, then must see persistent_next to find out
    // the **real** overwritten version.
    if (config::is_backup_srv() && !config::command_log) {
      oid_get_version_backup(ptr, tentative_next, prev_obj, cur_obj, visitor_xc);
    } else {
      ASSERT(ptr.asi_type() == 0);
      cur_obj = (Object *)ptr.offset();
      tentative_next = cur_obj->GetNextVolatile();
      ASSERT(tentative_next.asi_type() == 0);
    }

    bool retry = false;
    bool visible = TestVisibility(cur_obj, visitor_xc, retry);
    if (retry) {
      goto start_over;
    }
    if (visible) {
			// debug
			point_cnt++;
			*cnt = point_cnt;

      return cur_obj->GetPinnedTuple();
    }
    ptr = tentative_next;
    prev_obj = cur_obj;
		// debug
		point_cnt++;
  }
	// debug
	point_cnt++;
	*cnt = point_cnt;
  
	return nullptr;  // No Visible records
}

#endif /* HYU_DEBUG */

#ifdef HYU_EVAL_2 /* HYU_EVAL_2 */
// For tuple arrays only, i.e., entries are guaranteed to point to Objects.
dbtuple *sm_oid_mgr::oid_get_version_eval(oid_array *oa, OID o,
                                    TXN::xid_context *visitor_xc) {
  fat_ptr *entry = oa->get(o);
start_over:
  fat_ptr ptr = volatile_read(*entry);
  ASSERT(ptr.asi_type() == 0);
  Object *prev_obj = nullptr;
	uint64_t prev_level = 0;
	FILE* fp = fopen("chain_stack.data", "w+");
  while (ptr.offset()) {
    Object *cur_obj = nullptr;
		uint64_t cur_level = 0;
    // Must read next_ before reading cur_obj->_clsn:
    // the version we're currently reading (ie cur_obj) might be unlinked
    // and thus recycled by the memory allocator at any time if it's not
    // a committed version. If so, cur_obj->_next will be pointing to some
    // other object in the allocator's free object pool - we'll probably
    // end up at la-la land if we followed this _next pointer value...
    // Here we employ some flavor of OCC to solve this problem:
    // the aborting transaction that will unlink cur_obj will update
    // cur_obj->_clsn to NULL_PTR, then deallocate(). Before reading
    // cur_obj->_clsn, we (as the visitor), first dereference pp to get
    // a stable value that "should" contain the right address of the next
    // version. We then read cur_obj->_clsn to verify: if it's NULL_PTR
    // that means we might have read a wrong _next value that's actually
    // pointing to some irrelevant object in the allocator's memory pool,
    // hence must start over from the beginning of the version chain.
    fat_ptr tentative_next = NULL_PTR;
    // If this is a backup server, then must see persistent_next to find out
    // the **real** overwritten version.
    if (config::is_backup_srv() && !config::command_log) {
      oid_get_version_backup(ptr, tentative_next, prev_obj, cur_obj, visitor_xc);
    } else {
      ASSERT(ptr.asi_type() == 0);
      cur_obj = (Object *)ptr.offset();
			cur_level = cur_obj->GetLevel();
      tentative_next = cur_obj->GetNextVolatile();
      ASSERT(tentative_next.asi_type() == 0);
    }

    bool retry = false;
    bool visible = TestVisibility(cur_obj, visitor_xc, retry);
    if (retry) {
      goto start_over;
    }
    if (visible) {
			fclose(fp);
      return cur_obj->GetPinnedTuple();
    }
		if (prev_level == 1) {
			fprintf(fp, "%lu\n", cur_level);
			fflush(fp);
		}
    ptr = tentative_next;
    prev_obj = cur_obj;
		prev_level = cur_level;
  }
  
	fclose(fp);
	return nullptr;  // No Visible records
}
#endif /* HYU_EVAL_2 */

// For tuple arrays only, i.e., entries are guaranteed to point to Objects.
dbtuple *sm_oid_mgr::oid_get_version(oid_array *oa, OID o,
                                    TXN::xid_context *visitor_xc) {
  fat_ptr *entry = oa->get(o);
start_over:
  fat_ptr ptr = volatile_read(*entry);
  ASSERT(ptr.asi_type() == 0);
  Object *prev_obj = nullptr;
  while (ptr.offset()) {
    Object *cur_obj = nullptr;
    // Must read next_ before reading cur_obj->_clsn:
    // the version we're currently reading (ie cur_obj) might be unlinked
    // and thus recycled by the memory allocator at any time if it's not
    // a committed version. If so, cur_obj->_next will be pointing to some
    // other object in the allocator's free object pool - we'll probably
    // end up at la-la land if we followed this _next pointer value...
    // Here we employ some flavor of OCC to solve this problem:
    // the aborting transaction that will unlink cur_obj will update
    // cur_obj->_clsn to NULL_PTR, then deallocate(). Before reading
    // cur_obj->_clsn, we (as the visitor), first dereference pp to get
    // a stable value that "should" contain the right address of the next
    // version. We then read cur_obj->_clsn to verify: if it's NULL_PTR
    // that means we might have read a wrong _next value that's actually
    // pointing to some irrelevant object in the allocator's memory pool,
    // hence must start over from the beginning of the version chain.
    fat_ptr tentative_next = NULL_PTR;
    // If this is a backup server, then must see persistent_next to find out
    // the **real** overwritten version.
    if (config::is_backup_srv() && !config::command_log) {
      oid_get_version_backup(ptr, tentative_next, prev_obj, cur_obj, visitor_xc);
    } else {
      ASSERT(ptr.asi_type() == 0);
      cur_obj = (Object *)ptr.offset();
      tentative_next = cur_obj->GetNextVolatile();
      ASSERT(tentative_next.asi_type() == 0);
    }

    bool retry = false;
    bool visible = TestVisibility(cur_obj, visitor_xc, retry);
    if (retry) {
      goto start_over;
    }
    if (visible) {
      return cur_obj->GetPinnedTuple();
    }
    ptr = tentative_next;
    prev_obj = cur_obj;
  }
  
	return nullptr;  // No Visible records
}

#if defined(HYU_ZIGZAG) || defined(HYU_VRIDGY_ONLY)
#ifdef HYU_DEBUG /* HYU_DEBUG */
// For tuple arrays only, i.e., entries are guaranteed to point to Objects.
dbtuple *sm_oid_mgr::oid_get_version_zigzag_debug(oid_array *oa, OID o,
                                     							TXN::xid_context *visitor_xc,
																									uint64_t *cnt) {
  fat_ptr *entry = oa->get(o);
	uint64_t zigzag_cnt = 0;
start_over:
  fat_ptr ptr = volatile_read(*entry);
  ASSERT(ptr.asi_type() == 0);
  Object *prev_obj = nullptr;
  while (ptr.offset()) {
    Object *cur_obj = nullptr;
		Object *highway_obj = nullptr;
    // Must read next_ before reading cur_obj->_clsn:
    // the version we're currently reading (ie cur_obj) might be unlinked
    // and thus recycled by the memory allocator at any time if it's not
    // a committed version. If so, cur_obj->_next will be pointing to some
    // other object in the allocator's free object pool - we'll probably
    // end up at la-la land if we followed this _next pointer value...
    // Here we employ some flavor of OCC to solve this problem:
    // the aborting transaction that will unlink cur_obj will update
    // cur_obj->_clsn to NULL_PTR, then deallocate(). Before reading
    // cur_obj->_clsn, we (as the visitor), first dereference pp to get
    // a stable value that "should" contain the right address of the next
    // version. We then read cur_obj->_clsn to verify: if it's NULL_PTR
    // that means we might have read a wrong _next value that's actually
    // pointing to some irrelevant object in the allocator's memory pool,
    // hence must start over from the beginning of the version chain.
    fat_ptr tentative_next = NULL_PTR;
		fat_ptr tentative_highway = NULL_PTR;
    // If this is a backup server, then must see persistent_next to find out
    // the **real** overwritten version.
    if (config::is_backup_srv() && !config::command_log) {
			printf("[HYU] we only think about there is no replica\n");
      oid_get_version_backup(ptr, tentative_next, prev_obj, cur_obj, visitor_xc);
    } else {
      ASSERT(ptr.asi_type() == 0);
      cur_obj = (Object *)ptr.offset();
      tentative_next = cur_obj->GetNextVolatile();
			tentative_highway = cur_obj->GetHighway();
      ASSERT(tentative_next.asi_type() == 0);
			ASSERT(tentative_highway.asi_type() == 0);
    }

    bool retry = false;
    bool visible = TestVisibility(cur_obj, visitor_xc, retry);
    if (retry) {
      goto start_over;
    }
    if (visible) {
			// for check
			if (prev_obj != nullptr) {
				bool chk_retry = false;
				bool chk_again = TestVisibility(prev_obj, visitor_xc, chk_retry);
				if (chk_retry || chk_again) goto start_over;
			}

			// debug
			zigzag_cnt++;
			*cnt = zigzag_cnt;

			return cur_obj->GetPinnedTuple();
    } else {
			highway_obj = (Object *)tentative_highway.offset();

			if (highway_obj == NULL) {
				ptr = tentative_next;
				prev_obj = cur_obj;
				// debug
				zigzag_cnt++;
				continue;
			}

			fat_ptr hw_clsn = highway_obj->GetClsn();
			// is GCed?
			if (hw_clsn.asi_type() != fat_ptr::ASI_LOG || hw_clsn.asi_type() != fat_ptr::ASI_XID ||
					LSN::from_ptr(hw_clsn).offset() > LSN::from_ptr(cur_obj->GetClsn()).offset()) {
				ptr = tentative_next;
				prev_obj = cur_obj;
				continue;
				//return nullptr;
			}

			bool highway_retry = false;
			bool highway_visible = TestVisibility(highway_obj, visitor_xc, highway_retry);
	
			if (highway_retry)
				goto start_over;

			if (highway_visible) {
				ptr = tentative_next;
			} else {
				ptr = tentative_highway;
			}
			prev_obj = cur_obj;
			// debug
			zigzag_cnt++;
		}
  }
	// debug
	zigzag_cnt++;
	*cnt = zigzag_cnt;

  return nullptr;  // No Visible records
}
#endif /* HYU_DEBUG */

// For tuple arrays only, i.e., entries are guaranteed to point to Objects.
dbtuple *sm_oid_mgr::oid_get_version_zigzag(oid_array *oa, OID o,
                                     				TXN::xid_context *visitor_xc) {
  fat_ptr *entry = oa->get(o);
start_over:
  fat_ptr ptr = volatile_read(*entry);
  ASSERT(ptr.asi_type() == 0);
  Object *prev_obj = nullptr;
  while (ptr.offset()) {
    Object *cur_obj = nullptr;
		Object *highway_obj = nullptr;
    // Must read next_ before reading cur_obj->_clsn:
    // the version we're currently reading (ie cur_obj) might be unlinked
    // and thus recycled by the memory allocator at any time if it's not
    // a committed version. If so, cur_obj->_next will be pointing to some
    // other object in the allocator's free object pool - we'll probably
    // end up at la-la land if we followed this _next pointer value...
    // Here we employ some flavor of OCC to solve this problem:
    // the aborting transaction that will unlink cur_obj will update
    // cur_obj->_clsn to NULL_PTR, then deallocate(). Before reading
    // cur_obj->_clsn, we (as the visitor), first dereference pp to get
    // a stable value that "should" contain the right address of the next
    // version. We then read cur_obj->_clsn to verify: if it's NULL_PTR
    // that means we might have read a wrong _next value that's actually
    // pointing to some irrelevant object in the allocator's memory pool,
    // hence must start over from the beginning of the version chain.
    fat_ptr tentative_next = NULL_PTR;
		fat_ptr tentative_highway = NULL_PTR;
    // If this is a backup server, then must see persistent_next to find out
    // the **real** overwritten version.
    if (config::is_backup_srv() && !config::command_log) {
			printf("[HYU] we only think about there is no replica\n");
      oid_get_version_backup(ptr, tentative_next, prev_obj, cur_obj, visitor_xc);
    } else {
      ASSERT(ptr.asi_type() == 0);
      cur_obj = (Object *)ptr.offset();
      tentative_next = cur_obj->GetNextVolatile();
			tentative_highway = cur_obj->GetHighway();
      ASSERT(tentative_next.asi_type() == 0);
			ASSERT(tentative_highway.asi_type() == 0);
    }

    bool retry = false;
    bool visible = TestVisibility(cur_obj, visitor_xc, retry);
    if (retry) {
      goto start_over;
    }
    if (visible) {
      return cur_obj->GetPinnedTuple();
    } else {
			highway_obj = (Object *)tentative_highway.offset();

			if (highway_obj == NULL) {
				ptr = tentative_next;
				prev_obj = cur_obj;
				continue;
			}

			fat_ptr hw_clsn = highway_obj->GetClsn();
			// is GCed?
			if (hw_clsn.asi_type() != fat_ptr::ASI_LOG || hw_clsn.asi_type() != fat_ptr::ASI_XID ||
					LSN::from_ptr(hw_clsn).offset() > LSN::from_ptr(cur_obj->GetClsn()).offset()) {
				ptr = tentative_next;
				prev_obj = cur_obj;
				continue;
				//return nullptr;
			}

			bool highway_retry = false;
			bool highway_visible = TestVisibility(highway_obj, visitor_xc, highway_retry);

			if (highway_retry || highway_visible) {
				ptr = tentative_next;
			} else {
				ptr = tentative_highway;
			}
			prev_obj = cur_obj;
		}
  }

  return nullptr;  // No Visible records
}

// For tuple arrays only, i.e., entries are guaranteed to point to Objects.
fat_ptr sm_oid_mgr::oid_get_version_zigzag_ptr(oid_array *oa, OID o,
                                     				TXN::xid_context *visitor_xc) {
  fat_ptr *entry = oa->get(o);
start_over:
  fat_ptr ptr = volatile_read(*entry);
  ASSERT(ptr.asi_type() == 0);
  Object *prev_obj = nullptr;
  while (ptr.offset()) {
    Object *cur_obj = nullptr;
		Object *highway_obj = nullptr;
    // Must read next_ before reading cur_obj->_clsn:
    // the version we're currently reading (ie cur_obj) might be unlinked
    // and thus recycled by the memory allocator at any time if it's not
    // a committed version. If so, cur_obj->_next will be pointing to some
    // other object in the allocator's free object pool - we'll probably
    // end up at la-la land if we followed this _next pointer value...
    // Here we employ some flavor of OCC to solve this problem:
    // the aborting transaction that will unlink cur_obj will update
    // cur_obj->_clsn to NULL_PTR, then deallocate(). Before reading
    // cur_obj->_clsn, we (as the visitor), first dereference pp to get
    // a stable value that "should" contain the right address of the next
    // version. We then read cur_obj->_clsn to verify: if it's NULL_PTR
    // that means we might have read a wrong _next value that's actually
    // pointing to some irrelevant object in the allocator's memory pool,
    // hence must start over from the beginning of the version chain.
    fat_ptr tentative_next = NULL_PTR;
		fat_ptr tentative_highway = NULL_PTR;
    // If this is a backup server, then must see persistent_next to find out
    // the **real** overwritten version.
    if (config::is_backup_srv() && !config::command_log) {
			printf("[HYU] we only think about there is no replica\n");
      oid_get_version_backup(ptr, tentative_next, prev_obj, cur_obj, visitor_xc);
    } else {
      ASSERT(ptr.asi_type() == 0);
      cur_obj = (Object *)ptr.offset();
      tentative_next = cur_obj->GetNextVolatile();
			tentative_highway = cur_obj->GetHighway();
      ASSERT(tentative_next.asi_type() == 0);
			ASSERT(tentative_highway.asi_type() == 0);
    }

    bool retry = false;
    bool visible = TestVisibility(cur_obj, visitor_xc, retry);
    if (retry) {
      goto start_over;
    }
    if (visible) {
      return ptr;
    } else {
			highway_obj = (Object *)tentative_highway.offset();

			if (highway_obj == NULL) {
				ptr = tentative_next;
				prev_obj = cur_obj;
				continue;
			}

			fat_ptr hw_clsn = highway_obj->GetClsn();
			// is GCed?
			if (hw_clsn.asi_type() != fat_ptr::ASI_LOG || hw_clsn.asi_type() != fat_ptr::ASI_XID ||
					LSN::from_ptr(hw_clsn).offset() > LSN::from_ptr(cur_obj->GetClsn()).offset()) {
				ptr = tentative_next;
				prev_obj = cur_obj;
				continue;
				//return NULL_PTR;
			}

			bool highway_retry = false;
			bool highway_visible = TestVisibility(highway_obj, visitor_xc, highway_retry);

			if (highway_retry || highway_visible) {
				ptr = tentative_next;
			} else {
				ptr = tentative_highway;
			}
			prev_obj = cur_obj;
		}
  }

  return NULL_PTR;  // No Visible records
}

// For tuple arrays only, i.e., entries are guaranteed to point to Objects.
dbtuple *sm_oid_mgr::oid_get_version_zigzag_from_ver(fat_ptr ver,
                                     						TXN::xid_context *visitor_xc) {
start_over:
  fat_ptr ptr = ver;
  ASSERT(ptr.asi_type() == 0);
  Object *prev_obj = nullptr;
  while (ptr.offset()) {
    Object *cur_obj = nullptr;
		Object *highway_obj = nullptr;
    // Must read next_ before reading cur_obj->_clsn:
    // the version we're currently reading (ie cur_obj) might be unlinked
    // and thus recycled by the memory allocator at any time if it's not
    // a committed version. If so, cur_obj->_next will be pointing to some
    // other object in the allocator's free object pool - we'll probably
    // end up at la-la land if we followed this _next pointer value...
    // Here we employ some flavor of OCC to solve this problem:
    // the aborting transaction that will unlink cur_obj will update
    // cur_obj->_clsn to NULL_PTR, then deallocate(). Before reading
    // cur_obj->_clsn, we (as the visitor), first dereference pp to get
    // a stable value that "should" contain the right address of the next
    // version. We then read cur_obj->_clsn to verify: if it's NULL_PTR
    // that means we might have read a wrong _next value that's actually
    // pointing to some irrelevant object in the allocator's memory pool,
    // hence must start over from the beginning of the version chain.
    fat_ptr tentative_next = NULL_PTR;
		fat_ptr tentative_highway = NULL_PTR;
    // If this is a backup server, then must see persistent_next to find out
    // the **real** overwritten version.
    if (config::is_backup_srv() && !config::command_log) {
			printf("[HYU] we only think about there is no replica\n");
      oid_get_version_backup(ptr, tentative_next, prev_obj, cur_obj, visitor_xc);
    } else {
      ASSERT(ptr.asi_type() == 0);
      cur_obj = (Object *)ptr.offset();
      tentative_next = cur_obj->GetNextVolatile();
			tentative_highway = cur_obj->GetHighway();
      ASSERT(tentative_next.asi_type() == 0);
			ASSERT(tentative_highway.asi_type() == 0);
    }

    bool retry = false;
    bool visible = TestVisibility(cur_obj, visitor_xc, retry);
    if (retry) {
      goto start_over;
    }
    if (visible) {
      return cur_obj->GetPinnedTuple();
    } else {
			highway_obj = (Object *)tentative_highway.offset();

			if (highway_obj == NULL) {
				ptr = tentative_next;
				prev_obj = cur_obj;
				continue;
			}

			fat_ptr hw_clsn = highway_obj->GetClsn();
			// is GCed?
			if (hw_clsn.asi_type() != fat_ptr::ASI_LOG || hw_clsn.asi_type() != fat_ptr::ASI_XID ||
					LSN::from_ptr(hw_clsn).offset() > LSN::from_ptr(cur_obj->GetClsn()).offset()) {
				ptr = tentative_next;
				prev_obj = cur_obj;
				continue;
				//return nullptr;
			}

			bool highway_retry = false;
			bool highway_visible = TestVisibility(highway_obj, visitor_xc, highway_retry);

			if (highway_retry || highway_visible) {
				ptr = tentative_next;
			} else {
				ptr = tentative_highway;
			}
			prev_obj = cur_obj;
		}
  }

  return nullptr;  // No Visible records
}


#endif /* HYU_ZIGZAG */

bool sm_oid_mgr::TestVisibility(Object *object, TXN::xid_context *xc, bool &retry) {
  fat_ptr clsn = object->GetClsn();
  uint16_t asi_type = clsn.asi_type();
  if (clsn == NULL_PTR) {
    ASSERT(!config::is_backup_srv() || (config::command_log && config::replay_threads));
    // dead tuple that was (or about to be) unlinked, start over
    retry = true;
    return false;
  }

  ALWAYS_ASSERT(asi_type == fat_ptr::ASI_XID || asi_type == fat_ptr::ASI_LOG);
  if (asi_type == fat_ptr::ASI_XID) {  // in-flight
    // Backups don't write unless for command logging
    ASSERT(!config::is_backup_srv() || (config::command_log && config::replay_threads));

    XID holder_xid = XID::from_ptr(clsn);
    // Dirty data made by me is visible!
    if (holder_xid == xc->owner) {
      ASSERT(!object->GetNextVolatile().offset() ||
             ((Object *)object->GetNextVolatile().offset())
                     ->GetClsn()
                     .asi_type() == fat_ptr::ASI_LOG);
      ASSERT(!config::is_backup_srv() || (config::command_log && config::replay_threads));
      return true;
    }
    auto *holder = TXN::xid_get_context(holder_xid);
    if (!holder) {  // invalid XID (dead tuple, must retry than goto next in the
                    // chain)
      retry = true;
      return false;
    }

    auto state = volatile_read(holder->state);
    auto owner = volatile_read(holder->owner);

    // context still valid for this XID?
    if (owner != holder_xid) {
      ASSERT(!config::is_backup_srv() || (config::command_log && config::replay_threads));
      retry = true;
      return false;
    }

		// [HYU] There is a correctness violation case in checking visibility with
		// holder's transaction commit sequence(TXN_COMMITTING)
		// if (state == TNX::TXN_CMMTD)
		// 												get clsn			end commit
		//											(COMMITTING)		(CMMTD)
		// 					T1----W(A)------->|----------->|
		//															 T2--R(A)------>
		// When a transaction(T1) starts to commit, and it also gets clsn,
		// but doesn't start updating clsn in version Object yet.
		// After that, a new transaction(T2) starts and tries to read a record
		// version that T1 updates. Because T2 gets begin timestamp after T1 gets
		// clsn (holder->end < xc->begin), so T2 has to be able to read T1's updated
		// version. But in TestVisibility, there is no way to say 'visible' in this
		// case. So we add state TXN_ALMOST_COMMIT that guarantees there is no more
		// transaction abortion in commit sequence(TXN_ALMOST_COMMIT ~ TXN_CMMTD)
		// If the version holder's state is TXN_COMMITTING with clsn,
		// wait a slight time using spin for the time that we can guarantee
		// it is safe to check this version's visibility
		// (TXN_ALMOST_COMMIT or TXN_CMMTD)
    if (state == TXN::TXN_CMMTD || (state == TXN::TXN_COMMITTING && holder->end > 0) ||
				state == TXN::TXN_ALMOST_COMMIT) {
			ASSERT(volatile_read(holder->end));
      ASSERT(owner == holder_xid);
			
			if (state == TXN::TXN_COMMITTING) {
				// slight spin for abortion
				state = volatile_read(holder->state);
				while (state == TXN::TXN_COMMITTING) {
					state = volatile_read(holder->state);
					if (state != TXN::TXN_COMMITTING) break;
				}
				if (state == TXN::TXN_ABRTD) {
					retry = true;
					return false;
				}
				ASSERT(state == TXN::TXN_ALMOST_COMMIT || state == TXN::TXN_CMMTD);
			}
			// [HYU] end
#if defined(RC) || defined(RC_SPIN)
#ifdef SSN
      if (config::enable_safesnap &&
          (xc->xct->flags & transaction::TXN_FLAG_READ_ONLY)) {
        if (holder->end < xc->begin) {
          return true;
        }
      } else {
        return true;
      }
#else   // SSN
      return true;
#endif  // SSN
#else   // not RC/RC_SPIN
      if (holder->end < xc->begin) {
        return true;
      } else {
        oid_check_phantom(xc, holder->end);
      }
#endif
    }
  } else {
    // Already committed, now do visibility test
    ASSERT(object->GetPersistentAddress().asi_type() == fat_ptr::ASI_LOG ||
           object->GetPersistentAddress().asi_type() == fat_ptr::ASI_CHK ||
           object->GetPersistentAddress() == NULL_PTR);  // Delete
    uint64_t lsn_offset = LSN::from_ptr(clsn).offset();
#if defined(RC) || defined(RC_SPIN)
#if defined(SSN)
    if (config::enable_safesnap &&
        (xc->xct->flags & transaction::TXN_FLAG_READ_ONLY)) {
      if (lsn_offset <= xc->begin) {
        return true;
      } else {
        oid_check_phantom(xc, clsn.offset());
      }
    } else {
      return true;
    }
#else
    return true;
#endif
#else  // Not RC
    if (lsn_offset <= xc->begin) {
      return true;
    } else {
      oid_check_phantom(xc, clsn.offset());
    }
#endif
  }
  return false;
}
}  // namespace ermia
