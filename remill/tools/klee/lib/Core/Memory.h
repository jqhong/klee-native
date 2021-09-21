//===-- Memory.h ------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_MEMORY_H
#define KLEE_MEMORY_H

#include "Context.h"
#include "TimingSolver.h"
#include "klee/Expr.h"

#include "llvm/ADT/StringExtras.h"

#include <vector>
#include <string>

namespace llvm {
class Value;
}  // namespace llvm

namespace klee {

class BitArray;
class MemoryManager;
class Solver;
class ArrayCache;

class MemoryObject {
  friend class STPBuilder;
  friend class ObjectState;
  friend class ExecutionState;

 private:
  static uint64_t counter;
  mutable unsigned refCount;

 public:
  uint64_t id;
  uintptr_t address;

  /// size in bytes
  uint64_t size;
  mutable std::string name;

  bool isLocal;
  mutable bool isGlobal;
  bool isFixed;

  bool isUserSpecified;

  MemoryManager *parent;

  /// "Location" for which this memory object was allocated. This
  /// should be either the allocating instruction or the global object
  /// it was allocated for (or whatever else makes sense).
  const llvm::Value *allocSite;

  /// A list of boolean expressions the user has requested be true of
  /// a counterexample. Mutable since we play a little fast and loose
  /// with allowing it to be added to during execution (although
  /// should sensibly be only at creation time).
  mutable std::vector<ref<Expr> > cexPreferences;

  // DO NOT IMPLEMENT
  MemoryObject(const MemoryObject &b);
  MemoryObject &operator=(const MemoryObject &b);

 public:
  // XXX this is just a temp hack, should be removed
  explicit MemoryObject(uint64_t _address)
      : refCount(0),
        id(counter++),
        address(_address),
        size(0),
        isLocal(false),
        isGlobal(false),
        isFixed(true),
        isUserSpecified(false),
        parent(NULL),
        allocSite(0) {
  }

  MemoryObject(uint64_t _address, uint64_t _size, bool _isLocal, bool _isGlobal,
               bool _isFixed, const llvm::Value *_allocSite,
               MemoryManager *_parent)
      : refCount(0),
        id(counter++),
        address(_address),
        size(_size),
        name("unnamed"),
        isLocal(_isLocal),
        isGlobal(_isGlobal),
        isFixed(_isFixed),
        isUserSpecified(false),
        parent(_parent),
        allocSite(_allocSite) {
  }

  ~MemoryObject(void);

  /// Get an identifying string for this allocation.
  void getAllocInfo(std::string &result) const;

  void setName(std::string name) const {
    this->name = name;
  }

  ref<ConstantExpr> getBaseExpr(void) const {
    return ConstantExpr::create(address, Context::get().getPointerWidth());
  }
  ref<ConstantExpr> getSizeExpr(void) const {
    return ConstantExpr::create(size, Context::get().getPointerWidth());
  }
  ref<Expr> getOffsetExpr(ref<Expr> pointer) const {
    return SubExpr::create(pointer, getBaseExpr());
  }
  ref<Expr> getBoundsCheckPointer(ref<Expr> pointer) const {
    return getBoundsCheckOffset(getOffsetExpr(pointer));
  }
  ref<Expr> getBoundsCheckPointer(ref<Expr> pointer, size_t bytes) const {
    return getBoundsCheckOffset(getOffsetExpr(pointer), bytes);
  }

  ref<Expr> getBoundsCheckOffset(ref<Expr> offset) const {
    if (size == 0) {
      return EqExpr::create(
          offset, ConstantExpr::alloc(0, Context::get().getPointerWidth()));
    } else {
      return UltExpr::create(offset, getSizeExpr());
    }
  }

  ref<Expr> getBoundsCheckOffset(ref<Expr> offset, size_t bytes) const {
    if (bytes <= size) {
      return UltExpr::create(
          offset,
          ConstantExpr::alloc(size - bytes + 1,
                              Context::get().getPointerWidth()));
    } else {
      return ConstantExpr::alloc(0, Expr::Bool);
    }
  }
};

class ObjectState {
 public:
  friend class AddressSpace;
  friend class SpecialFunctionHandler;
  unsigned copyOnWriteOwner;  // exclusively for AddressSpace

  friend class ObjectHolder;
  unsigned refCount;

  const MemoryObject *object;

  uint8_t *concreteStore;

  // XXX cleanup name of flushMask (its backwards or something)
  BitArray *concreteMask;

  // mutable because may need flushed during read of const
  mutable BitArray *flushMask;

  ref<Expr> *knownSymbolics;

  // mutable because we may need flush during read of const
  mutable UpdateList updates;

 public:
  uint64_t size;

  bool readOnly;

 public:
  /// Create a new object state for the given memory object with concrete
  /// contents. The initial contents are undefined, it is the callers
  /// responsibility to initialize the object contents appropriately.
  ObjectState(const MemoryObject *mo);

  /// Create a new object state for the given memory object with symbolic
  /// contents.
  ObjectState(const MemoryObject *mo, const Array *array);

  ObjectState(const ObjectState &os);
  ~ObjectState(void);

  const MemoryObject *getObject(void) const {
    return object;
  }

  void setReadOnly(bool ro) {
    readOnly = ro;
  }

  // make contents all concrete and zero
  void initializeToZero(void);
  // make contents all concrete and random
  void initializeToRandom(void);

  ref<Expr> read(ref<Expr> offset, Expr::Width width) const;
  ref<Expr> read(size_t offset, Expr::Width width) const;
  ref<Expr> read8(size_t offset) const;

  // return bytes written.
  void write(size_t offset, ref<Expr> value);
  void write(ref<Expr> offset, ref<Expr> value);

  void write8(size_t offset, uint8_t value);
  void write16(size_t offset, uint16_t value);
  void write32(size_t offset, uint32_t value);
  void write64(size_t offset, uint64_t value);
  void print(void) const;

  /*
   Looks at all the symbolic bytes of this object, gets a value for them
   from the solver and puts them in the concreteStore.
   */
  void flushToConcreteStore(TimingSolver *solver,
                            const ExecutionState &state) const;

 private:
  const UpdateList &getUpdates(void) const;

  void makeConcrete(void);

  void makeSymbolic(void);

  ref<Expr> read8(ref<Expr> offset) const;
  void write8(size_t offset, ref<Expr> value);
  void write8(ref<Expr> offset, ref<Expr> value);

  void fastRangeCheckOffset(ref<Expr> offset, size_t *base_r,
                            size_t *size_r) const;
  void flushRangeForRead(size_t rangeBase, size_t rangeSize) const;
  void flushRangeForWrite(size_t rangeBase, size_t rangeSize);

  bool isByteConcrete(size_t offset) const;
  bool isByteFlushed(size_t offset) const;
  bool isByteKnownSymbolic(size_t offset) const;

  void markByteConcrete(size_t offset);
  void markByteSymbolic(size_t offset);
  void markByteFlushed(size_t offset);
  void markByteUnflushed(size_t offset);
  void setKnownSymbolic(size_t offset, Expr *value);

  ArrayCache *getArrayCache(void) const;
};

}  // End klee namespace

#endif
