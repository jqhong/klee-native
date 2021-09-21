//===-- Statistics.cpp ----------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Statistics.h"

#include <vector>

#include "Native/Util/AreaAllocator.h"

using namespace klee;

namespace {

static native::AreaAllocator gIndexedStatsAllocator(
    native::kAreaRW, native::kIndexedStatsTable);

}  // namespace

StatisticManager::StatisticManager()
  : enabled(true),
    globalStats(),
    indexedStats(nullptr),
    indexedStatsEnabled(false),
    prevTotalIndices(0),
    contextStats(nullptr),
    index(0) {}

void StatisticManager::useIndexedStats(void) {
  indexedStatsEnabled = true;
}

void StatisticManager::growIndexedStats(size_t totalIndices) {
  if (!indexedStatsEnabled) {
    return;
  }
  if (!indexedStats) {
    indexedStats = reinterpret_cast<uint64_t *>(gIndexedStatsAllocator.Allocate(
        totalIndices * stats.size() * sizeof(uint64_t)));
  } else {
    auto num_needed = totalIndices - prevTotalIndices;
    gIndexedStatsAllocator.Allocate(
        num_needed * stats.size() * sizeof(uint64_t));
  }
  prevTotalIndices = totalIndices;
}

void StatisticManager::registerStatistic(Statistic &s) {
  s.id = static_cast<unsigned>(stats.size());
  stats.push_back(&s);
  globalStats.resize(stats.size());
}

int StatisticManager::getStatisticID(const std::string &name) const {
  for (unsigned i=0; i < stats.size(); i++) {
    if (stats[i]->getName() == name) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

Statistic *StatisticManager::getStatisticByName(const std::string &name) const {
  for (unsigned i=0; i<stats.size(); i++)
    if (stats[i]->getName() == name)
      return stats[i];
  return 0;
}

StatisticManager *klee::theStatisticManager = nullptr;

static StatisticManager &getStatisticManager() {
  static StatisticManager sm;
  theStatisticManager = &sm;
  return sm;
}

/* *** */

Statistic::Statistic(const std::string &_name, 
                     const std::string &_shortName) 
  : id(0),
    name(_name),
    shortName(_shortName) {
  getStatisticManager().registerStatistic(*this);
}

Statistic::~Statistic() {
}

Statistic &Statistic::operator +=(const uint64_t addend) {
  theStatisticManager->incrementStatistic(*this, addend);
  return *this;
}

uint64_t Statistic::getValue() const {
  return theStatisticManager->getValue(*this);
}
