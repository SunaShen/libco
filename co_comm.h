#pragma once

#include "co_routine.h"

// 互斥量
class clsCoMutex {
 public:
  clsCoMutex();
  ~clsCoMutex();

  void CoLock();
  void CoUnLock();

 private:
  // 协程信号量
  stCoCond_t* m_ptCondSignal;
  // 记录上锁状态 0:未上锁 1:已上锁
  int m_iWaitItemCnt;
};

// 使用RAII机制实现互斥量
class clsSmartLock {
 public:
  clsSmartLock(clsCoMutex* m) {
    m_ptMutex = m;
    m_ptMutex->CoLock();
  }
  ~clsSmartLock() { m_ptMutex->CoUnLock(); }

 private:
  clsCoMutex* m_ptMutex;
};

