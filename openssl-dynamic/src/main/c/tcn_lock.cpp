/*
 * Copyright 2017 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
#include "tcn_lock.h"
#include <mutex>

tcn_lock_t tcn_lock_new() {
    return (tcn_lock_t) new std::mutex;
}

void tcn_lock_free(tcn_lock_t* lock) {
    delete (std::mutex *) *lock;
    *lock = nullptr;
}

void tcn_lock_acquire(tcn_lock_t lock) {
    ((std::mutex *) lock)->lock();
}

void tcn_lock_release(tcn_lock_t lock) {
    ((std::mutex *) lock)->unlock();
}
