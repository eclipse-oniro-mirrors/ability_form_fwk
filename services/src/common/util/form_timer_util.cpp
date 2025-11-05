/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common/util/form_timer_util.h"

#include <chrono>
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int NANO_TO_SECOND = 1000000000;
}  // namespace

int64_t FormTimerUtil::GetBootTimeMs()
{
    int64_t timeNow = -1;
    struct timespec tv {};
    if (clock_gettime(CLOCK_BOOTTIME, &tv) < 0) {
        HILOG_WARN("Get bootTime by clock_gettime failed, use std::chrono::steady_clock");
        auto timeSinceEpoch = std::chrono::steady_clock::now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(timeSinceEpoch).count();
    }
    timeNow = tv.tv_sec * NANO_TO_SECOND + tv.tv_nsec;
    std::chrono::steady_clock::time_point tpEpoch((std::chrono::nanoseconds(timeNow)));
    auto timeSinceEpoch = tpEpoch.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(timeSinceEpoch).count();
}

}  // namespace AppExecFwk
}  // namespace OHOS