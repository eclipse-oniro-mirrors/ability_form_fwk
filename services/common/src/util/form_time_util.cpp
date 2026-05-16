/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "util/form_time_util.h"

#include <chrono>
#include <ctime>

#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace Common {
namespace {
constexpr int NANO_PER_SECOND = 1000000000;
}

int64_t FormTimeUtil::GetBootTimeMs()
{
    int64_t timeNow = -1;
    struct timespec tv {};
    if (clock_gettime(CLOCK_BOOTTIME, &tv) < 0) {
        HILOG_WARN("Get bootTime by clock_gettime failed, use std::chrono::steady_clock");
        auto timeSinceEpoch = std::chrono::steady_clock::now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(timeSinceEpoch).count();
    }
    timeNow = static_cast<uint64_t>(tv.tv_sec) * NANO_PER_SECOND + static_cast<uint64_t>(tv.tv_nsec);
    std::chrono::steady_clock::time_point tpEpoch((std::chrono::nanoseconds(timeNow)));
    auto timeSinceEpoch = tpEpoch.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(timeSinceEpoch).count();
}

int64_t FormTimeUtil::GetNowMillisecond()
{
    auto timeSinceEpoch = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(timeSinceEpoch).count();
}
} // namespace Common
} // namespace AppExecFwk
} // namespace OHOS