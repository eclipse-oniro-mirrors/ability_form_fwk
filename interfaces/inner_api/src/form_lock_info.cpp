/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "form_lock_info.h"
#include "fms_log_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool FormLockInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(bundleName)) {
        HILOG_ERROR("marshall bundleName failed");
        return false;
    }

    if (!parcel.WriteInt32(userId)) {
        HILOG_ERROR("marshall userId failed");
        return false;
    }

    if (!parcel.WriteBool(lock)) {
        HILOG_ERROR("marshall lock failed");
        return false;
    }
    return true;
}

FormLockInfo *FormLockInfo::Unmarshalling(Parcel &parcel)
{
    FormLockInfo *lockInfo = new (std::nothrow) FormLockInfo();

    if (lockInfo == nullptr) {
        HILOG_ERROR("new FormLockInfo failed.");
        return nullptr;
    }

    if (!parcel.ReadString(lockInfo->bundleName)) {
        HILOG_ERROR("marshall bundleName failed.");
        delete lockInfo;
        lockInfo = nullptr;
        return lockInfo;
    }

    if (!parcel.ReadInt32(lockInfo->userId)) {
        HILOG_ERROR("marshall userId failed.");
        delete lockInfo;
        lockInfo = nullptr;
        return lockInfo;
    }

    if (!parcel.ReadBool(lockInfo->lock)) {
        HILOG_ERROR("marshall lock failed.");
        delete lockInfo;
        lockInfo = nullptr;
        return lockInfo;
    }
    return lockInfo;
}
} // OHOS
} // AppExecFwk