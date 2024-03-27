/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "form_ecological_rule_param.h"

#include <string>
#include <vector>

#include "iremote_broker.h"
#include "iremote_object.h"

#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

bool FormErmsCallerInfo::ReadFromParcel(Parcel &parcel)
{
    HILOG_DEBUG("read from parcel");
    return true;
}

FormErmsCallerInfo *FormErmsCallerInfo::Unmarshalling(Parcel &in)
{
    auto *info = new (std::nothrow) FormErmsCallerInfo();
    if (info == nullptr) {
        HILOG_ERROR("new callerInfo failed, return nullptr");
        return nullptr;
    }

    info->packageName = in.ReadString();
    HILOG_DEBUG("read packageName result: %{public}s", info->packageName.c_str());

    if (!in.ReadInt32(info->uid)) {
        HILOG_ERROR("read uid failed");
        delete info;
        return nullptr;
    }

    if (!in.ReadInt32(info->pid)) {
        HILOG_ERROR("read pid failed");
        delete info;
        return nullptr;
    }

    if (!in.ReadInt32(info->callerAppType)) {
        HILOG_ERROR("read callerAppType failed");
        delete info;
        return nullptr;
    }

    if (!in.ReadInt32(info->targetAppType)) {
        HILOG_ERROR("read targetAppType failed");
        delete info;
        return nullptr;
    }

    return info;
}

bool FormErmsCallerInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(packageName)) {
        HILOG_ERROR("write packageName failed");
        return false;
    }

    if (!parcel.WriteInt32(uid)) {
        HILOG_ERROR("write uid failed");
        return false;
    }

    if (!parcel.WriteInt32(pid)) {
        HILOG_ERROR("write pid failed");
        return false;
    }

    if (!parcel.WriteInt32(callerAppType)) {
        HILOG_ERROR("write callerAppType failed");
        return false;
    }

    if (!parcel.WriteInt32(targetAppType)) {
        HILOG_ERROR("write targetAppType failed");
        return false;
    }
    return true;
}

std::string FormErmsCallerInfo::ToString() const
{
    std::string str = "CallerInfo{packageName:" + packageName + ",uid:" + std::to_string(uid) +
        ",pid:" + std::to_string(pid) + ",callerAppType:" + std::to_string(callerAppType) +
        ",targetAppType:" + std::to_string(targetAppType) + "}";
    return str;
}
} // namespace EcologicalRuleMgrService
} // namespace OHOS
