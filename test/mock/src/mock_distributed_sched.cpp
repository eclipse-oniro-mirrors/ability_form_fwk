/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "ipc_skeleton.h"
#include "mock_distributed_sched.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace std;
using namespace AAFwk;

namespace {
const std::string TAG = "MockDistributedSched";
const std::u16string DMS_STUB_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
}
DistributedSchedStub::DistributedSchedStub()
{
    localFuncsMap_[START_REMOTE_SHARE_FORM] = &DistributedSchedStub::StartRemoteShareFormInner;
}

DistributedSchedStub::~DistributedSchedStub()
{
    localFuncsMap_.clear();
}

int32_t DistributedSchedStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    const auto &funcsMap = localFuncsMap_;
    auto iter = funcsMap.find(code);
    if (iter != funcsMap.end()) {
        auto func = iter->second;
        if (!EnforceInterfaceToken(data)) {
            return 1;
        }
        if (func != nullptr) {
            return (this->*func)(data, reply);
        }
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool DistributedSchedStub::EnforceInterfaceToken(MessageParcel &data)
{
    u16string interfaceToken = data.ReadInterfaceToken();
    return interfaceToken == DMS_STUB_INTERFACE_TOKEN;
}

int32_t DistributedSchedStub::StartRemoteShareFormInner(MessageParcel &data, MessageParcel &reply)
{
    std::string deviceId = data.ReadString();
    shared_ptr<AppExecFwk::FormShareInfo> formShareInfo(data.ReadParcelable<AppExecFwk::FormShareInfo>());
    if (formShareInfo == nullptr) {
        return ERR_NULL_OBJECT;
    }

    int32_t result = StartRemoteShareForm(deviceId, *formShareInfo);
    return result;
}
} // namespace DistributedSchedule
} // namespace OHOS