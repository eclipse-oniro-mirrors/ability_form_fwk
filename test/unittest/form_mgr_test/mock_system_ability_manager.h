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
#ifndef MOCK_SYSTEM_ABILITY_MANAGER_H
#define MOCK_SYSTEM_ABILITY_MANAGER_H
#include <gtest/gtest.h>
#include "gmock/gmock.h"
#include "if_system_ability_manager.h"
#include "iremote_object.h"
#include "iremote_stub.h"

namespace OHOS {
class MockSystemAbilityManager : public IRemoteStub<ISystemAbilityManager> {
public:
    MockSystemAbilityManager() {};
    virtual ~MockSystemAbilityManager() {};

    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption &option) override
    {
        return {};
    }

    std::vector<std::u16string> ListSystemAbilities(uint32_t dumpFlags) override
    {
        return {};
    };
    sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId) override
    {
        return this;
    };
    sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId) override
    {
        return this;
    };
    int32_t RemoveSystemAbility(int32_t systemAbilityId) override
    {
        return {};
    };
    int32_t SubscribeSystemAbility(int32_t systemAbilityId, const sptr<ISystemAbilityStatusChange>& listener) override
    {
        return {};
    };
    int32_t UnSubscribeSystemAbility(int32_t systemAbilityId,
        const sptr<ISystemAbilityStatusChange>& listener) override
    {
        return {};
    };
    sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override
    {
        return {};
    };
    sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override
    {
        return {};
    };
    int32_t AddOnDemandSystemAbilityInfo(int32_t systemAbilityId, const std::u16string& procName) override
    {
        return {};
    };
    sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId, bool& isExist) override
    {
        return {};
    };
    int32_t AddSystemAbility(int32_t systemAbilityId, const sptr<IRemoteObject>& ability,
        const SAExtraProp& extraProp) override
    {
        return {};
    };
    int32_t AddSystemProcess(const std::u16string& procName, const sptr<IRemoteObject>& procObject) override
    {
        return {};
    };
    int32_t LoadSystemAbility(int32_t systemAbilityId, const sptr<ISystemAbilityLoadCallback>& callback) override
    {
        return {};
    };
    int32_t LoadSystemAbility(int32_t systemAbilityId, const std::string& deviceId,
        const sptr<ISystemAbilityLoadCallback>& callback) override
    {
        return {};
    };
};
}   // namespace OHOS
#endif  // MOCK_SYSTEM_ABILITY_MANAGER_H_