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

#include "formabilityconnection_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "form_ability_connection.h"
#define private public
#define protected public
#include "form_ams_helper.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormAbilityConnection formAbilityConnection;
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObjects = nullptr;
    int resultCode = static_cast<int>(GetU32Data(data));
    formAbilityConnection.OnAbilityConnectDone(element, remoteObjects, resultCode);
    formAbilityConnection.GetProviderKey();
    std::string bundleName(data, size);
    std::string abilityName(data, size);
    formAbilityConnection.SetProviderKey(bundleName, abilityName);
    bool isFreeInstall = *data % ENABLE;
    formAbilityConnection.SetFreeInstall(isFreeInstall);
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    formAbilityConnection.SetFormId(formId);
    formAbilityConnection.GetFormId();
    sptr<IRemoteObject> hostToken = nullptr;
    formAbilityConnection.SetHostToken(hostToken);
    formAbilityConnection.GetHostToken();
    sptr<IRemoteObject> providerToken = nullptr;
    formAbilityConnection.SetProviderToken(providerToken);
    formAbilityConnection.GetProviderToken();
    int32_t connectId = static_cast<int32_t>(GetU32Data(data));
    formAbilityConnection.SetConnectId(connectId);
    FormAmsHelper formAmsHelper;
    formAmsHelper.GetAbilityManager();
    Want want;
    sptr<AAFwk::IAbilityConnection> connect = nullptr;
    formAmsHelper.ConnectServiceAbility(want, connect);
    formAmsHelper.DisconnectServiceAbility(connect);
    formAmsHelper.DisconnectServiceAbilityDelay(connect);
    sptr<AAFwk::IAbilityManager> abilityManager = nullptr;
    formAmsHelper.SetAbilityManager(abilityManager);
    formAmsHelper.DisconnectAbilityTask(connect);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    formAmsHelper.StartAbility(want, userId);
    return formAbilityConnection.GetConnectId();
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    /* Validate the length of size */
    if (size == 0 || size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = (char *)malloc(size + 1);
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

