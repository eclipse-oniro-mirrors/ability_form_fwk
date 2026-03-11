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
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "common/connection/form_ability_connection.h"
#include "ams_mgr/form_ams_helper.h"
#include "form_provider/connection/form_batch_delete_connection.h"
#include "form_provider/connection/form_cast_temp_connection.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = 0;
constexpr int32_t MAX_LOOP_COUNT = 10;

void DoSomethingInterestingPart2(FuzzedDataProvider *fdp)
{
    FormAmsHelper formAmsHelper;
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    AppExecFwk::ElementName element;
    element.SetBundleName(bundleName);
    element.SetAbilityName(abilityName);
    sptr<IRemoteObject> providerToken = nullptr;
    sptr<IRemoteObject> remoteObjects = nullptr;
    int resultCode = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    Want want;
    sptr<AAFwk::IAbilityConnection> connect = nullptr;
    
    formAmsHelper.GetAbilityManager();
    formAmsHelper.ConnectServiceAbility(want, connect);
    formAmsHelper.DisconnectServiceAbility(connect);
    formAmsHelper.DisconnectServiceAbilityDelay(connect);
    formAmsHelper.StopExtensionAbility(want);
    formAmsHelper.RegisterConfigurationObserver();
    formAmsHelper.UnRegisterConfigurationObserver();
    sptr<AAFwk::IAbilityManager> abilityManager = nullptr;
    formAmsHelper.SetAbilityManager(abilityManager);
    formAmsHelper.DisconnectAbilityTask(connect);
    int32_t userId = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    formAmsHelper.StartAbility(want, userId);
    sptr<IRemoteObject> callerToken = nullptr;
    formAmsHelper.StartAbilityOnlyUIAbility(want, callerToken, userId);
    std::set<int64_t> formIds;
    int64_t formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_NUM, MAX_NUM);
    int32_t numFormIds = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < numFormIds; i++) {
        formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_NUM, MAX_NUM);
        formIds.insert(formId);
    }
    sptr<IAbilityConnection> batchDeleteConnection = new FormBatchDeleteConnection(formIds, bundleName, abilityName,
        userId);
    batchDeleteConnection->OnAbilityConnectDone(element, providerToken, userId);
    sptr<IAbilityConnection> castTempConnection = new FormCastTempConnection(formId, bundleName, abilityName, userId);
    castTempConnection->OnAbilityConnectDone(element, remoteObjects, resultCode);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    FormAbilityConnection formAbilityConnection;
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObjects = nullptr;
    int resultCode = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    bool isFreeInstall = fdp->ConsumeBool();
    formAbilityConnection.SetFreeInstall(isFreeInstall);
    
    int32_t connectId = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    formAbilityConnection.SetConnectId(connectId);
    formAbilityConnection.GetConnectId();
    
    int64_t formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_NUM, MAX_NUM);
    formAbilityConnection.SetFormId(formId);
    formAbilityConnection.GetFormId();
    
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t userId = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    formAbilityConnection.SetProviderKey(bundleName, abilityName, userId);
    formAbilityConnection.GetProviderKey();
    
    sptr<IRemoteObject> hostToken = nullptr;
    formAbilityConnection.SetHostToken(hostToken);
    formAbilityConnection.GetHostToken();
    
    sptr<IRemoteObject> providerToken = nullptr;
    formAbilityConnection.SetProviderToken(providerToken);
    formAbilityConnection.GetProviderToken();
    
    formAbilityConnection.OnAbilityConnectDone(element, remoteObjects, resultCode);
    formAbilityConnection.onFormAppConnect();
    formAbilityConnection.ReportFormAppUnbindEvent();
    formAbilityConnection.GetBundleName();
    formAbilityConnection.GetAppFormPid();
    formAbilityConnection.OnAbilityDisconnectDone(element, resultCode);
    wptr<IRemoteObject> remoteObject1;
    formAbilityConnection.OnConnectDied(remoteObject1);
    
    DoSomethingInterestingPart2(fdp);
    
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
