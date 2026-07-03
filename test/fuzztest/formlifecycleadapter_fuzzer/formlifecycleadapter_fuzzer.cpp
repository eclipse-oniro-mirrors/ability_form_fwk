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

#include "formlifecycleadapter_fuzzer.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

#define private public
#define protected public
#include "form_mgr/form_lifecycle_adapter.h"
#undef private
#undef protected

#include "configuration.h"
#include "form_constants.h"
#include "data_center/form_info/form_item_info.h"
#include "form_js_info.h"
#include "data_center/form_record/form_record.h"
#include "running_form_info.h"
#include "want.h"
#include "want_params.h"

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 0;
constexpr int32_t MAX_USER_ID = 1000;
constexpr int32_t MIN_USER_ID = 0;
constexpr int32_t MAX_VECTOR_SIZE = 10;
constexpr int32_t MAX_DIMENSION_ID = 10;
constexpr int32_t MIN_DIMENSION_ID = 0;
constexpr int32_t MAX_CALLING_UID = 10000;
constexpr int32_t MIN_CALLING_UID = 0;
constexpr int32_t MAX_FORM_LOCATION = 4;
constexpr int32_t MAX_HOUR = 23;
constexpr int32_t MAX_MINUTE = 59;
constexpr int32_t MAX_NUM_FORMS_DELETED = 1000;

std::string GenerateSafeString(FuzzedDataProvider *fdp, int32_t maxLength)
{
    std::string result = fdp->ConsumeRandomLengthString(maxLength);
    std::string safeResult;
    for (char c : result) {
        if (std::isalnum(c) || c == '_' || c == '-' || c == '.' || c == '/' || c == ':') {
            safeResult += c;
        } else {
            safeResult += '_';
        }
    }
    return safeResult.empty() ? "default" : safeResult;
}

Want GenerateWant(FuzzedDataProvider *fdp)
{
    Want want;
    want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
    want.SetAction(GenerateSafeString(fdp, MAX_LENGTH));
    return want;
}

std::vector<int64_t> GenerateFormIdVector(FuzzedDataProvider *fdp)
{
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    std::vector<int64_t> formIds;
    for (int32_t i = 0; i < size; ++i) {
        formIds.push_back(fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID));
    }
    return formIds;
}

RunningFormInfo GenerateRunningFormInfo(FuzzedDataProvider *fdp)
{
    RunningFormInfo runningFormInfo;
    runningFormInfo.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    runningFormInfo.bundleName = GenerateSafeString(fdp, MAX_LENGTH);
    runningFormInfo.moduleName = GenerateSafeString(fdp, MAX_LENGTH);
    runningFormInfo.abilityName = GenerateSafeString(fdp, MAX_LENGTH);
    runningFormInfo.formName = GenerateSafeString(fdp, MAX_LENGTH);
    runningFormInfo.hostBundleName = GenerateSafeString(fdp, MAX_LENGTH);
    runningFormInfo.dimension = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    runningFormInfo.userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    return runningFormInfo;
}

FormItemInfo GenerateFormItemInfo(FuzzedDataProvider *fdp)
{
    FormItemInfo formItemInfo;
    formItemInfo.SetFormId(fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID));
    formItemInfo.SetProviderBundleName(GenerateSafeString(fdp, MAX_LENGTH));
    formItemInfo.SetModuleName(GenerateSafeString(fdp, MAX_LENGTH));
    formItemInfo.SetAbilityName(GenerateSafeString(fdp, MAX_LENGTH));
    formItemInfo.SetFormName(GenerateSafeString(fdp, MAX_LENGTH));
    return formItemInfo;
}

FormRecord GenerateFormRecord(FuzzedDataProvider *fdp)
{
    FormRecord formRecord;
    formRecord.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    formRecord.bundleName = GenerateSafeString(fdp, MAX_LENGTH);
    formRecord.moduleName = GenerateSafeString(fdp, MAX_LENGTH);
    formRecord.abilityName = GenerateSafeString(fdp, MAX_LENGTH);
    formRecord.formName = GenerateSafeString(fdp, MAX_LENGTH);
    formRecord.userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    return formRecord;
}

WantParams GenerateWantParams(FuzzedDataProvider *fdp)
{
    (void)fdp;
    WantParams wantParams;
    return wantParams;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormLifecycleAdapter::GetInstance();

    // Fuzz AddForm with nullptr callerToken (tests error path)
    int64_t addFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Want addWant = GenerateWant(fdp);
    sptr<IRemoteObject> addCallerToken = nullptr;
    FormJsInfo addFormInfo;
    adapter.AddForm(addFormId, addWant, addCallerToken, addFormInfo);

    // Fuzz DeleteForm with nullptr callerToken
    int64_t deleteFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> deleteCallerToken = nullptr;
    adapter.DeleteForm(deleteFormId, deleteCallerToken);

    // Fuzz ReleaseForm with nullptr callerToken
    int64_t releaseFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> releaseCallerToken = nullptr;
    bool delCache = fdp->ConsumeBool();
    adapter.ReleaseForm(releaseFormId, releaseCallerToken, delCache);

    // Fuzz CastTempForm with nullptr callerToken
    int64_t castFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> castCallerToken = nullptr;
    adapter.CastTempForm(castFormId, castCallerToken);

    // Fuzz CreateForm
    Want createWant = GenerateWant(fdp);
    RunningFormInfo createRunningFormInfo;
    adapter.CreateForm(createWant, createRunningFormInfo);

    // Fuzz StopRenderingForm
    int64_t stopFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::string stopCompId = GenerateSafeString(fdp, MAX_LENGTH);
    adapter.StopRenderingForm(stopFormId, stopCompId);

    // Fuzz ReleaseRenderer
    int64_t releaseRendererFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::string releaseCompId = GenerateSafeString(fdp, MAX_LENGTH);
    adapter.ReleaseRenderer(releaseRendererFormId, releaseCompId);

    // Fuzz DeleteInvalidForms with nullptr callerToken
    std::vector<int64_t> invalidFormIds = GenerateFormIdVector(fdp);
    sptr<IRemoteObject> invalidCallerToken = nullptr;
    int32_t numFormsDeleted = 0;
    adapter.DeleteInvalidForms(invalidFormIds, invalidCallerToken, numFormsDeleted);

    // Fuzz EnableForms
    std::string enableBundleName = GenerateSafeString(fdp, MAX_LENGTH);
    int32_t enableUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    bool enable = fdp->ConsumeBool();
    adapter.EnableForms(enableBundleName, enableUserId, enable);

    // Fuzz ProtectLockForms
    std::string protectBundleName = GenerateSafeString(fdp, MAX_LENGTH);
    int32_t protectUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    bool protect = fdp->ConsumeBool();
    adapter.ProtectLockForms(protectBundleName, protectUserId, protect);

    // Fuzz RecoverForms
    std::vector<int64_t> recoverFormIds = GenerateFormIdVector(fdp);
    Want recoverWant = GenerateWant(fdp);
    adapter.RecoverForms(recoverFormIds, recoverWant);

    // Fuzz RecycleForms
    std::vector<int64_t> recycleFormIds = GenerateFormIdVector(fdp);
    Want recycleWant = GenerateWant(fdp);
    bool isCheckCallingUid = fdp->ConsumeBool();
    adapter.RecycleForms(recycleFormIds, recycleWant, isCheckCallingUid);

    // Fuzz SwitchLockForms
    std::string switchBundleName = GenerateSafeString(fdp, MAX_LENGTH);
    int32_t switchUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    bool lock = fdp->ConsumeBool();
    adapter.SwitchLockForms(switchBundleName, switchUserId, lock);

    // Fuzz BatchNotifyFormsConfigurationUpdate
    Configuration configuration;
    adapter.BatchNotifyFormsConfigurationUpdate(configuration);

    // Fuzz HandleFormRemoveObserver
    RunningFormInfo removeObserverInfo = GenerateRunningFormInfo(fdp);
    adapter.HandleFormRemoveObserver(removeObserverInfo);

    // Fuzz AllotFormById (private, exposed via #define private public)
    FormItemInfo allotByIdInfo = GenerateFormItemInfo(fdp);
    sptr<IRemoteObject> allotByIdToken = nullptr;
    WantParams allotByIdParams = GenerateWantParams(fdp);
    FormJsInfo allotByIdFormInfo;
    adapter.AllotFormById(allotByIdInfo, allotByIdToken, allotByIdParams, allotByIdFormInfo);

    // Fuzz AllotFormByInfo
    FormItemInfo allotByInfoInfo = GenerateFormItemInfo(fdp);
    sptr<IRemoteObject> allotByInfoToken = nullptr;
    WantParams allotByInfoParams = GenerateWantParams(fdp);
    FormJsInfo allotByInfoFormInfo;
    adapter.AllotFormByInfo(allotByInfoInfo, allotByInfoToken, allotByInfoParams, allotByInfoFormInfo);

    // Fuzz AllotFormBySpecificId
    FormItemInfo allotBySpecInfo = GenerateFormItemInfo(fdp);
    sptr<IRemoteObject> allotBySpecToken = nullptr;
    WantParams allotBySpecParams = GenerateWantParams(fdp);
    FormJsInfo allotBySpecFormInfo;
    adapter.AllotFormBySpecificId(allotBySpecInfo, allotBySpecToken, allotBySpecParams, allotBySpecFormInfo);

    // Fuzz AddNewFormRecord
    FormItemInfo newRecordInfo = GenerateFormItemInfo(fdp);
    int64_t newRecordFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> newRecordToken = nullptr;
    WantParams newRecordParams = GenerateWantParams(fdp);
    FormJsInfo newRecordFormJsInfo;
    adapter.AddNewFormRecord(newRecordInfo, newRecordFormId, newRecordToken, newRecordParams, newRecordFormJsInfo);

    // Fuzz AddExistFormRecord
    FormItemInfo existRecordInfo = GenerateFormItemInfo(fdp);
    sptr<IRemoteObject> existRecordToken = nullptr;
    FormRecord existFormRecord = GenerateFormRecord(fdp);
    int64_t existRecordFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    WantParams existRecordParams = GenerateWantParams(fdp);
    FormJsInfo existRecordFormInfo;
    adapter.AddExistFormRecord(existRecordInfo, existRecordToken, existFormRecord,
        existRecordFormId, existRecordParams, existRecordFormInfo);

    // Fuzz AddRequestPublishForm
    FormItemInfo publishInfo = GenerateFormItemInfo(fdp);
    Want publishWant = GenerateWant(fdp);
    sptr<IRemoteObject> publishToken = nullptr;
    FormJsInfo publishFormJsInfo;
    adapter.AddRequestPublishForm(publishInfo, publishWant, publishToken, publishFormJsInfo);

    // Fuzz AllotForm (5-param signature per header)
    int64_t allotFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Want allotFormWant = GenerateWant(fdp);
    sptr<IRemoteObject> allotFormToken = nullptr;
    FormJsInfo allotFormJsInfo;
    FormItemInfo allotFormItemInfo = GenerateFormItemInfo(fdp);
    adapter.AllotForm(allotFormId, allotFormWant, allotFormToken, allotFormJsInfo, allotFormItemInfo);

    // Fuzz DeleteCommonForm with nullptr callerToken
    int64_t commonFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> commonToken = nullptr;
    int32_t commonUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    adapter.DeleteCommonForm(commonFormId, commonToken, commonUserId);

    // Fuzz HandleDeleteForm with nullptr callerToken
    int64_t handleDelFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> handleDelToken = nullptr;
    adapter.HandleDeleteForm(handleDelFormId, handleDelToken);

    // Fuzz HandleDeleteTempForm with nullptr callerToken
    int64_t handleDelTempFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> handleDelTempToken = nullptr;
    adapter.HandleDeleteTempForm(handleDelTempFormId, handleDelTempToken);

    // Fuzz HandleReleaseForm with nullptr callerToken
    int64_t handleReleaseFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> handleReleaseToken = nullptr;
    adapter.HandleReleaseForm(handleReleaseFormId, handleReleaseToken);

    // Fuzz HandleCastTempForm (header signature: int64_t + FormRecord)
    int64_t handleCastFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    FormRecord handleCastFormRecord = GenerateFormRecord(fdp);
    adapter.HandleCastTempForm(handleCastFormId, handleCastFormRecord);

    // Fuzz HandleDeleteFormCache
    FormRecord delCacheRecord = GenerateFormRecord(fdp);
    int32_t delCacheUid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    int64_t delCacheFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.HandleDeleteFormCache(delCacheRecord, delCacheUid, delCacheFormId);

#ifdef RES_SCHEDULE_ENABLE
    // Fuzz SetTimerTaskNeeded (only available when RES_SCHEDULE_ENABLE is defined)
    bool timerTaskNeeded = fdp->ConsumeBool();
    adapter.SetTimerTaskNeeded(timerTaskNeeded);
#endif

    // Fuzz CheckFormCountLimit
    int64_t checkCountFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Want checkCountWant = GenerateWant(fdp);
    adapter.CheckFormCountLimit(checkCountFormId, checkCountWant);

    // Fuzz CheckIsAddFormByHost
    FormRecord checkHostRecord = GenerateFormRecord(fdp);
    Want checkHostWant = GenerateWant(fdp);
    adapter.CheckIsAddFormByHost(checkHostRecord, checkHostWant);

    // Fuzz IsFormRenderServiceCall
    int32_t renderServiceUid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    adapter.IsFormRenderServiceCall(renderServiceUid);

    // Fuzz CheckAddRequestPublishForm
    Want checkPublishWant = GenerateWant(fdp);
    Want checkPublishFormProviderWant = GenerateWant(fdp);
    adapter.CheckAddRequestPublishForm(checkPublishWant, checkPublishFormProviderWant);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
