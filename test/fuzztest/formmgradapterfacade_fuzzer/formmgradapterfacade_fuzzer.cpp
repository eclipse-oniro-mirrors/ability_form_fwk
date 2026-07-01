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

#include "formmgradapterfacade_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "form_mgr/form_mgr_adapter_facade.h"

#include "form_constants.h"
#include "form_info.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "form_major_info.h"
#include "form_provider_data.h"
#include "form_record_filter.h"
#include "form_state_info.h"
#include "running_form_info.h"
#include "template_form_detail_info.h"
#include "form_custom_config.h"
#include "want.h"
#include "want_params.h"
#include "configuration.h"

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_VECTOR_SIZE = 10;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 1;
constexpr int32_t MAX_CALLING_UID = 10000;
constexpr int32_t MIN_CALLING_UID = 0;
constexpr int32_t MAX_DIMENSION_ID = 10;
constexpr int32_t MIN_DIMENSION_ID = 0;
constexpr int32_t MAX_DATA_SIZE = 1024;
constexpr int32_t MAX_USER_ID = 100;
constexpr int32_t MIN_USER_ID = 0;
constexpr int32_t MAX_VISIBLE_TYPE = 3;
constexpr int32_t MAX_REFRESH_TYPE = 10;
constexpr int32_t MAX_OPEN_TYPE = 10;
constexpr int32_t MAX_VERSION_CODE = 1000;
constexpr int32_t MIN_VERSION_CODE = 1;
constexpr int32_t MAX_FORM_LOCATION = 4;
constexpr int32_t MAX_FORM_TYPE = 2;
constexpr int32_t MAX_PRIVACY_LEVEL = 3;
constexpr int32_t MAX_HOUR = 23;
constexpr int32_t MAX_MINUTE = 59;
constexpr int32_t MAX_UPDATE_DURATION = 3600;
constexpr int32_t MAX_COMPATIBLE_VERSION = 100;
constexpr int32_t MIN_COMPATIBLE_VERSION = 1;

// ===================== Helper Functions =====================

Want GenerateWant(FuzzedDataProvider *fdp)
{
    Want want;
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string action = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    if (!bundleName.empty() && !abilityName.empty()) {
        want.SetElementName(bundleName, abilityName);
    }
    if (!action.empty()) {
        want.SetAction(action);
    }
    return want;
}

std::vector<int64_t> GenerateFormIds(FuzzedDataProvider *fdp)
{
    std::vector<int64_t> formIds;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        formIds.push_back(fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID));
    }
    return formIds;
}

FormRecord GenerateFormRecord(FuzzedDataProvider *fdp)
{
    FormRecord record;
    record.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.bundleName = bundleName.empty() ? "default.bundle" : bundleName;
    std::string moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.moduleName = moduleName.empty() ? "default.module" : moduleName;
    std::string abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.abilityName = abilityName.empty() ? "default.ability" : abilityName;
    std::string formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.formName = formName.empty() ? "default.form" : formName;
    record.specification = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    record.isEnableUpdate = fdp->ConsumeBool();
    record.formTempFlag = fdp->ConsumeBool();
    record.updateDuration = fdp->ConsumeIntegralInRange<int64_t>(0, MAX_UPDATE_DURATION);
    record.updateAtHour = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_HOUR);
    record.updateAtMin = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_MINUTE);
    record.providerUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    record.isDataProxy = fdp->ConsumeBool();
    record.isSystemApp = fdp->ConsumeBool();
    record.needRefresh = fdp->ConsumeBool();
    record.formLocation = static_cast<Constants::FormLocation>(fdp->ConsumeIntegralInRange<int32_t>(0,
        MAX_FORM_LOCATION));
    record.userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    record.uid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    record.versionCode = fdp->ConsumeIntegralInRange<uint32_t>(MIN_VERSION_CODE, MAX_VERSION_CODE);
    record.versionName = "1.0.0";
    record.compatibleVersion = fdp->ConsumeIntegralInRange<uint32_t>(MIN_COMPATIBLE_VERSION, MAX_COMPATIBLE_VERSION);
    record.type = static_cast<FormType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_TYPE));
    record.uiSyntax = static_cast<FormType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_TYPE));
    record.isDynamic = fdp->ConsumeBool();
    record.transparencyEnabled = fdp->ConsumeBool();
    record.privacyLevel = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_PRIVACY_LEVEL);
    return record;
}

std::vector<FormRecord> GenerateFormRecords(FuzzedDataProvider *fdp)
{
    std::vector<FormRecord> records;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        records.push_back(GenerateFormRecord(fdp));
    }
    return records;
}

FormProviderData GenerateFormProviderData(FuzzedDataProvider *fdp)
{
    std::string data = fdp->ConsumeRandomLengthString(MAX_DATA_SIZE);
    if (data.empty()) {
        data = "{}";
    }
    return FormProviderData(data);
}

std::vector<FormDataProxy> GenerateFormDataProxies(FuzzedDataProvider *fdp)
{
    std::vector<FormDataProxy> proxies;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
        std::string abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
        if (!bundleName.empty() && !abilityName.empty()) {
            proxies.push_back(FormDataProxy(bundleName, abilityName));
        }
    }
    return proxies;
}

FormMajorInfo GenerateFormMajorInfo(FuzzedDataProvider *fdp)
{
    FormMajorInfo info;
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    info.bundleName = bundleName.empty() ? "default.bundle" : bundleName;
    std::string moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    info.moduleName = moduleName.empty() ? "default.module" : moduleName;
    std::string abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    info.abilityName = abilityName.empty() ? "default.ability" : abilityName;
    std::string formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    info.formName = formName.empty() ? "default.form" : formName;
    info.dimension = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    return info;
}

// ===================== Main Fuzz Entry =====================

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &facade = FormMgrAdapterFacade::GetInstance();

    // ========== Excluded UNSAFE methods (25 total) ==========
    // The following methods are NOT fuzzed because they involve IPC proxy
    // calls, async task scheduling, FFRT queue operations, or sub-adapter
    // implementations that reach IPC/async code paths:
    //
    // Lifecycle:
    //   Init() - FormMgrQueue::ScheduleTask via DeleteInvalidFormCacheIfNeed
    //   AddForm() - FormRenderMgr::RenderForm (IPC to FRS) + AcquireProviderFormInfoAsync
    //   CastTempForm() - FormAmsHelper::ConnectServiceAbility (IPC to AMS)
    //
    // Data Update:
    //   RequestForm() - FormMgrQueue::ScheduleTask
    //   ReAcquireProviderFormInfoAsync() - FormMgrQueue::ScheduleTask
    //   AcquireProviderFormInfoByFormRecord() - async task scheduling
    //   DelayRefreshFormsOnAppUpgrade() - FormMgrQueue::ScheduleTask
    //
    // Query:
    //   AcquireFormState() - FormAmsHelper::ConnectServiceAbility (IPC to AMS)
    //   AcquireFormData() - FormAmsHelper::ConnectServiceAbility (IPC to AMS)
    //
    // Event:
    //   MessageEvent() - FormProviderMgr::MessageEvent (IPC to provider)
    //   RouterEvent() - FormAmsHelper::StartAbilityOnlyUIAbility (IPC to AMS)
    //   BackgroundEvent() - IN_PROCESS_CALL StartAbilityByCall (IPC to AMS)
    //   OpenByOpenType() - FormAmsHelper::StartAbility (IPC to AMS)
    //
    // Publish:
    //   RequestPublishForm() - FFRT ScheduleDelayTask + condition_variable
    //   RequestPublishFormCrossUser() - FFRT ScheduleDelayTask + condition_variable
    //   AcquireAddFormResult() - condition_variable::wait
    //
    // Callback (IPC proxy calls via iface_cast):
    //   StartAbilityByFms() - IPC: FormAmsHelper::StartAbility
    //   RequestOverflow() - IPC proxy->RequestOverflow
    //   ChangeSceneAnimationState() - IPC proxy->ChangeSceneAnimationState
    //   GetFormRect() - IPC proxy->GetFormRect
    //   GetLiveFormStatus() - IPC proxy->GetLiveFormStatus
    //   PublishFormCrossBundleControl() - IPC proxy->PublishFormCrossBundleControl
    //   UpdateTemplateFormDetailInfo() - IPC proxy->NotifyAllHosts
    //   UpdateFormsConfig() - IPC proxy->NotifyAllHosts
    //   DeleteForms() - IPC proxy->NotifyAllHosts

    // ========== 1. Lifecycle Management ==========
    // Excluded UNSAFE: AddForm (FormRenderMgr::RenderForm IPC + AcquireProviderFormInfoAsync)
    // Excluded UNSAFE: CastTempForm (FormAmsHelper::ConnectServiceAbility IPC)
    // Excluded UNSAFE: Init (FormMgrQueue::ScheduleTask)
    sptr<IRemoteObject> callerToken = nullptr;

    // CreateForm
    Want createWant = GenerateWant(fdp);
    RunningFormInfo createRunningInfo;
    facade.CreateForm(createWant, createRunningInfo);

    // DeleteForm
    int64_t deleteFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    facade.DeleteForm(deleteFormId, callerToken);

    // StopRenderingForm
    int64_t stopFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::string stopCompId = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    facade.StopRenderingForm(stopFormId, stopCompId);

    // ReleaseForm
    int64_t releaseFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    bool releaseDelCache = fdp->ConsumeBool();
    facade.ReleaseForm(releaseFormId, callerToken, releaseDelCache);

    // DeleteInvalidForms
    std::vector<int64_t> invalidFormIds = GenerateFormIds(fdp);
    int32_t numFormsDeleted = 0;
    facade.DeleteInvalidForms(invalidFormIds, callerToken, numFormsDeleted);

    // ReleaseRenderer
    int64_t rendererFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::string rendererCompId = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    facade.ReleaseRenderer(rendererFormId, rendererCompId);

    // EnableForms
    std::string enableBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t enableUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    bool enableFlag = fdp->ConsumeBool();
    facade.EnableForms(enableBundleName, enableUserId, enableFlag);

    // ProtectLockForms
    std::string protectBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t protectUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    bool protectFlag = fdp->ConsumeBool();
    facade.ProtectLockForms(protectBundleName, protectUserId, protectFlag);

    // SwitchLockForms
    std::string lockBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t lockUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    bool lockFlag = fdp->ConsumeBool();
    facade.SwitchLockForms(lockBundleName, lockUserId, lockFlag);

    // RecoverForms
    std::vector<int64_t> recoverFormIds = GenerateFormIds(fdp);
    Want recoverWant = GenerateWant(fdp);
    facade.RecoverForms(recoverFormIds, recoverWant);

    // BatchNotifyFormsConfigurationUpdate
    Configuration config;
    facade.BatchNotifyFormsConfigurationUpdate(config);

    // RecycleForms
    std::vector<int64_t> recycleFormIds = GenerateFormIds(fdp);
    Want recycleWant = GenerateWant(fdp);
    bool recycleCheckCallingUid = fdp->ConsumeBool();
    facade.RecycleForms(recycleFormIds, recycleWant, recycleCheckCallingUid);

    // HandleFormRemoveObserver
    RunningFormInfo removeObserverInfo;
    facade.HandleFormRemoveObserver(removeObserverInfo);

#ifdef RES_SCHEDULE_ENABLE
    // SetTimerTaskNeeded
    bool timerTaskNeeded = fdp->ConsumeBool();
    facade.SetTimerTaskNeeded(timerTaskNeeded);
#endif

    // ========== 2. Data Update Management ==========
    // Excluded UNSAFE: RequestForm (FormMgrQueue::ScheduleTask)
    // Excluded UNSAFE: ReAcquireProviderFormInfoAsync (FormMgrQueue::ScheduleTask)
    // Excluded UNSAFE: AcquireProviderFormInfoByFormRecord (async task scheduling)
    // Excluded UNSAFE: DelayRefreshFormsOnAppUpgrade (FormMgrQueue::ScheduleTask)

    // UpdateForm
    int64_t updateFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t updateCallingUid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    FormProviderData updateProviderData = GenerateFormProviderData(fdp);
    std::vector<FormDataProxy> updateDataProxies = GenerateFormDataProxies(fdp);
    facade.UpdateForm(updateFormId, updateCallingUid, updateProviderData, updateDataProxies);

    // UpdateFormSize (float version)
    int64_t sizeFloatFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    float width = fdp->ConsumeFloatingPoint<float>();
    float height = fdp->ConsumeFloatingPoint<float>();
    float borderWidth = fdp->ConsumeFloatingPoint<float>();
    float formViewScale = fdp->ConsumeFloatingPoint<float>();
    facade.UpdateFormSize(sizeFloatFormId, width, height, borderWidth, formViewScale);

    // UpdateFormSize (dimension version)
    int64_t sizeDimFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t newDimension = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    Rect newRect;
    newRect.left = fdp->ConsumeFloatingPoint<double>();
    newRect.top = fdp->ConsumeFloatingPoint<double>();
    newRect.width = fdp->ConsumeFloatingPoint<double>();
    newRect.height = fdp->ConsumeFloatingPoint<double>();
    facade.UpdateFormSize(sizeDimFormId, newDimension, newRect);

    // UpdateFormLocation
    int64_t locationFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t formLocationVal = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_LOCATION);
    bool isRequestPublishSnapshot = fdp->ConsumeBool();
    facade.UpdateFormLocation(locationFormId, formLocationVal, isRequestPublishSnapshot);

    // EnableUpdateForm
    std::vector<int64_t> enableUpdateFormIds = GenerateFormIds(fdp);
    facade.EnableUpdateForm(enableUpdateFormIds, callerToken);

    // DisableUpdateForm
    facade.DisableUpdateForm(enableUpdateFormIds, callerToken);

    // BatchRefreshForms
    int32_t batchRefreshType = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_REFRESH_TYPE);
    facade.BatchRefreshForms(batchRefreshType);

    // SetNextRefreshTime
    int64_t nextRefreshFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int64_t nextTime = fdp->ConsumeIntegral<int64_t>();
    facade.SetNextRefreshTime(nextRefreshFormId, nextTime);

    // ClearReconnectNum
    int64_t reconnectFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    facade.ClearReconnectNum(reconnectFormId);

    // ReloadForms
    int32_t reloadNum = 0;
    std::vector<FormRecord> refreshForms = GenerateFormRecords(fdp);
    facade.ReloadForms(reloadNum, refreshForms);

    // IsDeleteCacheInUpgradeScene
    FormRecord upgradeRecord = GenerateFormRecord(fdp);
    facade.IsDeleteCacheInUpgradeScene(upgradeRecord);

    // OnNotifyRefreshForm
    int64_t notifyRefreshFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    facade.OnNotifyRefreshForm(notifyRefreshFormId);

    // UpdateFormByCondition
    int32_t conditionType = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_REFRESH_TYPE);
    facade.UpdateFormByCondition(conditionType);

    // ========== 3. Common Management ==========

    // GetValidFormUpdateDuration
    int64_t durationFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int64_t updateDuration = 0;
    facade.GetValidFormUpdateDuration(durationFormId, updateDuration);

    // UpdateFormCloudUpdateDuration
    std::string cloudBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    facade.UpdateFormCloudUpdateDuration(cloudBundleName);

    // CheckFormDueControl
    FormMajorInfo dueControlInfo = GenerateFormMajorInfo(fdp);
    bool isDisablePolicy = fdp->ConsumeBool();
    facade.CheckFormDueControl(dueControlInfo, isDisablePolicy);

    // HandleFormAddObserver
    int64_t addObserverFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    facade.HandleFormAddObserver(addObserverFormId);

    // ========== 4. Visibility Management ==========

    // NotifyWhetherVisibleForms
    std::vector<int64_t> visibleFormIds = GenerateFormIds(fdp);
    int32_t formVisibleType = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VISIBLE_TYPE);
    facade.NotifyWhetherVisibleForms(visibleFormIds, callerToken, formVisibleType);

    // HasFormVisible
    uint32_t tokenId = static_cast<uint32_t>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_CALLING_UID));
    facade.HasFormVisible(tokenId);

    // NotifyFormsVisible
    std::vector<int64_t> notifyVisibleFormIds = GenerateFormIds(fdp);
    bool isVisible = fdp->ConsumeBool();
    facade.NotifyFormsVisible(notifyVisibleFormIds, isVisible, callerToken);

    // NotifyFormsEnableUpdate
    std::vector<int64_t> notifyEnableFormIds = GenerateFormIds(fdp);
    bool isEnableUpdate = fdp->ConsumeBool();
    facade.NotifyFormsEnableUpdate(notifyEnableFormIds, isEnableUpdate, callerToken);

    // HandlerNotifyWhetherVisibleForms
    std::vector<int64_t> handlerVisibleFormIds = GenerateFormIds(fdp);
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;
    int32_t handlerVisibleType = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VISIBLE_TYPE);
    facade.HandlerNotifyWhetherVisibleForms(handlerVisibleFormIds, formInstanceMaps, eventMaps,
        handlerVisibleType, callerToken);

    // PaddingNotifyVisibleFormsMap
    int32_t paddingVisibleType = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VISIBLE_TYPE);
    int64_t paddingFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::unordered_map<std::string, std::vector<FormInstance>> paddingMaps;
    facade.PaddingNotifyVisibleFormsMap(paddingVisibleType, paddingFormId, paddingMaps);

    // SetFormsRecyclable
    std::vector<int64_t> recyclableFormIds = GenerateFormIds(fdp);
    facade.SetFormsRecyclable(recyclableFormIds);

    // NotifyFormLocked
    int64_t lockedFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    bool isLocked = fdp->ConsumeBool();
    facade.NotifyFormLocked(lockedFormId, isLocked);

    // ========== 5. Query Management ==========

    // GetAllFormsInfo
    std::vector<FormInfo> allFormInfos;
    facade.GetAllFormsInfo(allFormInfos);

    // GetAllTemplateFormsInfo
    std::vector<FormInfo> allTemplateFormInfos;
    facade.GetAllTemplateFormsInfo(allTemplateFormInfos);

    // GetFormsInfoByApp
    std::string queryBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<FormInfo> appFormInfos;
    facade.GetFormsInfoByApp(queryBundleName, appFormInfos);

    // GetTemplateFormsInfoByApp
    std::vector<FormInfo> appTemplateFormInfos;
    facade.GetTemplateFormsInfoByApp(queryBundleName, appTemplateFormInfos);

    // GetFormsInfoByModule
    std::string queryModuleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<FormInfo> moduleFormInfos;
    facade.GetFormsInfoByModule(queryBundleName, queryModuleName, moduleFormInfos);

    // GetTemplateFormsInfoByModule
    std::vector<FormInfo> moduleTemplateFormInfos;
    facade.GetTemplateFormsInfoByModule(queryBundleName, queryModuleName, moduleTemplateFormInfos);

    // GetFormsInfoByFilter
    FormInfoFilter infoFilter;
    std::vector<FormInfo> filterFormInfos;
    facade.GetFormsInfoByFilter(infoFilter, filterFormInfos);

    // GetFormsCount
    bool isTempFormFlag = fdp->ConsumeBool();
    int32_t formCount = 0;
    facade.GetFormsCount(isTempFormFlag, formCount);

    // GetHostFormsCount
    std::string hostBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t hostFormCount = 0;
    facade.GetHostFormsCount(hostBundleName, hostFormCount);

    // GetFormInstanceById (1)
    int64_t instanceFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    FormInstance formInstance;
    facade.GetFormInstanceById(instanceFormId, formInstance);

    // GetFormInstanceById (2)
    bool isUnusedIncluded = fdp->ConsumeBool();
    FormInstance formInstance2;
    facade.GetFormInstanceById(instanceFormId, isUnusedIncluded, formInstance2);

    // GetRunningFormInfos
    bool runningIsUnused = fdp->ConsumeBool();
    std::vector<RunningFormInfo> runningFormInfos;
    int32_t runningUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    facade.GetRunningFormInfos(runningIsUnused, runningFormInfos, runningUserId);

    // GetRunningFormInfosByBundleName
    std::string runningBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    bool runningByBundleUnused = fdp->ConsumeBool();
    std::vector<RunningFormInfo> runningByBundleFormInfos;
    facade.GetRunningFormInfosByBundleName(runningBundleName, runningByBundleUnused, runningByBundleFormInfos);

    // GetFormInstancesByFilter
    FormInstancesFilter instancesFilter;
    std::vector<FormInstance> formInstances;
    facade.GetFormInstancesByFilter(instancesFilter, formInstances);

    // ========== 6. Observer Management ==========
    // Excluded UNSAFE: AcquireFormState (FormAmsHelper::ConnectServiceAbility IPC)
    // Excluded UNSAFE: AcquireFormData (FormAmsHelper::ConnectServiceAbility IPC)

    // RegisterFormAddObserverByBundle
    std::string observerBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    facade.RegisterFormAddObserverByBundle(observerBundleName, callerToken);

    // RegisterFormRemoveObserverByBundle
    std::string removeObserverBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    facade.RegisterFormRemoveObserverByBundle(removeObserverBundleName, callerToken);

    // RegisterAddObserver
    std::string addObserverBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    facade.RegisterAddObserver(addObserverBundleName, callerToken);

    // RegisterRemoveObserver
    std::string regRemoveBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    facade.RegisterRemoveObserver(regRemoveBundleName, callerToken);

    // RegisterClickEventObserver
    std::string clickBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string clickEventType = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    facade.RegisterClickEventObserver(clickBundleName, clickEventType, callerToken);

    // UnregisterClickEventObserver
    facade.UnregisterClickEventObserver(clickBundleName, clickEventType, callerToken);

    // CleanResource
    wptr<IRemoteObject> cleanRemote(nullptr);
    facade.CleanResource(cleanRemote);

    // ========== 7. Event Management ==========
    // Excluded UNSAFE: MessageEvent (FormProviderMgr::MessageEvent IPC to provider)
    // Excluded UNSAFE: RouterEvent (FormAmsHelper::StartAbilityOnlyUIAbility IPC to AMS)
    // Excluded UNSAFE: BackgroundEvent (IN_PROCESS_CALL StartAbilityByCall IPC to AMS)
    // Excluded UNSAFE: OpenByOpenType (FormAmsHelper::StartAbility IPC to AMS)

    // SetFreeInstallFlag
    FormRecord freeInstallRecord = GenerateFormRecord(fdp);
    Want freeInstallWant = GenerateWant(fdp);
    facade.SetFreeInstallFlag(freeInstallRecord, freeInstallWant);

    // ========== 8. Publish Management ==========

    // QueryPublishFormToHost (1)
    Want publishWant1 = GenerateWant(fdp);
    facade.QueryPublishFormToHost(publishWant1);

    // QueryPublishFormToHost (2)
    Want publishWant2 = GenerateWant(fdp);
    int32_t publishUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    facade.QueryPublishFormToHost(publishWant2, publishUserId);

    // RequestPublishFormCommon
    Want commonWant = GenerateWant(fdp);
    int32_t commonUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    int64_t commonFormId = 0;
    facade.RequestPublishFormCommon(commonWant, commonUserId, commonFormId);

    // RequestPublishFormCrossUser - UNSAFE: FFRT ScheduleDelayTask
    // RequestPublishForm - UNSAFE: FFRT ScheduleDelayTask
    // AcquireAddFormResult - UNSAFE: condition_variable wait

    // SetPublishFormResult
    int64_t publishResultFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Constants::PublishFormResult publishResult;
    publishResult.code = static_cast<Constants::PublishFormErrorCode>(
        fdp->ConsumeIntegralInRange<int32_t>(0, 10));
    facade.SetPublishFormResult(publishResultFormId, publishResult);

    // IsRequestPublishFormSupported
    facade.IsRequestPublishFormSupported();

    // ========== 9. Callback Management (Register/Unregister only) ==========
    // Excluded UNSAFE: StartAbilityByFms (IPC: FormAmsHelper::StartAbility)
    // Excluded UNSAFE: RequestOverflow (IPC proxy->RequestOverflow)
    // Excluded UNSAFE: ChangeSceneAnimationState (IPC proxy->ChangeSceneAnimationState)
    // Excluded UNSAFE: GetFormRect (IPC proxy->GetFormRect)
    // Excluded UNSAFE: GetLiveFormStatus (IPC proxy->GetLiveFormStatus)
    // Excluded UNSAFE: PublishFormCrossBundleControl (IPC proxy->PublishFormCrossBundleControl)
    // Excluded UNSAFE: UpdateTemplateFormDetailInfo (IPC proxy->NotifyAllHosts)
    // Excluded UNSAFE: UpdateFormsConfig (IPC proxy->NotifyAllHosts)
    // Excluded UNSAFE: DeleteForms (IPC proxy->NotifyAllHosts)
    // Only Register/Unregister proxy methods are SAFE (they just store nullptr proxy)

    // RegisterFormRouterProxy / UnregisterFormRouterProxy
    std::vector<int64_t> routerFormIds = GenerateFormIds(fdp);
    facade.RegisterFormRouterProxy(routerFormIds, callerToken);
    facade.UnregisterFormRouterProxy(routerFormIds);

    // RegisterPublishFormInterceptor / UnregisterPublishFormInterceptor
    sptr<IRemoteObject> interceptorCallback = nullptr;
    facade.RegisterPublishFormInterceptor(interceptorCallback);
    facade.UnregisterPublishFormInterceptor(interceptorCallback);

    // RegisterOverflowProxy / UnregisterOverflowProxy
    facade.RegisterOverflowProxy(callerToken);
    facade.UnregisterOverflowProxy();

    // RegisterChangeSceneAnimationStateProxy / UnregisterChangeSceneAnimationStateProxy
    facade.RegisterChangeSceneAnimationStateProxy(callerToken);
    facade.UnregisterChangeSceneAnimationStateProxy();

    // RegisterGetFormRectProxy / UnregisterGetFormRectProxy
    facade.RegisterGetFormRectProxy(callerToken);
    facade.UnregisterGetFormRectProxy();

    // RegisterGetLiveFormStatusProxy / UnregisterGetLiveFormStatusProxy
    facade.RegisterGetLiveFormStatusProxy(callerToken);
    facade.UnregisterGetLiveFormStatusProxy();

    // RegisterPublishFormCrossBundleControl / UnregisterPublishFormCrossBundleControl
    facade.RegisterPublishFormCrossBundleControl(callerToken);
    facade.UnregisterPublishFormCrossBundleControl();

    // RegisterTemplateFormDetailInfoChange / UnregisterTemplateFormDetailInfoChange
    facade.RegisterTemplateFormDetailInfoChange(callerToken);
    facade.UnregisterTemplateFormDetailInfoChange();

    // RegisterUpdateFormsConfigCallback / UnregisterUpdateFormsConfigCallback
    facade.RegisterUpdateFormsConfigCallback(callerToken);
    facade.UnregisterUpdateFormsConfigCallback();

    // RegisterDeleteFormsCallback / UnregisterDeleteFormsCallback
    facade.RegisterDeleteFormsCallback(callerToken);
    facade.UnregisterDeleteFormsCallback();

    // RegisterFormWantCallback / UnregisterFormWantCallback / GetWantCallbackProxy
    int32_t wantCallingUid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    facade.RegisterFormWantCallback(wantCallingUid, callerToken);
    facade.UnregisterFormWantCallback(wantCallingUid);
    sptr<IRemoteObject> wantProxy;
    facade.GetWantCallbackProxy(wantCallingUid, wantProxy);

    // ========== 10. Debug/Dump Management ==========

    // DumpStorageFormInfos
    std::string dumpStorageInfos;
    facade.DumpStorageFormInfos(dumpStorageInfos);

    // DumpTemporaryFormInfos
    std::string dumpTempInfos;
    facade.DumpTemporaryFormInfos(dumpTempInfos);

    // DumpStaticBundleFormInfos
    std::string dumpStaticInfos;
    facade.DumpStaticBundleFormInfos(dumpStaticInfos);

    // DumpHasFormVisible
    std::string dumpBundleInfo = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string dumpVisibleInfos;
    facade.DumpHasFormVisible(dumpBundleInfo, dumpVisibleInfos);

    // DumpFormInfoByBundleName
    std::string dumpBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string dumpBundleFormInfos;
    facade.DumpFormInfoByBundleName(dumpBundleName, dumpBundleFormInfos);

    // DumpFormInfoByFormId
    int64_t dumpFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::string dumpFormInfo;
    facade.DumpFormInfoByFormId(dumpFormId, dumpFormInfo);

    // DumpFormTimerByFormId
    int64_t dumpTimerFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::string dumpTimerInfo;
    facade.DumpFormTimerByFormId(dumpTimerFormId, dumpTimerInfo);

    // DumpFormRunningFormInfos
    std::string dumpRunningInfos;
    facade.DumpFormRunningFormInfos(dumpRunningInfos);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
