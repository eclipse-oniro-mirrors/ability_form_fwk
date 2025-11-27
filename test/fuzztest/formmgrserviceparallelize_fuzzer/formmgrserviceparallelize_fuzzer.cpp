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

#include "formmgrserviceparallelize_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>
#define private public
#define protected public
#include "form_mgr/form_mgr_service.h"
#undef private
#undef protected
#include "securec.h"
#include "token_setproc.h"
#include "form_js_info.h"
#include "running_form_info.h"
#include "form_provider_data.h"
#include "form_info_filter.h"
#include "form_state_info.h"
#include "form_share_info.h"
#include "form_lock_info.h"
#include "form_major_info.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "form_provider_data_proxy.h"
#include "want.h"

using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr long long TOKEN_ID = 718336240uLL;
constexpr long long OFFSET = 32;
class OHOS::AppExecFwk::FormMgrService* p_formMgrService = new OHOS::AppExecFwk::FormMgrService();

enum IpcCode : std::int16_t {
    ADD_FORM = 3001,
    // ADD_FORM_OHOS = 3002,
    DELETE_FORM = 3003,
    UPDATE_FORM = 3004,
    LIFECYCLE_UPDATE = 3005,
    REQUEST_FORM = 3006,
    RELEASE_FORM = 3007,
    // RELEASE_CACHED_FORM = 3008,
    CAST_TEMP_FORM = 3009,
    // EVENT_NOTIFY = 3010,
    // CHECK_AND_DELETE_INVALID_FORMS = 3011,
    SET_NEXT_REFRESH_TIME = 3012,
    NOTIFY_FORM_WHETHER_VISIBLE = 3013,
    STORAGE_FORM_INFOS = 3014,
    FORM_INFOS_BY_NAME = 3015,
    FORM_INFOS_BY_ID = 3016,
    FORM_TIMER_INFO_BY_ID = 3017,
    MESSAGE_EVENT = 3018,
    // BATCH_ADD_FORM_RECORDS_ST = 3019,
    // CLEAR_FORM_RECORDS_ST = 3020,
    // DISTRIBUTED_DATA_ADD_FORM_ST = 3021,
    // DISTRIBUTED_DATA_DELETE_FORM_ST = 3022,
    DELETE_INVALID_FORMS = 3023,
    ACQUIRE_FORM_STATE = 3024,
    NOTIFY_FORMS_VISIBLE = 3025,
    NOTIFY_FORMS_ENABLE_UPDATE = 3026,
    GET_ALL_FORMS_INFO = 3027,
    GET_FORMS_INFO_BY_APP = 3028,
    GET_FORMS_INFO_BY_MODULE = 3029,
    GET_FORMS_INFO = 3030,
    ROUTER_EVENT = 3031,
    // UPDATE_ROUTER_ACTION = 3032,
    // ADD_FORM_INFO = 3033,
    // REMOVE_FORM_INFO = 3034,
    REQUEST_PUBLISH_FORM = 3035,
    IS_REQUEST_PUBLISH_FORM_SUPPORTED = 3036,
    SHARE_FORM = 3037,
    RECV_FORM_SHARE_INFO_FROM_REMOTE = 3038,
    START_ABILITY = 3039,
    NOTIFY_FORMS_PRIVACY_PROTECTED = 3040,
    CHECK_FMS_READY = 3041,
    BACKGROUND_EVENT = 3042,
    STOP_RENDERING_FORM = 3043,
    REGISTER_FORM_ADD_OBSERVER_BY_BUNDLE = 3044,
    REGISTER_FORM_REMOVE_OBSERVER_BY_BUNDLE = 3045,
    ACQUIRE_DATA = 3046,
    GET_FORMS_COUNT = 3047,
    GET_HOST_FORMS_COUNT = 3048,
    GET_RUNNING_FORM_INFOS = 3049,
    GET_RUNNING_FORM_INFOS_BY_BUNDLE = 3050,
    GET_FORM_INSTANCES_BY_FILTER = 3051,
    GET_FORM_INSTANCES_BY_ID = 3052,
    REGISTER_ADD_OBSERVER = 3053,
    REGISTER_REMOVE_OBSERVER = 3054,
    UPDATE_PROXY_FORM = 3055,
    REQUEST_PUBLISH_PROXY_FORM = 3056,
    RELEASE_RENDERER = 3057,
    REGISTER_PUBLISH_FORM_INTERCEPTOR = 3058,
    UNREGISTER_PUBLISH_FORM_INTERCEPTOR = 3059,
    REGISTER_CLICK_EVENT_OBSERVER = 3060,
    UNREGISTER_CLICK_EVENT_OBSERVER = 3061,
    REGISTER_FORM_ROUTER_PROXY = 3062,
    UNREGISTER_FORM_ROUTER_PROXY = 3063,
    SET_FORMS_RECYCLABLE = 3064,
    RECYCLE_FORMS = 3065,
    RECOVER_FORMS = 3066,
    HAS_FORM_VISIBLE_WITH_TOKENID = 3067,
    UPDATE_FORM_LOCATION = 3068,
    GET_FORMS_INFO_BY_FILTER = 3069,
    CREATE_FORM = 3070,
    SET_PUBLISH_FORM_RESULT = 3071,
    ACQUIRE_ADD_FORM_RESULT = 3072,
    REQUEST_PUBLISH_FORM_WITH_SNAPSHOT = 3073,
    BATCH_REFRESH_FORMS = 3074,
    ENABLE_FORMS = 3075,
    IS_SYSTEM_APP_FORM = 3076,
    IS_FORM_BUNDLE_FORBIDDEN = 3077,
    UPDATE_FORM_SIZE = 3078,
    LOCK_FORMS = 3079,
    IS_FORM_BUNDLE_PROTECTED = 3080,
    IS_FORM_BUNDLE_EXEMPT = 3081,
    NOTIFY_FORM_LOCKED = 3082,
    START_ABILITY_BY_FMS = 3083,
    START_ABILITY_BY_CROSS_BUNDLE = 3084,
    GET_PUBLISHED_FORM_INFOS = 3085,
    GET_PUBLISHED_FORM_INFO_BY_ID = 3086,
    OPEN_FORM_EDIT_ABILITY = 3087,
    REGISTER_OVERFLOW_PROXY = 3088,
    UNREGISTER_OVERFLOW_PROXY = 3089,
    REQUEST_OVERFLOW = 3090,
    REGISTER_CHANGE_SCENEANIMATION_STATE_PROXY = 3091,
    UNREGISTER_CHANGE_SCENEANIMATION_STATE_PROXY = 3092,
    CHANGE_SCENE_ANIMATION_STATE = 3093,
    REGISTER_GET_FORM_RECT = 3094,
    UNREGISTER_GET_FORM_RECT = 3095,
    GET_FORM_RECT = 3096,
    NOTIFY_UPDATE_FORM_SIZE = 3097,
    REGISTER_GET_LIVE_FORM_STATUS = 3098,
    UNREGISTER_GET_LIVE_FORM_STATUS = 3099,
    IS_FORM_BUNDLE_DEBUG_SIGNATURE = 3100,
    RELOAD_FORMS = 3101,
    RELOAD_ALL_FORMS = 3102,
    IS_FORM_DUE_CONTROL = 3103,
    SEND_NON_TRANSPARENT_RATIO = 3104,
};

sptr<IRemoteObject> GetMockRemoteObject()
{
    return nullptr;
}

// Helper functions to fill structs with fuzzed data
void FillFormJsInfo(FuzzedDataProvider &provider, FormJsInfo &formInfo)
{
    formInfo.formId = provider.ConsumeIntegral<int64_t>();
    formInfo.formName = provider.ConsumeRandomLengthString(64);
    formInfo.bundleName = provider.ConsumeRandomLengthString(64);
    formInfo.abilityName = provider.ConsumeRandomLengthString(64);
    formInfo.moduleName = provider.ConsumeRandomLengthString(64);
    formInfo.formTempFlag = provider.ConsumeBool();
    formInfo.jsFormCodePath = provider.ConsumeRandomLengthString(128);
    formInfo.formData = provider.ConsumeRandomLengthString(256);
    formInfo.formSrc = provider.ConsumeRandomLengthString(128);
    formInfo.formWindow.designWidth = provider.ConsumeIntegral<int32_t>();
    formInfo.formWindow.autoDesignWidth = provider.ConsumeBool();
    formInfo.versionCode = provider.ConsumeIntegral<uint32_t>();
    formInfo.versionName = provider.ConsumeRandomLengthString(32);
    formInfo.compatibleVersion = provider.ConsumeIntegral<uint32_t>();
    formInfo.type = static_cast<FormType>(provider.ConsumeIntegralInRange<int32_t>(0, 2));
    formInfo.uiSyntax = static_cast<FormType>(provider.ConsumeIntegralInRange<int32_t>(0, 2));
    formInfo.isDynamic = provider.ConsumeBool();
    formInfo.transparencyEnabled = provider.ConsumeBool();
}

void FillRunningFormInfo(FuzzedDataProvider &provider, RunningFormInfo &formInfo)
{
    formInfo.formId = provider.ConsumeIntegral<int64_t>();
    formInfo.formName = provider.ConsumeRandomLengthString(64);
    formInfo.bundleName = provider.ConsumeRandomLengthString(64);
    formInfo.moduleName = provider.ConsumeRandomLengthString(64);
    formInfo.abilityName = provider.ConsumeRandomLengthString(64);
    formInfo.description = provider.ConsumeRandomLengthString(128);
    formInfo.dimension = provider.ConsumeIntegral<int32_t>();
    formInfo.hostBundleName = provider.ConsumeRandomLengthString(64);
    formInfo.formLocation = static_cast<Constants::FormLocation>(
        provider.ConsumeIntegralInRange<int32_t>(0, 3));
    formInfo.formVisiblity = static_cast<FormVisibilityType>(
        provider.ConsumeIntegralInRange<int32_t>(0, 2));
    formInfo.formUsageState = static_cast<FormUsageState>(
        provider.ConsumeIntegralInRange<int32_t>(0, 1));
    formInfo.appIndex = provider.ConsumeIntegral<int32_t>();
    formInfo.userId = provider.ConsumeIntegral<int32_t>();
}

void FillFormProviderData(FuzzedDataProvider &provider, FormProviderData &data)
{
    std::string jsonStr = "{\"key\":\"" + provider.ConsumeRandomLengthString(32) + "\"}";
    data = FormProviderData(jsonStr);
}

void FillFormInfoFilter(FuzzedDataProvider &provider, FormInfoFilter &filter)
{
    filter.bundleName = provider.ConsumeRandomLengthString(64);
    filter.moduleName = provider.ConsumeRandomLengthString(64);
    size_t dimCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
    for (size_t i = 0; i < dimCount; ++i) {
        filter.supportDimensions.push_back(provider.ConsumeIntegral<int32_t>());
    }
    size_t shapeCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
    for (size_t i = 0; i < shapeCount; ++i) {
        filter.supportShapes.push_back(provider.ConsumeIntegral<int32_t>());
    }
}

void FillFormStateInfo(FuzzedDataProvider &provider, FormStateInfo &stateInfo)
{
    stateInfo.state = static_cast<FormState>(
        provider.ConsumeIntegralInRange<int32_t>(0, 2));
    // Want is already filled by default constructor
}

void FillFormShareInfo(FuzzedDataProvider &provider, FormShareInfo &info)
{
    info.formId = provider.ConsumeIntegral<int64_t>();
    info.formName = provider.ConsumeRandomLengthString(64);
    info.bundleName = provider.ConsumeRandomLengthString(64);
    info.moduleName = provider.ConsumeRandomLengthString(64);
    info.abilityName = provider.ConsumeRandomLengthString(64);
    info.formTempFlag = provider.ConsumeBool();
    info.dimensionId = provider.ConsumeIntegral<int32_t>();
    info.deviceId = provider.ConsumeRandomLengthString(64);
    info.isFreeInstall = provider.ConsumeBool();
}

void FillFormLockInfo(FuzzedDataProvider &provider, FormLockInfo &info)
{
    info.bundleName = provider.ConsumeRandomLengthString(64);
    info.userId = provider.ConsumeIntegral<int32_t>();
    info.lock = provider.ConsumeBool();
}

void FillFormMajorInfo(FuzzedDataProvider &provider, FormMajorInfo &info)
{
    info.bundleName = provider.ConsumeRandomLengthString(64);
    info.moduleName = provider.ConsumeRandomLengthString(64);
    info.abilityName = provider.ConsumeRandomLengthString(64);
    info.formName = provider.ConsumeRandomLengthString(64);
    info.dimension = provider.ConsumeIntegral<int32_t>();
}

void FillFormInstancesFilter(FuzzedDataProvider &provider, FormInstancesFilter &filter)
{
    filter.bundleName = provider.ConsumeRandomLengthString(64);
    filter.formName = provider.ConsumeRandomLengthString(64);
    filter.moduleName = provider.ConsumeRandomLengthString(64);
    filter.abilityName = provider.ConsumeRandomLengthString(64);
    filter.isUnusedIncluded = provider.ConsumeBool();
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    if (SetSelfTokenID(TOKEN_ID | (1uLL << OHOS::OFFSET)) < 0) {
        return -1;
    }

    if (p_formMgrService == nullptr) {
        return -1;
    }

    OHOS::p_formMgrService->OnStart();
    return 0;
}

extern "C" int FuzzIFormMgrService(FuzzedDataProvider &provider)
{
    if (p_formMgrService == nullptr) {
        return 0;
    }

    static const int ipcCodes[] = {
        IpcCode::ADD_FORM, IpcCode::CREATE_FORM, IpcCode::DELETE_FORM,
        IpcCode::STOP_RENDERING_FORM, IpcCode::RELEASE_FORM, IpcCode::UPDATE_FORM,
        IpcCode::SET_NEXT_REFRESH_TIME, IpcCode::RELEASE_RENDERER,
        IpcCode::REQUEST_PUBLISH_FORM, IpcCode::SET_PUBLISH_FORM_RESULT,
        IpcCode::ACQUIRE_ADD_FORM_RESULT, IpcCode::LIFECYCLE_UPDATE,
        IpcCode::REQUEST_FORM, IpcCode::NOTIFY_FORM_WHETHER_VISIBLE,
        IpcCode::HAS_FORM_VISIBLE_WITH_TOKENID, IpcCode::CAST_TEMP_FORM,
        IpcCode::STORAGE_FORM_INFOS, IpcCode::FORM_INFOS_BY_NAME,
        IpcCode::FORM_INFOS_BY_ID, IpcCode::FORM_TIMER_INFO_BY_ID,
        IpcCode::MESSAGE_EVENT, IpcCode::ROUTER_EVENT, IpcCode::BACKGROUND_EVENT,
        IpcCode::DELETE_INVALID_FORMS, IpcCode::ACQUIRE_FORM_STATE,
        IpcCode::NOTIFY_FORMS_VISIBLE, IpcCode::NOTIFY_FORMS_PRIVACY_PROTECTED,
        IpcCode::NOTIFY_FORMS_ENABLE_UPDATE,
        IpcCode::GET_ALL_FORMS_INFO, IpcCode::GET_FORMS_INFO_BY_APP,
        IpcCode::GET_FORMS_INFO_BY_MODULE, IpcCode::GET_FORMS_INFO,
        IpcCode::GET_FORMS_INFO_BY_FILTER, IpcCode::IS_REQUEST_PUBLISH_FORM_SUPPORTED,
        IpcCode::START_ABILITY, IpcCode::START_ABILITY_BY_FMS,
        IpcCode::START_ABILITY_BY_CROSS_BUNDLE, IpcCode::SHARE_FORM,
        IpcCode::ACQUIRE_DATA, IpcCode::RECV_FORM_SHARE_INFO_FROM_REMOTE,
        IpcCode::CHECK_FMS_READY, IpcCode::IS_SYSTEM_APP_FORM,
        IpcCode::REGISTER_FORM_ADD_OBSERVER_BY_BUNDLE,
        IpcCode::REGISTER_FORM_REMOVE_OBSERVER_BY_BUNDLE,
        IpcCode::GET_FORMS_COUNT,
        IpcCode::GET_HOST_FORMS_COUNT, IpcCode::GET_RUNNING_FORM_INFOS,
        IpcCode::GET_RUNNING_FORM_INFOS_BY_BUNDLE,
        IpcCode::GET_FORM_INSTANCES_BY_FILTER, IpcCode::GET_FORM_INSTANCES_BY_ID,
        IpcCode::REGISTER_ADD_OBSERVER, IpcCode::REGISTER_REMOVE_OBSERVER,
        IpcCode::UPDATE_PROXY_FORM, IpcCode::REQUEST_PUBLISH_PROXY_FORM,
        IpcCode::REGISTER_PUBLISH_FORM_INTERCEPTOR,
        IpcCode::UNREGISTER_PUBLISH_FORM_INTERCEPTOR,
        IpcCode::REGISTER_CLICK_EVENT_OBSERVER,
        IpcCode::UNREGISTER_CLICK_EVENT_OBSERVER,
        IpcCode::REGISTER_FORM_ROUTER_PROXY, IpcCode::UNREGISTER_FORM_ROUTER_PROXY,
        IpcCode::SET_FORMS_RECYCLABLE, IpcCode::RECYCLE_FORMS,
        IpcCode::RECOVER_FORMS, IpcCode::UPDATE_FORM_LOCATION,
        IpcCode::REQUEST_PUBLISH_FORM_WITH_SNAPSHOT, IpcCode::BATCH_REFRESH_FORMS,
        IpcCode::ENABLE_FORMS, IpcCode::IS_FORM_BUNDLE_FORBIDDEN,
        IpcCode::UPDATE_FORM_SIZE, IpcCode::LOCK_FORMS,
        IpcCode::IS_FORM_BUNDLE_PROTECTED, IpcCode::IS_FORM_BUNDLE_EXEMPT,
        IpcCode::NOTIFY_FORM_LOCKED, IpcCode::GET_PUBLISHED_FORM_INFOS,
        IpcCode::GET_PUBLISHED_FORM_INFO_BY_ID, IpcCode::OPEN_FORM_EDIT_ABILITY,
        IpcCode::REGISTER_OVERFLOW_PROXY, IpcCode::UNREGISTER_OVERFLOW_PROXY,
        IpcCode::REQUEST_OVERFLOW, IpcCode::REGISTER_CHANGE_SCENEANIMATION_STATE_PROXY,
        IpcCode::UNREGISTER_CHANGE_SCENEANIMATION_STATE_PROXY,
        IpcCode::CHANGE_SCENE_ANIMATION_STATE, IpcCode::REGISTER_GET_FORM_RECT,
        IpcCode::UNREGISTER_GET_FORM_RECT, IpcCode::GET_FORM_RECT,
        IpcCode::NOTIFY_UPDATE_FORM_SIZE, IpcCode::REGISTER_GET_LIVE_FORM_STATUS,
        IpcCode::UNREGISTER_GET_LIVE_FORM_STATUS, IpcCode::IS_FORM_BUNDLE_DEBUG_SIGNATURE,
        IpcCode::RELOAD_FORMS, IpcCode::RELOAD_ALL_FORMS,
        IpcCode::IS_FORM_DUE_CONTROL, IpcCode::SEND_NON_TRANSPARENT_RATIO
    };
    int code = provider.PickValueInArray(ipcCodes);

    switch (code) {
        case IpcCode::ADD_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Want want;
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            FormJsInfo formInfo;
            FillFormJsInfo(provider, formInfo);
            OHOS::p_formMgrService->AddForm(formId, want, callerToken, formInfo);
            break;
        }
        case IpcCode::CREATE_FORM: {
            Want want;
            RunningFormInfo runningFormInfo;
            FillRunningFormInfo(provider, runningFormInfo);
            OHOS::p_formMgrService->CreateForm(want, runningFormInfo);
            break;
        }
        case IpcCode::DELETE_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->DeleteForm(formId, callerToken);
            break;
        }
        case IpcCode::STOP_RENDERING_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            std::string compId = provider.ConsumeRandomLengthString(64);
            OHOS::p_formMgrService->StopRenderingForm(formId, compId);
            break;
        }
        case IpcCode::RELEASE_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            bool delCache = provider.ConsumeBool();
            OHOS::p_formMgrService->ReleaseForm(formId, callerToken, delCache);
            break;
        }
        case IpcCode::UPDATE_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            FormProviderData formProviderData;
            FillFormProviderData(provider, formProviderData);
            OHOS::p_formMgrService->UpdateForm(formId, formProviderData);
            break;
        }
        case IpcCode::SET_NEXT_REFRESH_TIME: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            int64_t nextTime = provider.ConsumeIntegral<int64_t>();
            OHOS::p_formMgrService->SetNextRefreshTime(formId, nextTime);
            break;
        }
        case IpcCode::RELEASE_RENDERER: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            std::string compId = provider.ConsumeRandomLengthString(64);
            OHOS::p_formMgrService->ReleaseRenderer(formId, compId);
            break;
        }
        case IpcCode::REQUEST_PUBLISH_FORM: {
            Want want;
            bool withFormBindingData = provider.ConsumeBool();
            std::unique_ptr<FormProviderData> formBindingData = nullptr;
            if (withFormBindingData) {
                formBindingData = std::make_unique<FormProviderData>();
                FillFormProviderData(provider, *formBindingData);
            }
            int64_t formId = 0;
            OHOS::p_formMgrService->RequestPublishForm(want, withFormBindingData, formBindingData, formId);
            break;
        }
        case IpcCode::SET_PUBLISH_FORM_RESULT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Constants::PublishFormResult errorCodeInfo;
            errorCodeInfo.message = provider.ConsumeRandomLengthString(128);
            errorCodeInfo.code = static_cast<Constants::PublishFormErrorCode>(
                provider.ConsumeIntegralInRange<int32_t>(0, 10));
            OHOS::p_formMgrService->SetPublishFormResult(formId, errorCodeInfo);
            break;
        }
        case IpcCode::ACQUIRE_ADD_FORM_RESULT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            OHOS::p_formMgrService->AcquireAddFormResult(formId);
            break;
        }
        case IpcCode::LIFECYCLE_UPDATE: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            bool updateType = provider.ConsumeBool();
            OHOS::p_formMgrService->LifecycleUpdate(formIds, callerToken, updateType);
            break;
        }
        case IpcCode::REQUEST_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            Want want;
            OHOS::p_formMgrService->RequestForm(formId, callerToken, want);
            break;
        }
        case IpcCode::NOTIFY_FORM_WHETHER_VISIBLE: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            int32_t formVisibleType = provider.ConsumeIntegralInRange<int32_t>(0, 1);
            OHOS::p_formMgrService->NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType);
            break;
        }
        case IpcCode::HAS_FORM_VISIBLE_WITH_TOKENID: {
            uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
            OHOS::p_formMgrService->HasFormVisible(tokenId);
            break;
        }
        case IpcCode::CAST_TEMP_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->CastTempForm(formId, callerToken);
            break;
        }
        case IpcCode::STORAGE_FORM_INFOS: {
            std::string formInfos;
            OHOS::p_formMgrService->DumpStorageFormInfos(formInfos);
            break;
        }
        case IpcCode::FORM_INFOS_BY_NAME: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            std::string formInfos;
            OHOS::p_formMgrService->DumpFormInfoByBundleName(bundleName, formInfos);
            break;
        }
        case IpcCode::FORM_INFOS_BY_ID: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            std::string formInfo;
            OHOS::p_formMgrService->DumpFormInfoByFormId(formId, formInfo);
            break;
        }
        case IpcCode::FORM_TIMER_INFO_BY_ID: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            std::string isTimingService;
            OHOS::p_formMgrService->DumpFormTimerByFormId(formId, isTimingService);
            break;
        }
        case IpcCode::MESSAGE_EVENT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Want want;
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->MessageEvent(formId, want, callerToken);
            break;
        }
        case IpcCode::ROUTER_EVENT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Want want;
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->RouterEvent(formId, want, callerToken);
            break;
        }
        case IpcCode::BACKGROUND_EVENT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Want want;
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->BackgroundEvent(formId, want, callerToken);
            break;
        }
        case IpcCode::DELETE_INVALID_FORMS: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            int32_t numFormsDeleted = 0;
            OHOS::p_formMgrService->DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
            break;
        }
        case IpcCode::ACQUIRE_FORM_STATE: {
            Want want;
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            FormStateInfo stateInfo;
            FillFormStateInfo(provider, stateInfo);
            OHOS::p_formMgrService->AcquireFormState(want, callerToken, stateInfo);
            break;
        }
        case IpcCode::NOTIFY_FORMS_VISIBLE: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            bool isVisible = provider.ConsumeBool();
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->NotifyFormsVisible(formIds, isVisible, callerToken);
            break;
        }
        case IpcCode::NOTIFY_FORMS_PRIVACY_PROTECTED: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            bool isProtected = provider.ConsumeBool();
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->NotifyFormsPrivacyProtected(formIds, isProtected, callerToken);
            break;
        }
        case IpcCode::NOTIFY_FORMS_ENABLE_UPDATE: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            bool isEnableUpdate = provider.ConsumeBool();
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken);
            break;
        }
        case IpcCode::GET_ALL_FORMS_INFO: {
            std::vector<FormInfo> formInfos;
            OHOS::p_formMgrService->GetAllFormsInfo(formInfos);
            break;
        }
        case IpcCode::GET_FORMS_INFO_BY_APP: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            std::vector<FormInfo> formInfos;
            OHOS::p_formMgrService->GetFormsInfoByApp(bundleName, formInfos);
            break;
        }
        case IpcCode::GET_FORMS_INFO_BY_MODULE: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            std::string moduleName = provider.ConsumeRandomLengthString(64);
            std::vector<FormInfo> formInfos;
            OHOS::p_formMgrService->GetFormsInfoByModule(bundleName, moduleName, formInfos);
            break;
        }
        case IpcCode::GET_FORMS_INFO: {
            FormInfoFilter filter;
            FillFormInfoFilter(provider, filter);
            std::vector<FormInfo> formInfos;
            OHOS::p_formMgrService->GetFormsInfo(filter, formInfos);
            break;
        }
        case IpcCode::GET_FORMS_INFO_BY_FILTER: {
            FormInfoFilter filter;
            FillFormInfoFilter(provider, filter);
            std::vector<FormInfo> formInfos;
            OHOS::p_formMgrService->GetFormsInfoByFilter(filter, formInfos);
            break;
        }
        case IpcCode::IS_REQUEST_PUBLISH_FORM_SUPPORTED: {
            OHOS::p_formMgrService->IsRequestPublishFormSupported();
            break;
        }
        case IpcCode::START_ABILITY: {
            Want want;
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->StartAbility(want, callerToken);
            break;
        }
        case IpcCode::START_ABILITY_BY_FMS: {
            Want want;
            OHOS::p_formMgrService->StartAbilityByFms(want);
            break;
        }
        case IpcCode::START_ABILITY_BY_CROSS_BUNDLE: {
            Want want;
            OHOS::p_formMgrService->StartAbilityByCrossBundle(want);
            break;
        }
        case IpcCode::SHARE_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            std::string deviceId = provider.ConsumeRandomLengthString(64);
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            int64_t requestCode = provider.ConsumeIntegral<int64_t>();
            OHOS::p_formMgrService->ShareForm(formId, deviceId, callerToken, requestCode);
            break;
        }
        case IpcCode::ACQUIRE_DATA: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            int64_t requestCode = provider.ConsumeIntegral<int64_t>();
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            AAFwk::WantParams formData;
            OHOS::p_formMgrService->AcquireFormData(formId, requestCode, callerToken, formData);
            break;
        }
        case IpcCode::RECV_FORM_SHARE_INFO_FROM_REMOTE: {
            FormShareInfo info;
            FillFormShareInfo(provider, info);
            OHOS::p_formMgrService->RecvFormShareInfoFromRemote(info);
            break;
        }
        case IpcCode::CHECK_FMS_READY: {
            OHOS::p_formMgrService->CheckFMSReady();
            break;
        }
        case IpcCode::IS_SYSTEM_APP_FORM: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            OHOS::p_formMgrService->IsSystemAppForm(bundleName);
            break;
        }
        case IpcCode::REGISTER_FORM_ADD_OBSERVER_BY_BUNDLE: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->RegisterFormAddObserverByBundle(bundleName, callerToken);
            break;
        }
        case IpcCode::REGISTER_FORM_REMOVE_OBSERVER_BY_BUNDLE: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->RegisterFormRemoveObserverByBundle(bundleName, callerToken);
            break;
        }
        case IpcCode::GET_FORMS_COUNT: {
            bool isTempFormFlag = provider.ConsumeBool();
            int32_t formCount = 0;
            OHOS::p_formMgrService->GetFormsCount(isTempFormFlag, formCount);
            break;
        }
        case IpcCode::GET_HOST_FORMS_COUNT: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            int32_t formCount = 0;
            OHOS::p_formMgrService->GetHostFormsCount(bundleName, formCount);
            break;
        }
        case IpcCode::GET_RUNNING_FORM_INFOS: {
            bool isUnusedIncluded = provider.ConsumeBool();
            std::vector<RunningFormInfo> runningFormInfos;
            OHOS::p_formMgrService->GetRunningFormInfos(isUnusedIncluded, runningFormInfos);
            break;
        }
        case IpcCode::GET_RUNNING_FORM_INFOS_BY_BUNDLE: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            bool isUnusedIncluded = provider.ConsumeBool();
            std::vector<RunningFormInfo> runningFormInfos;
            OHOS::p_formMgrService->GetRunningFormInfosByBundleName(bundleName, isUnusedIncluded, runningFormInfos);
            break;
        }
        case IpcCode::GET_FORM_INSTANCES_BY_FILTER: {
            FormInstancesFilter filter;
            FillFormInstancesFilter(provider, filter);
            std::vector<FormInstance> formInstances;
            OHOS::p_formMgrService->GetFormInstancesByFilter(filter, formInstances);
            break;
        }
        case IpcCode::GET_FORM_INSTANCES_BY_ID: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            FormInstance formInstance;
            OHOS::p_formMgrService->GetFormInstanceById(formId, formInstance);
            break;
        }
        case IpcCode::REGISTER_ADD_OBSERVER: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->RegisterAddObserver(bundleName, callerToken);
            break;
        }
        case IpcCode::REGISTER_REMOVE_OBSERVER: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->RegisterRemoveObserver(bundleName, callerToken);
            break;
        }
        case IpcCode::UPDATE_PROXY_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            FormProviderData formProviderData;
            FillFormProviderData(provider, formProviderData);
            std::vector<FormDataProxy> formDataProxies;
            size_t proxyCount = provider.ConsumeIntegralInRange<size_t>(0, 4);
            for (size_t i = 0; i < proxyCount; ++i) {
                std::string key = provider.ConsumeRandomLengthString(32);
                std::string subscribeId = provider.ConsumeRandomLengthString(32);
                formDataProxies.emplace_back(key, subscribeId);
            }
            OHOS::p_formMgrService->UpdateProxyForm(formId, formProviderData, formDataProxies);
            break;
        }
        case IpcCode::REQUEST_PUBLISH_PROXY_FORM: {
            Want want;
            bool withFormBindingData = provider.ConsumeBool();
            std::unique_ptr<FormProviderData> formBindingData = nullptr;
            if (withFormBindingData) {
                formBindingData = std::make_unique<FormProviderData>();
                FillFormProviderData(provider, *formBindingData);
            }
            int64_t formId = 0;
            std::vector<FormDataProxy> formDataProxies;
            size_t proxyCount = provider.ConsumeIntegralInRange<size_t>(0, 4);
            for (size_t i = 0; i < proxyCount; ++i) {
                std::string key = provider.ConsumeRandomLengthString(32);
                std::string subscribeId = provider.ConsumeRandomLengthString(32);
                formDataProxies.emplace_back(key, subscribeId);
            }
            OHOS::p_formMgrService->RequestPublishProxyForm(want, withFormBindingData, formBindingData, formId, formDataProxies);
            break;
        }
        case IpcCode::REGISTER_PUBLISH_FORM_INTERCEPTOR: {
            sptr<IRemoteObject> interceptorCallback = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->RegisterPublishFormInterceptor(interceptorCallback);
            break;
        }
        case IpcCode::UNREGISTER_PUBLISH_FORM_INTERCEPTOR: {
            sptr<IRemoteObject> interceptorCallback = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->UnregisterPublishFormInterceptor(interceptorCallback);
            break;
        }
        case IpcCode::REGISTER_CLICK_EVENT_OBSERVER: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            std::string formEventType = provider.ConsumeRandomLengthString(32);
            sptr<IRemoteObject> observer = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->RegisterClickEventObserver(bundleName, formEventType, observer);
            break;
        }
        case IpcCode::UNREGISTER_CLICK_EVENT_OBSERVER: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            std::string formEventType = provider.ConsumeRandomLengthString(32);
            sptr<IRemoteObject> observer = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->UnregisterClickEventObserver(bundleName, formEventType, observer);
            break;
        }
        case IpcCode::REGISTER_FORM_ROUTER_PROXY: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->RegisterFormRouterProxy(formIds, callerToken);
            break;
        }
        case IpcCode::UNREGISTER_FORM_ROUTER_PROXY: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            OHOS::p_formMgrService->UnregisterFormRouterProxy(formIds);
            break;
        }
        case IpcCode::SET_FORMS_RECYCLABLE: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            OHOS::p_formMgrService->SetFormsRecyclable(formIds);
            break;
        }
        case IpcCode::RECYCLE_FORMS: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            Want want;
            OHOS::p_formMgrService->RecycleForms(formIds, want);
            break;
        }
        case IpcCode::RECOVER_FORMS: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            Want want;
            OHOS::p_formMgrService->RecoverForms(formIds, want);
            break;
        }
        case IpcCode::UPDATE_FORM_LOCATION: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            int32_t formLocation = provider.ConsumeIntegralInRange<int32_t>(0, 3);
            OHOS::p_formMgrService->UpdateFormLocation(formId, formLocation);
            break;
        }
        case IpcCode::REQUEST_PUBLISH_FORM_WITH_SNAPSHOT: {
            Want want;
            bool withFormBindingData = provider.ConsumeBool();
            std::unique_ptr<FormProviderData> formBindingData = nullptr;
            if (withFormBindingData) {
                formBindingData = std::make_unique<FormProviderData>();
                FillFormProviderData(provider, *formBindingData);
            }
            int64_t formId = 0;
            OHOS::p_formMgrService->RequestPublishFormWithSnapshot(want, withFormBindingData, formBindingData, formId);
            break;
        }
        case IpcCode::BATCH_REFRESH_FORMS: {
            int32_t formRefreshType = provider.ConsumeIntegralInRange<int32_t>(0, 2);
            OHOS::p_formMgrService->BatchRefreshForms(formRefreshType);
            break;
        }
        case IpcCode::ENABLE_FORMS: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            int32_t userId = provider.ConsumeIntegral<int32_t>();
            bool enable = provider.ConsumeBool();
            OHOS::p_formMgrService->EnableForms(bundleName, userId, enable);
            break;
        }
        case IpcCode::IS_FORM_BUNDLE_FORBIDDEN: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            OHOS::p_formMgrService->IsFormBundleForbidden(bundleName);
            break;
        }
        case IpcCode::UPDATE_FORM_SIZE: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            float width = provider.ConsumeFloatingPoint<float>();
            float height = provider.ConsumeFloatingPoint<float>();
            float borderWidth = provider.ConsumeFloatingPoint<float>();
            float formViewScale = provider.ConsumeFloatingPoint<float>();
            OHOS::p_formMgrService->UpdateFormSize(formId, width, height, borderWidth, formViewScale);
            break;
        }
        case IpcCode::LOCK_FORMS: {
            size_t formLockInfosCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<FormLockInfo> formLockInfos;
            for (size_t i = 0; i < formLockInfosCount; ++i) {
                FormLockInfo info;
                FillFormLockInfo(provider, info);
                formLockInfos.push_back(info);
            }
            LockChangeType type = static_cast<LockChangeType>(
                provider.ConsumeIntegralInRange<int32_t>(0, 1));
            OHOS::p_formMgrService->LockForms(formLockInfos, type);
            break;
        }
        case IpcCode::IS_FORM_BUNDLE_PROTECTED: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            OHOS::p_formMgrService->IsFormBundleProtected(bundleName, formId);
            break;
        }
        case IpcCode::IS_FORM_BUNDLE_EXEMPT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            OHOS::p_formMgrService->IsFormBundleExempt(formId);
            break;
        }
        case IpcCode::NOTIFY_FORM_LOCKED: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            bool isLocked = provider.ConsumeBool();
            OHOS::p_formMgrService->NotifyFormLocked(formId, isLocked);
            break;
        }
        case IpcCode::GET_PUBLISHED_FORM_INFOS: {
            std::vector<RunningFormInfo> formInfos;
            OHOS::p_formMgrService->GetPublishedFormInfos(formInfos);
            break;
        }
        case IpcCode::GET_PUBLISHED_FORM_INFO_BY_ID: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            RunningFormInfo formInfo;
            OHOS::p_formMgrService->GetPublishedFormInfoById(formId, formInfo);
            break;
        }
        case IpcCode::OPEN_FORM_EDIT_ABILITY: {
            std::string abilityName = provider.ConsumeRandomLengthString(64);
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            bool isMainPage = provider.ConsumeBool();
            OHOS::p_formMgrService->OpenFormEditAbility(abilityName, formId, isMainPage);
            break;
        }
        case IpcCode::REGISTER_OVERFLOW_PROXY: {
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->RegisterOverflowProxy(callerToken);
            break;
        }
        case IpcCode::UNREGISTER_OVERFLOW_PROXY: {
            OHOS::p_formMgrService->UnregisterOverflowProxy();
            break;
        }
        case IpcCode::REQUEST_OVERFLOW: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            OverflowInfo overflowInfo;
            overflowInfo.area.left = provider.ConsumeFloatingPoint<double>();
            overflowInfo.area.top = provider.ConsumeFloatingPoint<double>();
            overflowInfo.area.width = provider.ConsumeFloatingPoint<double>();
            overflowInfo.area.height = provider.ConsumeFloatingPoint<double>();
            overflowInfo.duration = provider.ConsumeIntegral<int32_t>();
            overflowInfo.useDefaultAnimation = provider.ConsumeBool();
            bool isOverflow = provider.ConsumeBool();
            OHOS::p_formMgrService->RequestOverflow(formId, overflowInfo, isOverflow);
            break;
        }
        case IpcCode::REGISTER_CHANGE_SCENEANIMATION_STATE_PROXY: {
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->RegisterChangeSceneAnimationStateProxy(callerToken);
            break;
        }
        case IpcCode::UNREGISTER_CHANGE_SCENEANIMATION_STATE_PROXY: {
            OHOS::p_formMgrService->UnregisterChangeSceneAnimationStateProxy();
            break;
        }
        case IpcCode::CHANGE_SCENE_ANIMATION_STATE: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            int32_t state = provider.ConsumeIntegralInRange<int32_t>(0, 1);
            OHOS::p_formMgrService->ChangeSceneAnimationState(formId, state);
            break;
        }
        case IpcCode::REGISTER_GET_FORM_RECT: {
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->RegisterGetFormRectProxy(callerToken);
            break;
        }
        case IpcCode::UNREGISTER_GET_FORM_RECT: {
            OHOS::p_formMgrService->UnregisterGetFormRectProxy();
            break;
        }
        case IpcCode::GET_FORM_RECT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Rect rect;
            OHOS::p_formMgrService->GetFormRect(formId, rect);
            break;
        }
        case IpcCode::NOTIFY_UPDATE_FORM_SIZE: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            int32_t newDimension = provider.ConsumeIntegral<int32_t>();
            Rect newRect;
            newRect.left = provider.ConsumeFloatingPoint<double>();
            newRect.top = provider.ConsumeFloatingPoint<double>();
            newRect.width = provider.ConsumeFloatingPoint<double>();
            newRect.height = provider.ConsumeFloatingPoint<double>();
            OHOS::p_formMgrService->UpdateFormSize(formId, newDimension, newRect);
            break;
        }
        case IpcCode::REGISTER_GET_LIVE_FORM_STATUS: {
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->RegisterGetLiveFormStatusProxy(callerToken);
            break;
        }
        case IpcCode::UNREGISTER_GET_LIVE_FORM_STATUS: {
            OHOS::p_formMgrService->UnregisterGetLiveFormStatusProxy();
            break;
        }
        case IpcCode::IS_FORM_BUNDLE_DEBUG_SIGNATURE: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            OHOS::p_formMgrService->IsFormBundleDebugSignature(bundleName);
            break;
        }
        case IpcCode::RELOAD_FORMS: {
            int32_t reloadNum = 0;
            std::string moduleName = provider.ConsumeRandomLengthString(64);
            std::string abilityName = provider.ConsumeRandomLengthString(64);
            std::string formName = provider.ConsumeRandomLengthString(64);
            OHOS::p_formMgrService->ReloadForms(reloadNum, moduleName, abilityName, formName);
            break;
        }
        case IpcCode::RELOAD_ALL_FORMS: {
            int32_t reloadNum = 0;
            OHOS::p_formMgrService->ReloadAllForms(reloadNum);
            break;
        }
        case IpcCode::IS_FORM_DUE_CONTROL: {
            FormMajorInfo formMajorInfo;
            FillFormMajorInfo(provider, formMajorInfo);
            bool isDisablePolicy = provider.ConsumeBool();
            OHOS::p_formMgrService->IsFormDueControl(formMajorInfo, isDisablePolicy);
            break;
        }
        case IpcCode::SEND_NON_TRANSPARENT_RATIO: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            int32_t ratio = provider.ConsumeIntegralInRange<int32_t>(0, 100);
            OHOS::p_formMgrService->SendNonTransparencyRatio(formId, ratio);
            break;
        }
        default: {
            break;
        }
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    FuzzIFormMgrService(fdp);
    return 0;
}