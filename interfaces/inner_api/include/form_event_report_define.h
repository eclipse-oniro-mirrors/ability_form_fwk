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
 
#ifndef OHOS_FORM_FWK_FORM_EVENT_REPORT_DEFINE_H
#define OHOS_FORM_FWK_FORM_EVENT_REPORT_DEFINE_H
 
#include <string>
#include "hisysevent.h"
 
namespace OHOS {
namespace AppExecFwk {
struct FormEventInfo {
    int64_t formId = -1;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string hostBundleName = "";
    int32_t formAppPid = -1;
    int64_t timeStamp = 0;
    int64_t formDimension = 0;
    bool distributedForm = false;
};

enum class CallDbFailedErrorType : int32_t {
    LOAD_DATABASE_FAILED = 1,
    DATABASE_RESET_CONNECT_FAILED,
    DATABASE_SAVE_FORMID_FAILED,
    DATABASE_DELETE_FORMID_FAILED,
    DATABASE_QUERY_FORMID_FAILED,
    DATABASE_EXIT_ABNORMAL,
};

enum class InitFmsFailedErrorType : int32_t {
    LOAD_FORM_DB_FAILED = 1,
    PUBLISH_SER_FAILED,
};

enum class AddFormFailedErrorType : int32_t {
    NUMBER_EXCEEDING_LIMIT = 1,
    CONNECT_FORM_RENDER_FAILED,
    CONNECT_FORM_PROVIDER_FAILED,
    SUBSCRIBE_DATA_SHARE_FAILED,
    // Sending the card addition request to FMS failed or FMS failed to process the card addition request
    ADD_FORM_FAILED,
    // Sending a RenderForm request to FRS failed or an exception occurred while FRS processed the RenderForm request
    RENDER_FORM_FAILED,
    // Failed to create SurfaceNode
    UI_CONTENT_INIT_FAILED,
    // Failed to mount SurfaceNode
    SURFACE_NODE_CREATE_FAILED,
    SURFACE_NODE_REUSE_FAILED,
};

enum class UpdateFormErrorType : int32_t {
    REQUEST_FORM_FAILED = 1,
    UPDATE_FORM_FAILED,
    PROXY_UPDATE_FORM_FAILED,
    TIMER_UPDATE_FORM_FAILED,
    FORM_VISIBLE_UPDATE_FAILED,
};

enum class DeleteFormErrorType : int32_t {
    DELETE_THEME_FORM_FAILED = 1,
    DELETE_TEMP_FORM_FAILED,
    DELETE_NORMAL_FORM_FAILED,
};

enum class RecycleRecoverFormErrorType : int32_t {
    RECYCLE_FORM_FAILED = 1,
    RECOVER_FORM_FAILED,
    RELEASE_FORM_FAILED,
    CHECK_FORM_STATUS_FAILED
};

enum class ConnectFormAbilityErrorType : int32_t {
    ACQUIRE_FORM_FAILED = 1,
    UPDATE_FORM_FAILED,
};

enum class ReloadFormErrorType : int32_t {
    RELOAD_FORM_FRS_DEAD = 1,
    RELOAD_FORM_IPC_ERROR,
    RELOAD_FORM_RELOAD_FORM_ERROR,
    RELOAD_FORM_UPDATE_FORM_ERROR,
};

struct NewFormEventInfo {
    int64_t formId = -1;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string hostBundleName = "";
    int64_t sessionId;
    int64_t bindDuration;
    int64_t getDuration;
    std::string formName;
    int64_t formDimension;
    int64_t acquireDuration;
    int64_t duration;
    int64_t durationType;
    int32_t dailyRefreshTimes;
    int32_t invisibleRefreshTimes;
    int32_t hfRefreshBlockTimes;
    int32_t invisibleRefreshBlockTimes;
    int32_t highLoadRefreshBlockTimes;
    int32_t activeRecoverRefreshTimes;
    int32_t passiveRecoverRefreshTimes;
    int32_t hfRecoverRefreshTimes;
    int32_t offloadRecoverRefreshTimes;
    int32_t disableFormRefreshTimes;
    std::string clientBundleName = "";
    std::string formBundleName = "";
    int32_t conditionType;
    int32_t renderingMode;
    std::string bundleAndFormName;
    bool distributedForm = false;
};

enum class FormEventName {
    // form behavior event
    ADD_FORM,
    REQUEST_FORM,
    DELETE_FORM,
    CASTTEMP_FORM,
    ACQUIREFORMSTATE_FORM,
    MESSAGE_EVENT_FORM,
    ROUTE_EVENT_FORM,
    BACKGROUND_EVENT_FORM,
    RELEASE_FORM,
    DELETE_INVALID_FORM,
    SET_NEXT_REFRESH_TIME_FORM,
    FORM_RENDER_BLOCK,
    INIT_FMS_FAILED,
    CALLEN_DB_FAILED,
    ADD_FORM_FAILED,
    FIRST_ADD_FORM_DURATION,
    FIRST_UPDATE_FORM_DURATION,
    UPDATE_FORM_REFRESH_TIMES,
    PROXY_UPDATE_FORM,
    INVALID_PUBLISH_FORM_TO_HOST,
    LAUNCH_FORM_APP,
    CONDITION_UPDATE_FORM,
    UNBIND_FORM_APP,
    LOAD_STAGE_FORM_CONFIG_INFO,
    DELETE_FORM_FAILED,
    UPDATE_FORM_FAILED,
    RECYCLE_RECOVER_FORM_FAILED,
    REQUEST_PUBLIC_FORM,
    CONNECT_FORM_ABILITY_FAILED,
    RELOAD_FORM_FAILED,
    FORM_NODE_ERROR,
    FORM_STATUS_ERROR,
    FORM_EVENT_QUEUE_OVER_LIMIT,
    FORM_DUE_CONTROL,
};
 
enum class RequestFormType : int8_t {
    REQUEST_PUBLISH_FORM = 1,
    REQUEST_PUBLISH_FORM_WITH_SNAPSHOT,
    OPEN_FORM_MANAGER
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_EVENT_REPORT_DEFINE_H