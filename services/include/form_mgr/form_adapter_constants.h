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

#ifndef OHOS_FORM_FWK_FORM_ADAPTER_CONSTANTS_H
#define OHOS_FORM_FWK_FORM_ADAPTER_CONSTANTS_H

#include <cstdint>

namespace OHOS {
namespace AppExecFwk {
namespace FormAdapterConstants {
    // System constants
    constexpr int32_t SYSTEM_UID = 1000;
    constexpr int32_t API_11 = 11;
    constexpr int32_t DEFAULT_USER_ID = 100;

    // Bundle info parsing indices
    constexpr int32_t BUNDLE_NAME_INDEX = 0;
    constexpr int32_t USER_ID_INDEX = 1;
    constexpr int32_t INSTANCE_SEQ_INDEX = 2;
    constexpr const char *BUNDLE_INFO_SEPARATOR = "_";

    // Form info constants
    constexpr const char *POINT_ETS = ".ets";
    constexpr const char *EMPTY_BUNDLE = "";

    // Data field indices
    constexpr int DATA_FIELD = 1;
    constexpr int32_t FORM_UPDATE_LEVEL_VALUE_MAX_LENGTH = 3; // update level is 1~336, so max length is 3.

    // Form click event types
    constexpr const char *FORM_CLICK_ROUTER = "router";
    constexpr const char *FORM_CLICK_MESSAGE = "message";
    constexpr const char *FORM_CLICK_CALL = "call";

    // Ecological rule manager
    constexpr const char *FORM_SUPPORT_ECOLOGICAL_RULEMGRSERVICE =
        "persist.sys.fms.support.ecologicalrulemgrservice";

    // Add form request timeout
    constexpr int ADD_FORM_REQUEST_TIMEOUT_PERIOD = 3000;
    constexpr const char *FORM_ADD_FORM_TIMER_TASK_QUEUE = "FormMgrTimerTaskQueue";

    // Data proxy
    constexpr const char *FORM_DATA_PROXY_IGNORE_VISIBILITY =
        "ohos.extension.form_data_proxy_ignore_visibility";

    // Reconnect
    constexpr int32_t MAX_RECONNECT_NUMS = 4;

    // Add form task type
    enum class AddFormTaskType : int32_t {
        ADD_FORM_TIMER,
    };
} // namespace FormAdapterConstants
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_ADAPTER_CONSTANTS_H
