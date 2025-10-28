/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
 
#ifndef OHOS_FORM_FWK_FORM_TASK_COMMON_H
#define OHOS_FORM_FWK_FORM_TASK_COMMON_H
 
namespace OHOS {
namespace AppExecFwk {
enum class TaskType : int64_t {
    RECYCLE_FORM = 0, // add form type base 0
    RENDER_FORM,
    DELETE_FORM_HOST_RECORD = 10000, // add form_host type base 10000
    UPDATE_IS_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT
};
namespace {
constexpr int32_t FORM_TASK_DELAY_TIME = 20; // ms
constexpr int32_t FORM_FRS_DIED_TASK_DELAY_TIME = 100; // ms
constexpr int32_t FORM_BUILD_DELAY_TIME = 2000; // ms
constexpr int32_t ENTERPRISE_APP_INSTALL_FAILED_DELAY_TIME = 5000; // ms
constexpr int32_t CLEAN_FORM_HOST_TASK_DELAY_TIME = 100; // ms
constexpr int32_t FORM_CON_NETWORK_DELAY_TIME = 500; // ms
constexpr int32_t PROVIDER_UPDATE_REFRESH_FORMS_TASK_DELAY_TIME = 1000; // ms
constexpr int32_t IS_FORM_REQUEST_PUBLISH_FORM_TASK_DELAY_TIME = 2000; // ms
}
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_TASK_COMMON_H