/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_NAPI_FORM_HOST_H
#define OHOS_FORM_FWK_NAPI_FORM_HOST_H

#include "ability.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AbilityRuntime {

struct AsyncDeleteInvalidFormsCallbackInfo {
    napi_env env;
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;
    std::vector<int64_t> formIds;
    int numFormsDeleted = 0;
    int result = OHOS::ERR_OK;
};

struct AsyncAcquireFormStateCallbackInfo {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;
    OHOS::AAFwk::Want want;
    OHOS::AppExecFwk::FormStateInfo stateInfo;
    int32_t callbackType = 0;
    int result = OHOS::ERR_OK;
};

struct AsyncNotifyFormsVisibleCallbackInfo {
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref callback;
    std::vector<int64_t> formIds;
    bool isVisible;
    int result;
};

struct AsyncNotifyFormsEnableUpdateCallbackInfo {
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref callback;
    std::vector<int64_t> formIds;
    bool isEnableUpdate;
    int result;
};

napi_value NAPI_AcquireFormState(napi_env env, napi_callback_info info);
napi_value NAPI_RegisterFormUninstallObserver(napi_env env, napi_callback_info info);
napi_value NAPI_UnregisterFormUninstallObserver(napi_env env, napi_callback_info info);
napi_value NAPI_NotifyFormsVisible(napi_env env, napi_callback_info info);
napi_value NAPI_NotifyFormsEnableUpdate(napi_env env, napi_callback_info info);

using ShareFormTask = std::function<void(int32_t)>;
class NapiFormHost {
public:
    NapiFormHost() = default;
    ~NapiFormHost() = default;

    static void Finalizer(napi_env env, void* data, void* hint);
    static napi_value ShareForm(napi_env env, napi_callback_info info);
    static napi_value DisableFormsUpdate(napi_env env, napi_callback_info info);
    static napi_value IsSystemReady(napi_env env, napi_callback_info info);
    static napi_value DeleteForm(napi_env env, napi_callback_info info);
    static napi_value ReleaseForm(napi_env env, napi_callback_info info);
    static napi_value RequestForm(napi_env env, napi_callback_info info);
    static napi_value CastTempForm(napi_env env, napi_callback_info info);
    static napi_value GetAllFormsInfo(napi_env env, napi_callback_info info);
    static napi_value GetFormsInfo(napi_env env, napi_callback_info info);
    static napi_value EnableFormsUpdate(napi_env env, napi_callback_info info);
    static napi_value NotifyFormsPrivacyProtected(napi_env env, napi_callback_info info);
    static napi_value NotifyVisibleForms(napi_env env, napi_callback_info info);
    static napi_value NotifyInVisibleForms(napi_env env, napi_callback_info info);
    static napi_value DeleteInvalidForms(napi_env env, napi_callback_info info);
private:
    napi_value OnDisableFormsUpdate(napi_env env, size_t argc, napi_value* argv);
    napi_value OnIsSystemReady(napi_env env, size_t argc, napi_value* argv);
    napi_value OnDeleteForm(napi_env env, size_t argc, napi_value* argv);
    napi_value OnReleaseForm(napi_env env, size_t argc, napi_value* argv);
    napi_value OnRequestForm(napi_env env, size_t argc, napi_value* argv);
    napi_value OnCastTempForm(napi_env env, size_t argc, napi_value* argv);
    napi_value OnGetAllFormsInfo(napi_env env, size_t argc, napi_value* argv);
    napi_value OnGetFormsInfo(napi_env env, size_t argc, napi_value* argv);
    napi_value OnEnableFormsUpdate(napi_env env, size_t argc, napi_value* argv);
    napi_value OnShareForm(napi_env env, size_t argc, napi_value* argv);
    napi_value OnNotifyFormsPrivacyProtected(napi_env env, size_t argc, napi_value* argv);
    napi_value OnNotifyVisibleForms(napi_env env, size_t argc, napi_value* argv);
    napi_value OnNotifyInVisibleForms(napi_env env, size_t argc, napi_value* argv);
    napi_value OnDeleteInvalidForms(napi_env env, size_t argc, napi_value* argv);
    void InnerShareForm(napi_env env, const std::shared_ptr<OHOS::AbilityRuntime::NapiAsyncTask> &asyncTask,
        ShareFormTask &&task, int64_t formId, const std::string &remoteDeviceId);
    bool GetStringsValue(napi_env env, napi_value object, std::vector<std::string> &strList);
    static bool UnwrapGetFormsInfoParams(napi_env env, size_t argc, napi_value* argv, std::string &moduleName,
        bool &bParam);
    int32_t OnNotifyInVisibleFormsParseParam(napi_env env, size_t argc, napi_value* argv,
        std::vector<int64_t> &formIds);
    bool OnDeleteInvalidFormsParseParam(napi_env env, size_t argc, napi_value* argv,
        int32_t &errCode, std::vector<std::string> &strFormIdList);
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif /* OHOS_FORM_FWK_NAPI_FORM_HOST_H */
