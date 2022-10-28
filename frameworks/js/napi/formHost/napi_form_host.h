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

struct AsyncNotifyVisibleFormsCallbackInfo {
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref callback;
    std::vector<int64_t> formIds;
    int result;
};

struct AsyncNotifyInvisibleFormsCallbackInfo {
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref callback;
    std::vector<int64_t> formIds;
    int result;
};

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
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref callback;
    OHOS::AAFwk::Want want;
    OHOS::AppExecFwk::FormStateInfo stateInfo;
    int32_t callbackType = 0;
    int result;
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

napi_value NAPI_NotifyVisibleForms(napi_env env, napi_callback_info info);
napi_value NAPI_NotifyInvisibleForms(napi_env env, napi_callback_info info);
napi_value NAPI_DeleteInvalidForms(napi_env env, napi_callback_info info);
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

    static void Finalizer(NativeEngine* engine, void* data, void* hint);
    static NativeValue* ShareForm(NativeEngine* engine, NativeCallbackInfo* info);
    static NativeValue* DisableFormsUpdate(NativeEngine *engine, NativeCallbackInfo *info);
    static NativeValue* IsSystemReady(NativeEngine *engine, NativeCallbackInfo *info);
    static NativeValue* DeleteForm(NativeEngine *engine, NativeCallbackInfo *info);
    static NativeValue* ReleaseForm(NativeEngine *engine, NativeCallbackInfo *info);
    static NativeValue* RequestForm(NativeEngine *engine, NativeCallbackInfo *info);
    static NativeValue* CastTempForm(NativeEngine *engine, NativeCallbackInfo *info);
    static NativeValue* GetAllFormsInfo(NativeEngine *engine, NativeCallbackInfo *info);
    static NativeValue* GetFormsInfo(NativeEngine *engine, NativeCallbackInfo *info);
    static NativeValue* EnableFormsUpdate(NativeEngine *engine, NativeCallbackInfo *info);
    static NativeValue* NotifyFormsPrivacyProtected(NativeEngine *engine, NativeCallbackInfo *info);
private:
    NativeValue* OnDisableFormsUpdate(NativeEngine &engine, NativeCallbackInfo &info);
    NativeValue* OnIsSystemReady(NativeEngine &engine, const NativeCallbackInfo &info);
    NativeValue* OnDeleteForm(NativeEngine &engine, NativeCallbackInfo &info);
    NativeValue* OnReleaseForm(NativeEngine &engine, NativeCallbackInfo &info);
    NativeValue* OnRequestForm(NativeEngine &engine, NativeCallbackInfo &info);
    NativeValue* OnCastTempForm(NativeEngine &engine, NativeCallbackInfo &info);
    NativeValue* OnGetAllFormsInfo(NativeEngine &engine, const NativeCallbackInfo &info);
    NativeValue* OnGetFormsInfo(NativeEngine &engine, NativeCallbackInfo &info);
    NativeValue* OnEnableFormsUpdate(NativeEngine &engine, NativeCallbackInfo &info);
    NativeValue* OnShareForm(NativeEngine &engine, NativeCallbackInfo &info);
    NativeValue* OnNotifyFormsPrivacyProtected(NativeEngine &engine, NativeCallbackInfo &info);
    void InnerShareForm(NativeEngine &engine, const std::shared_ptr<OHOS::AbilityRuntime::AsyncTask> &asyncTask,
        ShareFormTask &&task, int64_t formId, const std::string &remoteDeviceId);
    bool GetStringsValue(NativeEngine &engine, NativeValue *object, std::vector<std::string> &strList);
    static bool UnwrapGetFormsInfoParams(NativeEngine &engine, NativeCallbackInfo &info, std::string &moduleName,
        bool &bParam);
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif /* OHOS_FORM_FWK_NAPI_FORM_HOST_H */
