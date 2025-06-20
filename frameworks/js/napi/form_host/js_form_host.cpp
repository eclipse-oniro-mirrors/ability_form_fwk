
/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "js_form_host.h"

#include "fms_log_wrapper.h"
#include "form_info.h"
#include "form_info_filter.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "form_callback_interface.h"
#include "form_host_client.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"
#include "ipc_skeleton.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi_common_data.h"
#include "napi_form_util.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "runtime.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace {
    constexpr int REF_COUNT = 1;
    // NANOSECONDS mean 10^9 nano second
    constexpr int64_t NANOSECONDS = 1000000000;
    // MICROSECONDS mean 10^6 millias second
    constexpr int64_t MICROSECONDS = 1000000;
    constexpr int32_t INVALID_FORM_LOCATION = -2;
    constexpr int32_t INVALID_FORM_RESULT_ERRCODE = -2;
    const std::string FORM_UNINSTALL = "formUninstall";
    const std::string FORM_OVERFLOW = "formOverflow";
    const std::string CHANGE_SCENE_ANIMATION_STATE = "changeSceneAnimationState";
    const std::string GET_FORM_RECT = "getFormRect";
    const std::set<std::string> FORM_LISTENER_TYPE = {
        FORM_UNINSTALL, FORM_OVERFLOW, CHANGE_SCENE_ANIMATION_STATE, GET_FORM_RECT
    };
}

int64_t SystemTimeMillis() noexcept
{
    struct timespec t;
    t.tv_sec = 0;
    t.tv_nsec = 0;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return static_cast<int64_t>(((t.tv_sec) * NANOSECONDS + t.tv_nsec) / MICROSECONDS);
}

class ShareFormCallBackClient : public ShareFormCallBack,
                                public std::enable_shared_from_this<ShareFormCallBackClient> {
public:
    using ShareFormTask = std::function<void(int32_t)>;
    explicit ShareFormCallBackClient(ShareFormTask &&task) : task_(std::move(task))
    {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }

    virtual ~ShareFormCallBackClient() = default;

    void ProcessShareFormResponse(int32_t result) override
    {
        if (handler_) {
            handler_->PostSyncTask([client = shared_from_this(), result] () {
                client->task_(result);
            });
        }
    }

private:
    ShareFormTask task_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_;
};

class FormUninstallCallbackClient : public std::enable_shared_from_this<FormUninstallCallbackClient> {
public:
    FormUninstallCallbackClient(napi_env env, napi_ref callbackRef) : callbackRef_(callbackRef), env_(env)
    {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }

    virtual ~FormUninstallCallbackClient()
    {
        napi_delete_reference(env_, callbackRef_);
    }

    void ProcessFormUninstall(const int64_t formId)
    {
        if (handler_ == nullptr) {
            HILOG_INFO("null handler");
            return;
        }
        handler_->PostSyncTask([thisWeakPtr = weak_from_this(), formId]() {
            auto sharedThis = thisWeakPtr.lock();
            if (sharedThis == nullptr) {
                HILOG_ERROR("null sharedThis");
                return;
            }
            HILOG_DEBUG("task complete formId:%{public}" PRId64 ".", formId);
            std::string formIdString = std::to_string(formId);
            napi_value callbackValues;
            napi_create_string_utf8(sharedThis->env_, formIdString.c_str(), NAPI_AUTO_LENGTH, &callbackValues);
            napi_value callResult;
            napi_value myCallback = nullptr;
            napi_get_reference_value(sharedThis->env_, sharedThis->callbackRef_, &myCallback);
            if (myCallback != nullptr) {
                napi_call_function(sharedThis->env_, nullptr, myCallback, ARGS_ONE, &callbackValues, &callResult);
            }
        });
    }

    bool IsStrictEqual(napi_value callback)
    {
        bool isEqual = false;
        napi_value myCallback = nullptr;
        napi_get_reference_value(env_, callbackRef_, &myCallback);
        napi_strict_equals(env_, myCallback, callback, &isEqual);
        HILOG_INFO("isStrictEqual = %{public}d", isEqual);
        return isEqual;
    }

private:
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    napi_ref callbackRef_ {};
    napi_env env_;
};

class JsFormStateCallbackClient : public FormStateCallbackInterface,
                                  public std::enable_shared_from_this<JsFormStateCallbackClient> {
public:
    using AcquireFormStateTask = std::function<void(int32_t, Want)>;
    explicit JsFormStateCallbackClient(AcquireFormStateTask &&task) : task_(std::move(task))
    {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }

    virtual ~JsFormStateCallbackClient() = default;

    void ProcessAcquireState(FormState state) override
    {
        if (handler_) {
            handler_->PostSyncTask([client = shared_from_this(), state] () {
                client->task_(static_cast<int32_t>(state), client->want_);
            });
        }
    }

    void SetWant(const Want want)
    {
        want_ = want;
    }
private:
    Want want_;
    AcquireFormStateTask task_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
};

class JsFormDataCallbackClient : public FormDataCallbackInterface,
                                 public std::enable_shared_from_this<JsFormDataCallbackClient> {
public:
    using AcquireFormDataTask = std::function<void(AAFwk::WantParams data)>;
    explicit JsFormDataCallbackClient(AcquireFormDataTask &&task) : task_(std::move(task))
    {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }

    virtual ~JsFormDataCallbackClient() = default;

    void ProcessAcquireFormData(AAFwk::WantParams data) override
    {
        if (handler_) {
            handler_->PostSyncTask([client = shared_from_this(), data] () {
                client->task_(data);
            });
        }
    }
private:
    AcquireFormDataTask task_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
};

std::map<napi_ref, std::shared_ptr<FormUninstallCallbackClient>> g_formUninstallCallbackMap {};
std::mutex g_formUninstallCallbackMapMutex_;

void FormUninstallCallback(const std::vector<int64_t> &formIds)
{
    std::lock_guard<std::mutex> lock(g_formUninstallCallbackMapMutex_);
    for (auto &iter : g_formUninstallCallbackMap) {
        for (int64_t formId : formIds) {
            iter.second->ProcessFormUninstall(formId);
        }
    }
}

bool AddFormUninstallCallback(napi_env env, napi_value callback)
{
    HILOG_DEBUG("start");
    std::lock_guard<std::mutex> lock(g_formUninstallCallbackMapMutex_);
    for (auto &iter : g_formUninstallCallbackMap) {
        if (iter.second->IsStrictEqual(callback)) {
            HILOG_ERROR("found equal callback");
            return false;
        }
    }

    napi_ref callbackRef;
    napi_create_reference(env, callback, REF_COUNT, &callbackRef);
    std::shared_ptr<FormUninstallCallbackClient> callbackClient = std::make_shared<FormUninstallCallbackClient>(env,
        callbackRef);

    auto ret = g_formUninstallCallbackMap.emplace(callbackRef, callbackClient);
    if (!ret.second) {
        HILOG_ERROR("fail emplace callback");
        return false;
    }
    return true;
}

bool DelFormUninstallCallback(napi_value callback)
{
    HILOG_DEBUG("start");
    int32_t count = 0;
    std::lock_guard<std::mutex> lock(g_formUninstallCallbackMapMutex_);
    for (auto iter = g_formUninstallCallbackMap.begin(); iter != g_formUninstallCallbackMap.end();) {
        if (iter->second->IsStrictEqual(callback)) {
            HILOG_INFO("found equal callback");
            iter = g_formUninstallCallbackMap.erase(iter);
            count++;
        } else {
            iter++;
        }
    }
    HILOG_INFO("%{public}d form uninstall callback canceled.", count);
    return true;
}

bool ClearFormUninstallCallback()
{
    std::lock_guard<std::mutex> lock(g_formUninstallCallbackMapMutex_);
    g_formUninstallCallbackMap.clear();
    return true;
}

class JsFormHost {
public:
    JsFormHost() = default;
    ~JsFormHost() = default;

    static void Finalizer(napi_env env, void* data, void* hint)
    {
        HILOG_INFO("call");
        std::unique_ptr<JsFormHost>(static_cast<JsFormHost*>(data));
    }

    static napi_value AddForm(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnAddForm);
    }

    static napi_value DeleteForm(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnDeleteForm);
    }

    static napi_value ReleaseForm(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnReleaseForm);
    }

    static napi_value RequestForm(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnRequestForm);
    }

    static napi_value RequestFormWithParams(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnRequestFormWithParams);
    }

    static napi_value CastTempForm(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnCastTempForm);
    }

    static napi_value NotifyVisibleForms(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnNotifyVisibleForms);
    }

    static napi_value NotifyInvisibleForms(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnNotifyInvisibleForms);
    }

    static napi_value EnableFormsUpdate(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnEnableFormsUpdate);
    }

    static napi_value DisableFormsUpdate(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnDisableFormsUpdate);
    }

    static napi_value IsSystemReady(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnIsSystemReady);
    }

    static napi_value DeleteInvalidForms(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnDeleteInvalidForms);
    }

    static napi_value AcquireFormState(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnAcquireFormState);
    }

    static napi_value RegisterFormObserver(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnRegisterFormObserver);
    }

    static napi_value UnregisterFormObserver(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnUnregisterFormObserver);
    }

    static napi_value NotifyFormsVisible(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnNotifyFormsVisible);
    }

    static napi_value NotifyFormsEnableUpdate(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnNotifyFormsEnableUpdate);
    }

    static napi_value GetAllFormsInfo(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnGetAllFormsInfo);
    }

    static napi_value GetFormsInfo(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnGetFormsInfo);
    }

    static napi_value ShareForm(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnShareForm);
    }

    static napi_value AcquireFormData(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnAcquireFormData);
    }

    static napi_value SetRouterProxy(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnSetRouterProxy);
    }

    static napi_value ClearRouterProxy(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnClearRouterProxy);
    }

    static napi_value NotifyFormsPrivacyProtected(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnNotifyFormsPrivacyProtected);
    }

    static napi_value SetFormsRecyclable(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnSetFormsRecyclable);
    }

    static napi_value RecoverForms(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnRecoverForms);
    }

    static napi_value RecycleForms(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnRecycleForms);
    }

    static napi_value UpdateFormLocation(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnUpdateFormLocation);
    }

    static napi_value SetPublishFormResult(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnSetPublishFormResult);
    }

    static napi_value UpdateFormLockedState(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnUpdateFormLockedState);
    }

    static napi_value UpdateFormSize(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnUpdateFormSize);
    }

private:
    bool CheckCallerIsSystemApp()
    {
        auto selfToken = IPCSkeleton::GetSelfTokenID();
        return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
    }

    static bool ConvertFromId(napi_env env, napi_value jsValue, int64_t &formId)
    {
        std::string strFormId;
        if (!ConvertFromJsValue(env, jsValue, strFormId)) {
            HILOG_ERROR("convert strFormId failed");
            return false;
        }

        if (strFormId.empty()) {
            HILOG_ERROR("empty strFormId");
            return false;
        }

        if (!ConvertStringToInt64(strFormId, formId)) {
            HILOG_ERROR("convert string formId to int64 failed");
            return false;
        }
        return true;
    }

    bool GetStringsValue(napi_env env, napi_value array, std::vector<std::string> &strList)
    {
        napi_valuetype paramType = napi_undefined;
        napi_typeof(env, array, &paramType);
        if (paramType == napi_undefined || paramType == napi_null) {
            HILOG_ERROR("input array is napi_undefined or napi_null");
            return false;
        }
        uint32_t nativeArrayLen = 0;
        napi_get_array_length(env, array, &nativeArrayLen);
        napi_value element = nullptr;

        for (uint32_t i = 0; i < nativeArrayLen; i++) {
            std::string itemStr("");
            napi_get_element(env, array, i, &element);
            if (!ConvertFromJsValue(env, element, itemStr)) {
                HILOG_ERROR("GetElement from to array [%{public}u] error", i);
                return false;
            }
            strList.push_back(itemStr);
        }

        return true;
    }

    bool ConvertFromIds(napi_env env, napi_value jsValue, std::vector<int64_t> &formIds)
    {
        std::vector<string> strFormIdList;
        if (!GetStringsValue(env, jsValue, strFormIdList)) {
            HILOG_ERROR("convert strFormIdList failed");
            return false;
        }

        for (size_t i = 0; i < strFormIdList.size(); i++) {
            int64_t formIdValue;
            if (!ConvertStringToInt64(strFormIdList[i], formIdValue)) {
                HILOG_ERROR("convert formIdValue failed");
                return false;
            }
            formIds.push_back(formIdValue);
        }
        return true;
    }

    bool ConvertDeviceId(napi_env env, napi_value jsValue, std::string &deviceId)
    {
        if (!ConvertFromJsValue(env, jsValue, deviceId)) {
            HILOG_ERROR("convert deviceId failed");
            return false;
        }

        if (deviceId.empty()) {
            HILOG_ERROR("empty deviceId");
            return false;
        }

        return true;
    }

    bool ParseParameter(napi_env env, napi_value *argv, int32_t &formErrorCode, std::string &messageInfo)
    {
        napi_valuetype param1Type = napi_undefined;
        napi_typeof(env, argv[1], &param1Type);
        if (param1Type != napi_object) {
            HILOG_ERROR("result not napi_object");
            return false;
        }
        napi_value publishFormErrorCode = nullptr;
        napi_status codeRet = napi_get_named_property(env, argv[1], "code", &publishFormErrorCode);
        napi_value message = nullptr;
        napi_status messageRet = napi_get_named_property(env, argv[1], "message", &message);
        if (codeRet != napi_ok || messageRet != napi_ok) {
            HILOG_ERROR("get property failed");
            return false;
        }
        messageInfo = GetStringFromNapi(env, message);
        if (napi_get_value_int32(env, publishFormErrorCode, &formErrorCode) != napi_ok) {
            HILOG_ERROR("PublishFormErrorCode not number");
            return false;
        }
        if (formErrorCode < static_cast<int32_t>(Constants::PublishFormErrorCode::SUCCESS) ||
                formErrorCode > static_cast<int32_t>(Constants::PublishFormErrorCode::INTERNAL_ERROR)) {
            HILOG_ERROR("PublishFormResult is convert fail");
            return false;
        }
        return true;
    }

    napi_value OnAddForm(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_INFO("call");

        if (argc != ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1");
            return CreateJsUndefined(env);
        }

        Want want;
        if (!UnwrapWant(env, argv[PARAM0], want)) {
            HILOG_ERROR("UnwrapWant failed");
            NapiFormUtil::ThrowParamTypeError(env, "want", "Want");
            return CreateJsUndefined(env);
        }

        std::shared_ptr<AppExecFwk::RunningFormInfo> runningFormInfo =
            std::make_shared<AppExecFwk::RunningFormInfo>();
        auto apiResult = std::make_shared<int32_t>();
        NapiAsyncTask::ExecuteCallback execute = [want, runningFormInfo, ret = apiResult]() {
            *ret = FormMgr::GetInstance().CreateForm(want, *runningFormInfo);
        };

        NapiAsyncTask::CompleteCallback complete = [runningFormInfo, ret = apiResult](napi_env env,
            NapiAsyncTask &task, int32_t status) {
            HILOG_INFO("ret:%{public}d,formId:%{public}" PRId64, *ret, runningFormInfo->formId);
            if (*ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateRunningFormInfo(env, *runningFormInfo));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, *ret));
            }
        };

        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnAddForm",
            env, CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnDeleteForm(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");
        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("OnDeleteForm invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("OnDeleteForm invalid formId");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        auto apiResult = std::make_shared<int32_t>();
        NapiAsyncTask::ExecuteCallback execute = [formId, ret = apiResult]() {
            *ret = FormMgr::GetInstance().DeleteForm(formId, FormHostClient::GetInstance());
        };

        NapiAsyncTask::CompleteCallback complete = [formId, ret = apiResult](napi_env env,
            NapiAsyncTask &task, int32_t status) {
            HILOG_WARN("deleteForm ret:%{public}d,formId:%{public}" PRId64, *ret, formId);
            if (*ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, *ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnDeleteForm",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnReleaseForm(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (argc > ARGS_THREE || argc < ARGS_ONE) {
            HILOG_ERROR("OnReleaseForm invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2 or 3");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("invalid formId");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        bool isReleaseCache = false;
        if ((argc == ARGS_TWO || argc == ARGS_THREE) && !IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            if (!ConvertFromJsValue(env, argv[PARAM1], isReleaseCache)) {
                HILOG_ERROR("convert isReleaseCache failed");
                NapiFormUtil::ThrowParamTypeError(env, "isReleaseCache", "boolean");
                return CreateJsUndefined(env);
            }
            convertArgc++;
        }

        NapiAsyncTask::CompleteCallback complete = [formId, isReleaseCache]
            (napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().ReleaseForm(formId, FormHostClient::GetInstance(), isReleaseCache);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnReleaseForm",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnRequestForm(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("invalid formId");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        NapiAsyncTask::CompleteCallback complete = [formId](napi_env env, NapiAsyncTask &task, int32_t status) {
            Want want;
            auto ret = FormMgr::GetInstance().RequestForm(formId, FormHostClient::GetInstance(), want);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnRequestForm",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnRequestFormWithParams(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("invalid formId");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        if (argc == ARGS_TWO && !IsTypeForNapiValue(env, argv[PARAM1], napi_object)) {
            HILOG_ERROR("invalid secondInputParam");
            NapiFormUtil::ThrowParamTypeError(env, "wantParams", "object");
            return CreateJsUndefined(env);
        }

        Want want;
        AAFwk::WantParams wantParams;
        if (UnwrapWantParams(env, argv[PARAM1], wantParams)) {
            want.SetParams(wantParams);
        }
        convertArgc++;

        NapiAsyncTask::CompleteCallback complete = [formId, want](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().RequestForm(formId, FormHostClient::GetInstance(), want);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnRequestFormWithParams",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnCastTempForm(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("invalid formId");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        NapiAsyncTask::CompleteCallback complete = [formId](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().CastTempForm(formId, FormHostClient::GetInstance());
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnCastTempForm",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnNotifyVisibleForms(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        auto complete = [formIds](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, FormHostClient::GetInstance(),
                Constants::FORM_VISIBLE);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnEnableFormsUpdate",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
        HILOG_DEBUG("OnNotifyVisibleForms end");
    }

    napi_value OnNotifyInvisibleForms(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        auto complete = [formIds](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, FormHostClient::GetInstance(),
                Constants::FORM_INVISIBLE);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnEnableFormsUpdate",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
        HILOG_DEBUG("OnNotifyInvisibleForms end");
    }

    napi_value OnEnableFormsUpdate(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        auto complete = [formIds](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().LifecycleUpdate(formIds, FormHostClient::GetInstance(), true);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnEnableFormsUpdate",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
        HILOG_DEBUG("OnEnableFormsUpdate end");
    }

    napi_value OnDisableFormsUpdate(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> iFormIds;
        if (!ConvertFromIds(env, argv[PARAM0], iFormIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        auto complete = [formIds = iFormIds](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().LifecycleUpdate(formIds, FormHostClient::GetInstance(), false);
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            task.ResolveWithNoError(env, CreateJsUndefined(env));
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnDisableFormsUpdate",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnIsSystemReady(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("the app not system-app,can't use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }

        if (argc > ARGS_ONE || argc < ARGS_ZERO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "0 or 1");
            return CreateJsUndefined(env);
        }

        auto complete = [](napi_env env, NapiAsyncTask &task, int32_t status) {
            // Use original logic.
            // Use the error code to return whether the function executed successfully.
            auto ret = FormMgr::GetInstance().CheckFMSReady() ? 0 : 1;
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        auto callback = (argc == ARGS_ZERO) ? nullptr : argv[PARAM0];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnIsSystemReady",
            env, CreateAsyncTaskWithLastParam(env, callback, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnDeleteInvalidForms(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        auto complete = [formIds](napi_env env, NapiAsyncTask &task, int32_t status) {
            int32_t num;
            auto ret = FormMgr::GetInstance().DeleteInvalidForms(formIds, FormHostClient::GetInstance(), num);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsValue(env, num));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnEnableFormsUpdate",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    void InnerAcquireFormState(
        napi_env env,
        const std::shared_ptr<NapiAsyncTask> &asyncTask,
        JsFormStateCallbackClient::AcquireFormStateTask &&task,
        const Want &want)
    {
        auto formStateCallback = std::make_shared<JsFormStateCallbackClient>(std::move(task));
        FormHostClient::GetInstance()->AddFormState(formStateCallback, want);
        FormStateInfo stateInfo;
        auto result = FormMgr::GetInstance().AcquireFormState(want, FormHostClient::GetInstance(), stateInfo);
        formStateCallback->SetWant(stateInfo.want);
        if (result != ERR_OK) {
            HILOG_DEBUG("AcquireFormState failed");
            asyncTask->Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, result));
            FormHostClient::GetInstance()->RemoveFormState(want);
        }
    }

    napi_value OnAcquireFormState(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");
        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        Want want;
        napi_value argWant = argv[PARAM0];
        if (!UnwrapWant(env, argWant, want)) {
            HILOG_ERROR("invalid want");
            NapiFormUtil::ThrowParamTypeError(env, "want", "Want");
            return CreateJsUndefined(env);
        }

        napi_value lastParam = (argc == ARGS_ONE) ? nullptr : argv[PARAM1];
        napi_value result = nullptr;

        std::unique_ptr<AbilityRuntime::NapiAsyncTask> uasyncTask =
            AbilityRuntime::CreateAsyncTaskWithLastParam(env, lastParam, nullptr, nullptr, &result);
        std::shared_ptr<AbilityRuntime::NapiAsyncTask> asyncTask = std::move(uasyncTask);

        JsFormStateCallbackClient::AcquireFormStateTask task = [env, asyncTask](int32_t state, Want want) {
            HILOG_DEBUG("task complete state:%{public}d", state);
            napi_value objValue = nullptr;
            napi_create_object(env, &objValue);
            napi_set_named_property(env, objValue, "want", CreateJsWant(env, want));
            napi_set_named_property(env, objValue, "formState", CreateJsValue(env, state));
            asyncTask->ResolveWithNoError(env, objValue);
        };

        InnerAcquireFormState(env, asyncTask, std::move(task), want);
        return result;
    }

    napi_value OnSetRouterProxy(napi_env env, size_t argc, napi_value* argv)
    {
#ifndef WATCH_API_DISABLE
        if (argc > ARGS_THREE || argc < ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2 or 3");
            return CreateJsUndefined(env);
        }
        decltype(argc) convertArgc = 0;

        // Check the type of the PARAM0.
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        // Check the type of the PARAM1.
        if (!IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            HILOG_ERROR("invalid Param2");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<Want>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        auto apiResult = std::make_shared<int32_t>();
        JsFormRouterProxyMgr::GetInstance()->AddFormRouterProxyCallback(env, argv[PARAM1], formIds);
        auto execute = [formIds, ret = apiResult]() {
            *ret = FormMgr::GetInstance().RegisterFormRouterProxy(formIds, JsFormRouterProxyMgr::GetInstance());
        };

        NapiAsyncTask::CompleteCallback complete =
            [ret = apiResult](napi_env env, NapiAsyncTask &task, int32_t status) {
                if (*ret == ERR_OK) {
                    task.ResolveWithNoError(env, CreateJsUndefined(env));
                } else {
                    task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, *ret));
                }
            };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnSetRouterProxy",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
#else
        return nullptr;
#endif
    }

    napi_value OnClearRouterProxy(napi_env env, size_t argc, napi_value* argv)
    {
#ifndef WATCH_API_DISABLE
        // Check the number of input parameters.
        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }
        decltype(argc) convertArgc = 0;

        // Check the type of the PARAM0.
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        auto apiResult = std::make_shared<int32_t>();
        JsFormRouterProxyMgr::GetInstance()->RemoveFormRouterProxyCallback(formIds);
        auto execute = [formIds, ret = apiResult]() {
            *ret = FormMgr::GetInstance().UnregisterFormRouterProxy(formIds);
        };

        NapiAsyncTask::CompleteCallback complete =
            [ret = apiResult](napi_env env, NapiAsyncTask &task, int32_t status) {
                if (*ret == ERR_OK) {
                    task.ResolveWithNoError(env, CreateJsUndefined(env));
                } else {
                    task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, *ret));
                }
            };
        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnClearRouterProxy",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
#else
        return nullptr;
#endif
    }

    napi_value OnRegisterFormObserver(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("The app not system-app,can't use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }

        // Check the number of input parameters.
        if (argc != ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2");
            return CreateJsUndefined(env);
        }

        std::string type;
        if (!ConvertFromJsValue(env, argv[PARAM0], type) ||
            (FORM_LISTENER_TYPE.find(type) == FORM_LISTENER_TYPE.end())) {
            HILOG_ERROR("args[0] not register func %{public}s", type.c_str());
            NapiFormUtil::ThrowParamTypeError(env, "type",
                "formUninstall or formOverflow or changeSceneAnimationState or getFormRect");
            return CreateJsUndefined(env);
        }

        // Check the type of the PARAM1.
        if (!IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            HILOG_ERROR("invalid param1");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<string>");
            return CreateJsUndefined(env);
        }
        napi_value callback = argv[PARAM1];
        napi_ref callbackRef;
        napi_create_reference(env, callback, REF_COUNT, &callbackRef);
        if (type == FORM_UNINSTALL) {
            FormHostClient::GetInstance()->RegisterUninstallCallback(FormUninstallCallback);
            AddFormUninstallCallback(env, argv[PARAM1]);
        } else if (type == FORM_OVERFLOW) {
            return OnRegisterOverflowListener(env, callbackRef);
        } else if (type == CHANGE_SCENE_ANIMATION_STATE) {
            return OnRegisterChangeSceneAnimationStateListener(env, callbackRef);
        } else if (type == GET_FORM_RECT) {
            return OnRegisterGetFormRectListener(env, callbackRef);
        }
        return CreateJsUndefined(env);
    }

    napi_value OnUnregisterFormObserver(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("the application not system-app,can't use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }

        // Check the number of input parameters.
        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        // Check the type of the PARAM0 and convert it to string.
        std::string type;
        if (!ConvertFromJsValue(env, argv[PARAM0], type) ||
            (FORM_LISTENER_TYPE.find(type) == FORM_LISTENER_TYPE.end())) {
            HILOG_ERROR("Invalid type provided: %{public}s."
                "Expected formUninstall or formOverflow or changeSceneAnimationState or getFormRect.", type.c_str());
            NapiFormUtil::ThrowParamTypeError(env, "type",
                "formUninstall or formOverflow or changeSceneAnimationState or getFormRect");
            return CreateJsUndefined(env);
        }
        // Check the type of the PARAM1.
        if (argc == ARGS_TWO && !IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            HILOG_ERROR("invalid param1");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<string>");
            return CreateJsUndefined(env);
        }

        if (argc == ARGS_TWO) {
            DelFormUninstallCallback(argv[PARAM1]);
            return CreateJsUndefined(env);
        }

        if (type == FORM_UNINSTALL) {
            ClearFormUninstallCallback();
        } else if (type == FORM_OVERFLOW) {
            return OffRegisterOverflowListener(env);
        } else if (type == CHANGE_SCENE_ANIMATION_STATE) {
            return OffRegisterChangeSceneAnimationStateListener(env);
        } else if (type == GET_FORM_RECT) {
            return OffRegisterGetFormRectListener(env);
        }
        return CreateJsUndefined(env);
    }

    napi_value OnNotifyFormsVisible(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (argc > ARGS_THREE || argc < ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2 or 3");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        bool isVisible = false;
        if (!ConvertFromJsValue(env, argv[PARAM1], isVisible)) {
            HILOG_ERROR("convert isVisible failed");
            NapiFormUtil::ThrowParamTypeError(env, "isVisible", "boolean");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        auto complete = [formIds, isVisible](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().NotifyFormsVisible(formIds, isVisible,
                FormHostClient::GetInstance());
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnNotifyFormsVisible",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnNotifyFormsEnableUpdate(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (argc > ARGS_THREE || argc < ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2 or 3");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        bool isEnableUpdate = false;
        if (!ConvertFromJsValue(env, argv[PARAM1], isEnableUpdate)) {
            HILOG_ERROR("convert isEnableUpdate failed");
            NapiFormUtil::ThrowParamTypeError(env, "isEnableUpdate", "boolean");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        auto complete = [formIds, isEnableUpdate](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().NotifyFormsEnableUpdate(formIds, isEnableUpdate,
                FormHostClient::GetInstance());
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnNotifyFormsVisible",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnGetAllFormsInfo(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");
        if (argc > ARGS_ONE || argc < ARGS_ZERO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "0 or 1");
            return CreateJsUndefined(env);
        }

        auto errCodeVal = std::make_shared<int32_t>(0);
        auto formInfoList = std::make_shared<std::vector<FormInfo>>();
        NapiAsyncTask::ExecuteCallback execute = [formInfos = formInfoList, errCode = errCodeVal]() {
            if (formInfos == nullptr || errCode == nullptr) {
                HILOG_ERROR("invalid param");
                return;
            }
            *errCode = FormMgr::GetInstance().GetAllFormsInfo(*formInfos);
        };

        NapiAsyncTask::CompleteCallback complete = CreateFormInfosCompleteCallback(errCodeVal, formInfoList);

        auto callback = (argc == ARGS_ZERO) ? nullptr : argv[PARAM0];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnGetAllFormsInfo",
            env, CreateAsyncTaskWithLastParam(env, callback, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value GetFormsInfoByFilter(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_INFO("call");
        if (argc != ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        AppExecFwk::FormInfoFilter filter;
        napi_value jsValue = GetPropertyValueByPropertyName(env, argv[PARAM0], "supportedDimensions", napi_object);
        if (jsValue != nullptr) {
            std::vector<int32_t> dimensions;
            UnwrapArrayInt32FromJS(env, jsValue, dimensions);
            for (size_t i = 0; i < dimensions.size(); ++i) {
                if (dimensions[i] < 0) {
                    HILOG_ERROR("dimensions value should not be negative");
                    NapiFormUtil::ThrowParamError(env, "dimensions value should not be negative");
                    return CreateJsUndefined(env);
                }
                filter.supportDimensions.emplace_back(dimensions[i]);
            }
        }

        napi_value jsShapeValue = GetPropertyValueByPropertyName(env, argv[PARAM0], "supportedShapes", napi_object);
        if (jsShapeValue != nullptr && !GetIntVecValue(env, jsShapeValue, filter.supportShapes)) {
            HILOG_ERROR("shapes value should not be negative");
            NapiFormUtil::ThrowParamError(env, "shapes value should not be negative");
            return CreateJsUndefined(env);
        }

        UnwrapStringByPropertyName(env, argv[PARAM0], "moduleName", filter.moduleName);
        UnwrapStringByPropertyName(env, argv[PARAM0], "bundleName", filter.bundleName);

        convertArgc++;

        auto errCodeVal = std::make_shared<int32_t>(0);
        auto formInfoList = std::make_shared<std::vector<FormInfo>>();
        NapiAsyncTask::ExecuteCallback execute = [filter, formInfos = formInfoList, errCode = errCodeVal]() {
            if (formInfos == nullptr || errCode == nullptr) {
                HILOG_ERROR("invalid param");
                return;
            }
            *errCode = FormMgr::GetInstance().GetFormsInfoByFilter(filter, *formInfos);
        };

        NapiAsyncTask::CompleteCallback complete = CreateFormInfosCompleteCallback(errCodeVal, formInfoList);

        napi_value result = nullptr;
        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnGetFormsInfo",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    bool GetIntVecValue(napi_env &env, napi_value &jsValue, std::vector<int32_t> &results)
    {
        std::vector<int32_t> vals;
        UnwrapArrayInt32FromJS(env, jsValue, vals);
        for (size_t i = 0; i < vals.size(); ++i) {
            if (vals[i] < 0) {
                HILOG_ERROR("value should not be negative");
                return false;
            }
            results.emplace_back(vals[i]);
        }
        return true;
    }

    napi_value OnGetFormsInfo(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_INFO("call");
        if (argc == ARGS_ONE && IsTypeForNapiValue(env, argv[PARAM0], napi_object)) {
            return GetFormsInfoByFilter(env, argc, argv);
        }
        if (argc > ARGS_THREE || argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2 or 3");
            return CreateJsUndefined(env);
        }
        decltype(argc) convertArgc = 0;
        std::string bName("");
        if (!ConvertFromJsValue(env, argv[PARAM0], bName)) {
            HILOG_ERROR("bundleName convert failed");
            NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;
        std::string mName("");
        if ((argc == ARGS_TWO || argc == ARGS_THREE) && !IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            if (!ConvertFromJsValue(env, argv[PARAM1], mName)) {
                HILOG_ERROR("moduleName convert failed");
                NapiFormUtil::ThrowParamTypeError(env, "moduleName", "string");
                return CreateJsUndefined(env);
            }
            convertArgc++;
        }

        auto errCodeVal = std::make_shared<int32_t>(0);
        auto formInfoList = std::make_shared<std::vector<FormInfo>>();
        NapiAsyncTask::ExecuteCallback execute = [bName, mName, convertArgc, formInfos = formInfoList,
            errCode = errCodeVal]() {
            if (formInfos == nullptr || errCode == nullptr) {
                HILOG_ERROR("invalid param");
                return;
            }
            std::string bundleName(bName);
            std::string moduleName(mName);
            if (convertArgc == ARGS_ONE) {
                *errCode = FormMgr::GetInstance().GetFormsInfoByApp(bundleName, *formInfos);
            } else {
                *errCode = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, *formInfos);
            }
        };

        NapiAsyncTask::CompleteCallback complete = CreateFormInfosCompleteCallback(errCodeVal, formInfoList);
        napi_value result = nullptr;
        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnGetFormsInfo",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    NapiAsyncTask::CompleteCallback CreateFormInfosCompleteCallback(std::shared_ptr<int32_t> errCodeVal,
        std::shared_ptr<std::vector<FormInfo>> formInfoList)
    {
        return [errCode = errCodeVal, formInfos = formInfoList](
            napi_env env, NapiAsyncTask &task, int32_t status) {
            if (errCode == nullptr || formInfos == nullptr) {
                HILOG_ERROR("invalid param");
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ERR_APPEXECFWK_FORM_COMMON_CODE));
                return;
            }
            if (*errCode != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, *errCode));
                return;
            }
            task.ResolveWithNoError(env, CreateFormInfos(env, *formInfos));
        };
    }

    void InnerShareForm(napi_env env, const std::shared_ptr<AbilityRuntime::NapiAsyncTask> &asyncTask,
        ShareFormCallBackClient::ShareFormTask &&task, int64_t formId, const std::string &remoteDeviceId)
    {
        auto shareFormCallback = std::make_shared<ShareFormCallBackClient>(std::move(task));
        int64_t requestCode = SystemTimeMillis();
        FormHostClient::GetInstance()->AddShareFormCallback(shareFormCallback, requestCode);

        ErrCode ret = FormMgr::GetInstance().ShareForm(
            formId, remoteDeviceId, FormHostClient::GetInstance(), requestCode);
        if (ret != ERR_OK) {
            HILOG_INFO("share form fail");
            asyncTask->Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            FormHostClient::GetInstance()->RemoveShareFormCallback(requestCode);
        }
    }

    void InnerAcquireFormData(napi_env env, const std::shared_ptr<AbilityRuntime::NapiAsyncTask> &asyncTask,
       JsFormDataCallbackClient::AcquireFormDataTask &&task, int64_t formId)
    {
        auto formDataCallbackClient = std::make_shared<JsFormDataCallbackClient>(std::move(task));
        int64_t requestCode = SystemTimeMillis();
        FormHostClient::GetInstance()->AddAcqiureFormDataCallback(formDataCallbackClient, requestCode);

        AAFwk::WantParams formData;
        auto ret = FormMgr::GetInstance().AcquireFormData(formId, requestCode, FormHostClient::GetInstance(), formData);
        if (ret != ERR_OK) {
            HILOG_ERROR("acquire form failed");
            asyncTask->Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            FormHostClient::GetInstance()->RemoveAcquireDataCallback(requestCode);
        }
    }

    napi_value OnShareForm(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");
        if (argc > ARGS_THREE || argc < ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2 or 3");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("invalid formId");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        std::string devicedId;
        if (!ConvertDeviceId(env, argv[PARAM1], devicedId)) {
            HILOG_ERROR("invalid deviceId");
            NapiFormUtil::ThrowParamTypeError(env, "devicedId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;

        std::unique_ptr<AbilityRuntime::NapiAsyncTask> uasyncTask =
            AbilityRuntime::CreateAsyncTaskWithLastParam(env, lastParam, nullptr, nullptr, &result);
        std::shared_ptr<AbilityRuntime::NapiAsyncTask> asyncTask = std::move(uasyncTask);

        ShareFormCallBackClient::ShareFormTask task = [env, asyncTask](int32_t code) {
            HILOG_DEBUG("task complete code:%{public}d", code);
            if (code == ERR_OK) {
                asyncTask->ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                asyncTask->Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, code));
            }
        };

        InnerShareForm(env, asyncTask, std::move(task), formId, devicedId);

        return result;
    }

    napi_value OnAcquireFormData(napi_env env, size_t argc, napi_value* argv)
    {
#ifndef WATCH_API_DISABLE
        HILOG_DEBUG("call");
        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        // The promise form has only one parameters
        decltype(argc) unwrapArgc = 1;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("invalid formId");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }

        napi_value lastParam = (argc <= unwrapArgc) ? nullptr : argv[unwrapArgc];
        napi_value result = nullptr;

        std::unique_ptr<AbilityRuntime::NapiAsyncTask> uasyncTask =
            AbilityRuntime::CreateAsyncTaskWithLastParam(env, lastParam, nullptr, nullptr, &result);
        std::shared_ptr<AbilityRuntime::NapiAsyncTask> asyncTask = std::move(uasyncTask);

        JsFormDataCallbackClient::AcquireFormDataTask task = [env, asyncTask](AAFwk::WantParams data) {
            HILOG_DEBUG("task complete form data");
            napi_value objValue = nullptr;
            napi_create_object(env, &objValue);
            napi_set_named_property(env, objValue, "formData", CreateJsWantParams(env, data));
            asyncTask->ResolveWithNoError(env, objValue);
        };

        InnerAcquireFormData(env, asyncTask, std::move(task), formId);
        return result;
#else
        return nullptr;
#endif
    }

    napi_value OnNotifyFormsPrivacyProtected(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_INFO("call");
        if (argc > ARGS_THREE || argc < ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2 or 3");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        bool isProtected = false;
        if (!ConvertFromJsValue(env, argv[PARAM1], isProtected)) {
            HILOG_ERROR("convert isProtected failed");
            NapiFormUtil::ThrowParamTypeError(env, "isProtected", "boolean");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        NapiAsyncTask::CompleteCallback complete =
            [formIds, isProtected](napi_env env, NapiAsyncTask &task, int32_t status) {
                auto ret = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds,
                    isProtected, FormHostClient::GetInstance());
                if (ret == ERR_OK) {
                    task.ResolveWithNoError(env, CreateJsUndefined(env));
                } else {
                    task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                }
            };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnNotifyFormsPrivacyProtected",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnSetFormsRecyclable(napi_env env, size_t argc, napi_value *argv)
    {
#ifndef WATCH_API_DISABLE
        HILOG_DEBUG("call");
        if (argc < ARGS_ONE || argc > ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        NapiAsyncTask::CompleteCallback complete = [formIds](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().SetFormsRecyclable(formIds);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnSetFormsRecyclable",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
#else
        return nullptr;
#endif
    }

    napi_value OnRecoverForms(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("call");
        if (argc < ARGS_ONE || argc > ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        auto apiResult = std::make_shared<int32_t>();
        NapiAsyncTask::ExecuteCallback execute = [formIds, ret = apiResult]() {
            Want want;
            *ret = FormMgr::GetInstance().RecoverForms(formIds, want);
        };
        
        NapiAsyncTask::CompleteCallback complete =
            [ret = apiResult](napi_env env, NapiAsyncTask &task, int32_t status) {
            if (*ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, *ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnRecoverForms",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnRecycleForms(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("call");
        if (argc < ARGS_ONE || argc > ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("invalid formIdList");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        NapiAsyncTask::CompleteCallback complete = [formIds](napi_env env, NapiAsyncTask &task, int32_t status) {
            Want want;
            auto ret = FormMgr::GetInstance().RecycleForms(formIds, want);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnRecycleForms",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnUpdateFormLockedState(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");

        if (argc != ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("invalid formId");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        bool isLocked = false;
        if (!ConvertFromJsValue(env, argv[PARAM1], isLocked)) {
            HILOG_ERROR("convert isLocked failed");
            NapiFormUtil::ThrowParamTypeError(env, "isLocked", "boolean");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        auto complete = [formId, isLocked](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().NotifyFormLocked(formId, isLocked);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnUpdateFormLockedState",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnUpdateFormLocation(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("call");
        if (argc != ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "argc != 2");
            return CreateJsUndefined(env);
        }

        int64_t formId = -1;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("Convert strFormIdList failed");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        HILOG_INFO("formId:%{public}s", std::to_string(formId).c_str());
        int32_t formLocation = INVALID_FORM_LOCATION;
        if (napi_get_value_int32(env, argv[PARAM1], &formLocation) == napi_ok) {
            if (formLocation < static_cast<int32_t>(Constants::FormLocation::OTHER) ||
                 formLocation > static_cast<int32_t>(Constants::FormLocation::AI_SUGGESTION)) {
                HILOG_ERROR("formLocation not FormLocation enum");
                NapiFormUtil::ThrowParamTypeError(env, "formLocation", "FormLocation enum");
                return CreateJsUndefined(env);
            }
        } else {
            HILOG_ERROR("formLocation not number");
            NapiFormUtil::ThrowParamTypeError(env, "formLocation", "number");
            return CreateJsUndefined(env);
        }
        HILOG_INFO("formLocation:%{public}s", std::to_string(formLocation).c_str());
        auto ret = FormMgr::GetInstance().UpdateFormLocation(formId, formLocation);
        if (ret == ERR_OK) {
            return CreateJsUndefined(env);
        }
        NapiFormUtil::ThrowByInternalErrorCode(env, ret);
        return CreateJsUndefined(env);
    }

    napi_value OnSetPublishFormResult(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("call");
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("the application not system-app,can't use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }
        if (argc != ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2");
            return CreateJsUndefined(env);
        }
        decltype(argc) convertArgc = 0;
        int64_t formId;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("Convert strFormId failed");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;
        std::string messageInfo = "";
        int32_t formErrorCode = INVALID_FORM_RESULT_ERRCODE;
        if (!ParseParameter(env, argv, formErrorCode, messageInfo)) {
            HILOG_ERROR("Parsing Argument Errors");
            NapiFormUtil::ThrowParamError(env, "Failed to get property.");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        AppExecFwk::Constants::PublishFormResult publishFormResult;
        publishFormResult.code = static_cast<AppExecFwk::Constants::PublishFormErrorCode>(formErrorCode);
        publishFormResult.message = messageInfo;
        ErrCode ret = FormMgr::GetInstance().SetPublishFormResult(formId, publishFormResult);
        if (ret == ERR_OK) {
            return CreateJsUndefined(env);
        }
        NapiFormUtil::ThrowByInternalErrorCode(env, ret);
        return CreateJsUndefined(env);
    }

    napi_value OnRegisterOverflowListener(napi_env env, napi_ref callbackRef)
    {
        HILOG_INFO("call");
        bool result = FormMgr::GetInstance().RegisterOverflowProxy(JsFormRouterProxyMgr::GetInstance());
        if (!result) {
            return CreateJsValue(env, result);
        }
        result = JsFormRouterProxyMgr::GetInstance()->RegisterOverflowListener(env, callbackRef);
        return CreateJsValue(env, result);
    }
    
    napi_value OffRegisterOverflowListener(napi_env env)
    {
        HILOG_INFO("call");
        bool result = FormMgr::GetInstance().UnregisterOverflowProxy();
        if (!result) {
            return CreateJsValue(env, result);
        }
        result = JsFormRouterProxyMgr::GetInstance()->UnregisterOverflowListener();
        return CreateJsValue(env, result);
    }

    napi_value OnRegisterChangeSceneAnimationStateListener(napi_env env, napi_ref callbackRef)
    {
        HILOG_INFO("call");
        bool result = FormMgr::GetInstance().RegisterChangeSceneAnimationStateProxy(
            JsFormRouterProxyMgr::GetInstance());
        if (!result) {
            return CreateJsValue(env, result);
        }
        result = JsFormRouterProxyMgr::GetInstance()->RegisterChangeSceneAnimationStateListener(
            env, callbackRef);
        return CreateJsValue(env, result);
    }

    napi_value OffRegisterChangeSceneAnimationStateListener(napi_env env)
    {
        HILOG_INFO("call");
        bool result = FormMgr::GetInstance().UnregisterChangeSceneAnimationStateProxy();
        if (!result) {
            return CreateJsValue(env, result);
        }
        result = JsFormRouterProxyMgr::GetInstance()->UnregisterChangeSceneAnimationStateListener();
        return CreateJsValue(env, result);
    }

    napi_value OnRegisterGetFormRectListener(napi_env env, napi_ref callbackRef)
    {
        HILOG_INFO("call");
        bool result = FormMgr::GetInstance().RegisterGetFormRectProxy(
            JsFormRouterProxyMgr::GetInstance());
        if (!result) {
            return CreateJsValue(env, result);
        }
        result = JsFormRouterProxyMgr::GetInstance()->RegisterGetFormRectListener(
            env, callbackRef);
        return CreateJsValue(env, result);
    }

    napi_value OffRegisterGetFormRectListener(napi_env env)
    {
        HILOG_INFO("call");
        bool result = FormMgr::GetInstance().UnregisterGetFormRectProxy();
        if (!result) {
            return CreateJsValue(env, result);
        }
        result = JsFormRouterProxyMgr::GetInstance()->UnregisterGetFormRectListener();
        return CreateJsValue(env, result);
    }

    napi_value OnUpdateFormSize(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("call");
        if (argc != ARGS_THREE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "3");
            return CreateJsUndefined(env);
        }
        int64_t formId;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("Convert formId failed");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        decltype(argc) convertArgc = 0;
        convertArgc++;
        std::string newDimesnion("");
        if (!ConvertFromJsValue(env, argv[PARAM1], newDimesnion)) {
            HILOG_ERROR("convert newDimesnion failed");
            NapiFormUtil::ThrowParamTypeError(env, "newDimesnion", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;
        AppExecFwk::Rect* newRect = new (std::nothrow) AppExecFwk::Rect {};
        if (newRect == nullptr) {
            HILOG_ERROR("Failed to new newRect");
            return CreateJsUndefined(env);
        }
        if (!ConvertFormRect(env, argv[PARAM2], newRect)) {
            HILOG_ERROR("convert newRect failed");
            delete newRect;
            NapiFormUtil::ThrowParamError(env, "The newRect is invalid");
            return CreateJsUndefined(env);
        }
        convertArgc++;
        auto ret = FormMgr::GetInstance().UpdateFormSize(formId, newDimesnion, *newRect);
        delete newRect;
        if (ret == ERR_OK) {
            return CreateJsUndefined(env);
        }
        NapiFormUtil::ThrowByInternalErrorCode(env, ret);
        return CreateJsUndefined(env);
    }

    bool ConvertFormRect(napi_env env, napi_value rect, AppExecFwk::Rect* newRect)
    {
        if (newRect == nullptr) {
            HILOG_ERROR("input newRect is null");
            return false;
        }
        napi_valuetype type = napi_undefined;
        napi_typeof(env, rect, &type);
        if (type == napi_undefined || type == napi_null) {
            HILOG_ERROR("input rect is undefined or null");
            return false;
        }
        if (!GetAndConvertProperty(env, rect, "left", newRect->left) ||
            !GetAndConvertProperty(env, rect, "top", newRect->top) ||
            !GetAndConvertProperty(env, rect, "width", newRect->width) ||
            !GetAndConvertProperty(env, rect, "height", newRect->height)) {
            return false;
        }
        return true;
    }

    bool GetAndConvertProperty(napi_env env, napi_value object, const char* propertyName, double& outValue)
    {
        napi_value propertyValue;
        napi_status status = napi_get_named_property(env, object, propertyName, &propertyValue);
        if (status != napi_ok) {
            HILOG_ERROR("Failed to get property: %{public}s", propertyName);
            return false;
        }
        if (!ConvertFromJsValue(env, propertyValue, outValue)) {
            HILOG_ERROR("ConvertFromJsValue %{public}s failed", propertyName);
            return false;
        }
        return true;
    }
};

napi_value JsFormHostInit(napi_env env, napi_value exportObj)
{
    HILOG_DEBUG("call");

    std::unique_ptr<JsFormHost> jsFormHost = std::make_unique<JsFormHost>();
    napi_wrap(env, exportObj, jsFormHost.release(), JsFormHost::Finalizer, nullptr, nullptr);

    const char *moduleName = "JsFormHost";
    BindNativeFunction(env, exportObj, "deleteForm", moduleName, JsFormHost::DeleteForm);
    BindNativeFunction(env, exportObj, "releaseForm", moduleName, JsFormHost::ReleaseForm);
    BindNativeFunction(env, exportObj, "requestForm", moduleName, JsFormHost::RequestForm);
    BindNativeFunction(env, exportObj, "requestFormWithParams", moduleName, JsFormHost::RequestFormWithParams);
    BindNativeFunction(env, exportObj, "castTempForm", moduleName, JsFormHost::CastTempForm);
    BindNativeFunction(env, exportObj, "castToNormalForm", moduleName, JsFormHost::CastTempForm);
    BindNativeFunction(env, exportObj, "notifyVisibleForms", moduleName, JsFormHost::NotifyVisibleForms);
    BindNativeFunction(env, exportObj, "notifyInvisibleForms", moduleName, JsFormHost::NotifyInvisibleForms);
    BindNativeFunction(env, exportObj, "enableFormsUpdate", moduleName, JsFormHost::EnableFormsUpdate);
    BindNativeFunction(env, exportObj, "disableFormsUpdate", moduleName, JsFormHost::DisableFormsUpdate);
    BindNativeFunction(env, exportObj, "isSystemReady", moduleName, JsFormHost::IsSystemReady);
    BindNativeFunction(env, exportObj, "deleteInvalidForms", moduleName, JsFormHost::DeleteInvalidForms);
    BindNativeFunction(env, exportObj, "acquireFormState", moduleName, JsFormHost::AcquireFormState);
    BindNativeFunction(env, exportObj, "on", moduleName, JsFormHost::RegisterFormObserver);
    BindNativeFunction(env, exportObj, "off", moduleName, JsFormHost::UnregisterFormObserver);
    BindNativeFunction(env, exportObj, "notifyFormsVisible", moduleName, JsFormHost::NotifyFormsVisible);
    BindNativeFunction(env, exportObj, "notifyFormsEnableUpdate", moduleName, JsFormHost::NotifyFormsEnableUpdate);
    BindNativeFunction(env, exportObj, "getAllFormsInfo", moduleName, JsFormHost::GetAllFormsInfo);
    BindNativeFunction(env, exportObj, "getFormsInfo", moduleName, JsFormHost::GetFormsInfo);
    BindNativeFunction(env, exportObj, "shareForm", moduleName, JsFormHost::ShareForm);
    BindNativeFunction(env, exportObj, "notifyFormsPrivacyProtected", moduleName,
        JsFormHost::NotifyFormsPrivacyProtected);
    BindNativeFunction(env, exportObj, "acquireFormData", moduleName, JsFormHost::AcquireFormData);
    BindNativeFunction(env, exportObj, "setRouterProxy", moduleName, JsFormHost::SetRouterProxy);
    BindNativeFunction(env, exportObj, "clearRouterProxy", moduleName, JsFormHost::ClearRouterProxy);
    BindNativeFunction(env, exportObj, "setFormsRecyclable", moduleName, JsFormHost::SetFormsRecyclable);
    BindNativeFunction(env, exportObj, "recoverForms", moduleName, JsFormHost::RecoverForms);
    BindNativeFunction(env, exportObj, "recycleForms", moduleName, JsFormHost::RecycleForms);
    BindNativeFunction(env, exportObj, "updateFormLocation", moduleName, JsFormHost::UpdateFormLocation);
    BindNativeFunction(env, exportObj, "setPublishFormResult", moduleName, JsFormHost::SetPublishFormResult);
    BindNativeFunction(env, exportObj, "addForm", moduleName, JsFormHost::AddForm);
    BindNativeFunction(env, exportObj, "updateFormLockedState", moduleName, JsFormHost::UpdateFormLockedState);
    BindNativeFunction(env, exportObj, "updateFormSize", moduleName, JsFormHost::UpdateFormSize);

    return CreateJsUndefined(env);
}

FormRouterProxyCallbackClient::FormRouterProxyCallbackClient(napi_env env, napi_ref callbackRef)
{
    env_ = env;
    callbackRef_ = callbackRef;
    handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
}

FormRouterProxyCallbackClient::~FormRouterProxyCallbackClient()
{
    napi_delete_reference(env_, callbackRef_);
}

void FormRouterProxyCallbackClient::ProcessFormRouterProxy(const Want &want)
{
    HILOG_INFO("call");
    if (handler_ == nullptr) {
        HILOG_ERROR("null Handler");
        return;
    }
    handler_->PostSyncTask([thisWeakPtr = weak_from_this(), want]() {
        auto sharedThis = thisWeakPtr.lock();
        if (sharedThis == nullptr) {
            HILOG_ERROR("null SharedThis");
            return;
        }

        napi_value callbackValues = CreateJsWant(sharedThis->env_, want);
        napi_value callResult;
        napi_value myCallback = nullptr;
        napi_get_reference_value(sharedThis->env_, sharedThis->callbackRef_, &myCallback);
        if (myCallback != nullptr) {
            napi_call_function(sharedThis->env_, nullptr, myCallback, ARGS_ONE, &callbackValues, &callResult);
        }
    });
}

sptr<JsFormRouterProxyMgr> JsFormRouterProxyMgr::instance_ = nullptr;
std::mutex JsFormRouterProxyMgr::mutex_;
sptr<JsFormRouterProxyMgr> JsFormRouterProxyMgr::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) JsFormRouterProxyMgr();
            if (instance_ == nullptr) {
                HILOG_ERROR("create JsFormRouterProxyMgr failed");
            }
        }
    }
    return instance_;
}

ErrCode JsFormRouterProxyMgr::RouterEvent(int64_t formId, const Want &want)
{
    HILOG_DEBUG("call");

    std::lock_guard<std::mutex> lock(FormRouterProxyCallbackMutex_);
    auto callbackClient = formRouterProxyCallbackMap_.find(formId);
    if (callbackClient != formRouterProxyCallbackMap_.end()) {
        if (callbackClient->second != nullptr) {
            callbackClient->second->ProcessFormRouterProxy(want);
        }
    }
    return ERR_OK;
}

void JsFormRouterProxyMgr::AddFormRouterProxyCallback(napi_env env, napi_value callback,
    const std::vector<int64_t> &formIds)
{
#ifndef WATCH_API_DISABLE
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(FormRouterProxyCallbackMutex_);

    napi_ref callbackRef;
    napi_create_reference(env, callback, REF_COUNT, &callbackRef);
    std::shared_ptr<FormRouterProxyCallbackClient> callbackClient = std::make_shared<FormRouterProxyCallbackClient>(env,
        callbackRef);

    for (const auto &formId : formIds) {
        auto iter = formRouterProxyCallbackMap_.find(formId);
        if (iter != formRouterProxyCallbackMap_.end()) {
            iter->second = callbackClient;
            continue;
        }
        formRouterProxyCallbackMap_.emplace(formId, callbackClient);
    }
#endif
}

void JsFormRouterProxyMgr::RemoveFormRouterProxyCallback(const std::vector<int64_t> &formIds)
{
    HILOG_INFO("call");
    std::lock_guard<std::mutex> lock(FormRouterProxyCallbackMutex_);
    for (const auto &formId : formIds) {
        auto iter = formRouterProxyCallbackMap_.find(formId);
        if (iter != formRouterProxyCallbackMap_.end()) {
            formRouterProxyCallbackMap_.erase(formId);
        }
    }
}

bool JsFormRouterProxyMgr::RegisterOverflowListener(napi_env env, napi_ref callbackRef)
{
    HILOG_INFO("call");

    if (callbackRef == nullptr) {
        HILOG_ERROR("Invalid callback reference");
        return false;
    }

    if (overflowRegisterCallback_ != nullptr) {
        napi_delete_reference(env, overflowRegisterCallback_);
        overflowRegisterCallback_ = nullptr;
    }

    overflowRegisterCallback_ = callbackRef;
    overflowEnv_ = env;

    napi_value callback;
    napi_get_reference_value(env, callbackRef, &callback);
    napi_valuetype valueType;
    napi_typeof(env, callback, &valueType);
    if (valueType != napi_function) {
        HILOG_ERROR("Callback is not a function");
        return false;
    }

    HILOG_INFO("Listener registered successfully");
    return true;
}

bool JsFormRouterProxyMgr::UnregisterOverflowListener()
{
    HILOG_INFO("call");
    overflowRegisterCallback_ = nullptr;
    overflowEnv_ = nullptr;
    return true;
}

ErrCode JsFormRouterProxyMgr::RequestOverflow(const int64_t formId, const AppExecFwk::OverflowInfo &overflowInfo,
    bool isOverflow)
{
    HILOG_INFO("call");
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(overflowEnv_, &loop);
    if (loop == nullptr) {
        HILOG_ERROR("Failed to get loop, formId:%{public}" PRId64 ".", formId);
        return ERR_GET_INFO_FAILED;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        HILOG_ERROR("Failed to new uv_work_t, formId:%{public}" PRId64 ".", formId);
        return ERR_GET_INFO_FAILED;
    }

    LiveFormInterfaceParam* dataParam = new (std::nothrow) LiveFormInterfaceParam {
        .formId = std::to_string(formId),
        .overflowInfo = overflowInfo,
        .isOverflow = isOverflow
    };
    if (dataParam == nullptr) {
        HILOG_ERROR("Failed to new dataParam, formId:%{public}" PRId64 ".", formId);
        delete work;
        return ERR_GET_INFO_FAILED;
    }
    work->data = dataParam;
    uv_queue_work(
        loop, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int status) {
            LiveFormInterfaceParam* dataParam = (LiveFormInterfaceParam*)work->data;
            JsFormRouterProxyMgr::GetInstance()->RequestOverflowInner(dataParam);
            std::unique_lock<std::mutex> lock(dataParam->mutex);
            dataParam->isReady = true;
            dataParam->condition.notify_all();
            delete work;
        });
    std::unique_lock<std::mutex> lock(dataParam->mutex);
    dataParam->condition.wait(lock, [&] { return dataParam->isReady; });
    bool result = dataParam->result;
    delete dataParam;
    return result ? ERR_OK : ERR_GET_INFO_FAILED;
}

void JsFormRouterProxyMgr::RequestOverflowInner(LiveFormInterfaceParam* dataParam)
{
    HILOG_INFO("call");
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(overflowEnv_, &scope);
    if (scope == nullptr) {
        HILOG_ERROR("null scope");
        return;
    }
    napi_value requestObj;
    napi_create_object(overflowEnv_, &requestObj);

    napi_value formIdValue;
    napi_create_string_utf8(overflowEnv_, dataParam->formId.c_str(), NAPI_AUTO_LENGTH, &formIdValue);
    napi_set_named_property(overflowEnv_, requestObj, "formId", formIdValue);
    napi_set_named_property(overflowEnv_, requestObj, "isOverflow", CreateJsValue(overflowEnv_, dataParam->isOverflow));

    napi_value overflowInfoValue;
    CreateFormOverflowInfo(overflowEnv_, dataParam->overflowInfo, &overflowInfoValue);
    napi_set_named_property(overflowEnv_, requestObj, "overflowInfo", overflowInfoValue);

    napi_value myCallback = nullptr;
    napi_get_reference_value(overflowEnv_, overflowRegisterCallback_, &myCallback);

    napi_valuetype valueType;
    napi_typeof(overflowEnv_, myCallback, &valueType);

    if (valueType != napi_function) {
        dataParam->result = false;
        napi_close_handle_scope(overflowEnv_, scope);
        return;
    }

    napi_value args[] = { requestObj };
    napi_value callResult = nullptr;
    napi_status status = napi_call_function(overflowEnv_, nullptr, myCallback, 1, args, &callResult);
    if (status != napi_ok) {
        dataParam->result = false;
        napi_close_handle_scope(overflowEnv_, scope);
        return;
    }

    napi_valuetype returnType;
    napi_typeof(overflowEnv_, callResult, &returnType);

    bool result = false;
    if (returnType == napi_undefined) {
        dataParam->result = false;
        napi_close_handle_scope(overflowEnv_, scope);
        return;
    }

    napi_get_value_bool(overflowEnv_, callResult, &result);
    dataParam->result = result;
    napi_close_handle_scope(overflowEnv_, scope);
}

void JsFormRouterProxyMgr::CreateFormOverflowInfo(napi_env env, AppExecFwk::OverflowInfo &overflowInfo,
    napi_value* result)
{
    HILOG_INFO("CreateFormOverflowInfo call");
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        HILOG_ERROR("null scope");
        return;
    }
    napi_value area = nullptr;
    napi_create_object(env, &area);
    napi_set_named_property(env, area, "left", CreateJsValue(env, overflowInfo.area.left));
    napi_set_named_property(env, area, "top", CreateJsValue(env, overflowInfo.area.top));
    napi_set_named_property(env, area, "width", CreateJsValue(env, overflowInfo.area.width));
    napi_set_named_property(env, area, "height", CreateJsValue(env, overflowInfo.area.height));

    napi_value duration = nullptr;
    napi_create_int32(env, overflowInfo.duration, &duration);
    napi_create_object(env, result);
    napi_set_named_property(env, *result, "area", area);
    napi_set_named_property(env, *result, "duration", duration);
    napi_close_handle_scope(env, scope);
}

bool JsFormRouterProxyMgr::RegisterChangeSceneAnimationStateListener(napi_env env, napi_ref callbackRef)
{
    HILOG_INFO("call");

    if (callbackRef == nullptr) {
        HILOG_ERROR("Invalid callback reference");
        return false;
    }

    if (changeSceneAnimationStateRigisterCallback_ != nullptr) {
        napi_delete_reference(env, changeSceneAnimationStateRigisterCallback_);
        changeSceneAnimationStateRigisterCallback_ = nullptr;
    }

    changeSceneAnimationStateRigisterCallback_ = callbackRef;
    changeSceneAnimationStateEnv_ = env;

    napi_value callback;
    napi_get_reference_value(env, callbackRef, &callback);
    napi_valuetype valueType;
    napi_typeof(env, callback, &valueType);
    if (valueType != napi_function) {
        HILOG_ERROR("Callback is not a function");
        return false;
    }

    HILOG_INFO("Listener registered successfully");
    return true;
}

bool JsFormRouterProxyMgr::UnregisterChangeSceneAnimationStateListener()
{
    HILOG_INFO("call");
    changeSceneAnimationStateRigisterCallback_ = nullptr;
    changeSceneAnimationStateEnv_ = nullptr;
    return true;
}

ErrCode JsFormRouterProxyMgr::ChangeSceneAnimationState(const int64_t formId, int32_t state)
{
    HILOG_INFO("call");
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(overflowEnv_, &loop);
    if (loop == nullptr) {
        HILOG_ERROR("Failed to get loop, formId:%{public}" PRId64 ".", formId);
        return ERR_GET_INFO_FAILED;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        HILOG_ERROR("Failed to new uv_work_t, formId:%{public}" PRId64 ".", formId);
        return ERR_GET_INFO_FAILED;
    }

    LiveFormInterfaceParam* dataParam = new (std::nothrow) LiveFormInterfaceParam {
        .formId = std::to_string(formId),
        .state = state
    };
    if (dataParam == nullptr) {
        HILOG_ERROR("Failed to new dataParam, formId:%{public}" PRId64 ".", formId);
        delete work;
        return ERR_GET_INFO_FAILED;
    }
    work->data = dataParam;
    uv_queue_work(
        loop, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int status) {
            LiveFormInterfaceParam* dataParam = (LiveFormInterfaceParam*)work->data;
            JsFormRouterProxyMgr::GetInstance()->ChangeSceneAnimationStateInner(dataParam);
            std::unique_lock<std::mutex> lock(dataParam->mutex);
            dataParam->isReady = true;
            dataParam->condition.notify_all();
            delete work;
        });
    std::unique_lock<std::mutex> lock(dataParam->mutex);
    dataParam->condition.wait(lock, [&] { return dataParam->isReady; });
    bool result = dataParam->result;

    delete dataParam;
    return result ? ERR_OK : ERR_GET_INFO_FAILED;
}

void JsFormRouterProxyMgr::ChangeSceneAnimationStateInner(LiveFormInterfaceParam* dataParam)
{
    HILOG_INFO("call");
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(changeSceneAnimationStateEnv_, &scope);
    if (scope == nullptr) {
        HILOG_ERROR("null scope");
        return;
    }
    napi_value requestObj;
    napi_create_object(changeSceneAnimationStateEnv_, &requestObj);

    napi_value formIdValue;
    napi_create_string_utf8(changeSceneAnimationStateEnv_, dataParam->formId.c_str(), NAPI_AUTO_LENGTH, &formIdValue);
    napi_set_named_property(changeSceneAnimationStateEnv_, requestObj, "formId", formIdValue);
    napi_set_named_property(changeSceneAnimationStateEnv_, requestObj, "state",
        CreateJsValue(changeSceneAnimationStateEnv_, dataParam->state));

    napi_value myCallback = nullptr;
    napi_get_reference_value(changeSceneAnimationStateEnv_, changeSceneAnimationStateRigisterCallback_, &myCallback);

    napi_valuetype valueType;
    napi_typeof(changeSceneAnimationStateEnv_, myCallback, &valueType);

    if (valueType != napi_function) {
        dataParam->result = false;
        napi_close_handle_scope(changeSceneAnimationStateEnv_, scope);
        return;
    }

    napi_value args[] = { requestObj };
    napi_value callResult = nullptr;
    napi_status status = napi_call_function(changeSceneAnimationStateEnv_, nullptr, myCallback, 1, args, &callResult);
    if (status != napi_ok) {
        dataParam->result = false;
        napi_close_handle_scope(changeSceneAnimationStateEnv_, scope);
        return;
    }

    napi_valuetype returnType;
    napi_typeof(changeSceneAnimationStateEnv_, callResult, &returnType);

    if (returnType == napi_undefined) {
        dataParam->result = false;
        napi_close_handle_scope(changeSceneAnimationStateEnv_, scope);
        return;
    }

    bool result = false;
    napi_get_value_bool(changeSceneAnimationStateEnv_, callResult, &result);
    dataParam->result = result;
    napi_close_handle_scope(changeSceneAnimationStateEnv_, scope);
}

bool JsFormRouterProxyMgr::RegisterGetFormRectListener(napi_env env, napi_ref callbackRef)
{
    HILOG_INFO("call");
    if (callbackRef == nullptr) {
        HILOG_ERROR("Invalid callback reference");
        return false;
    }

    if (getFormRectCallbackRef_ != nullptr) {
        napi_delete_reference(env, getFormRectCallbackRef_);
        getFormRectCallbackRef_ = nullptr;
    }

    getFormRectCallbackRef_ = callbackRef;
    getFormRectEnv_ = env;

    napi_value callback;
    napi_get_reference_value(env, callbackRef, &callback);
    napi_valuetype valueType;
    napi_typeof(env, callback, &valueType);
    if (valueType != napi_function) {
        HILOG_ERROR("Callback is not a function");
        return false;
    }

    HILOG_INFO("Listener registered successfully");
    return true;
}

bool JsFormRouterProxyMgr::UnregisterGetFormRectListener()
{
    HILOG_INFO("call");
    getFormRectCallbackRef_ = nullptr;
    getFormRectEnv_ = nullptr;
    return true;
}
 
ErrCode JsFormRouterProxyMgr::GetFormRect(const int64_t formId, AppExecFwk::Rect &rect)
{
    HILOG_INFO("call");
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(getFormRectEnv_, &loop);
    if (loop == nullptr) {
        HILOG_ERROR("Failed to get loop, formId:%{public}" PRId64 ".", formId);
        return ERR_GET_INFO_FAILED;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        HILOG_ERROR("Failed to new uv_work_t, formId:%{public}" PRId64 ".", formId);
        return ERR_GET_INFO_FAILED;
    }
    
    LiveFormInterfaceParam* dataParam = new (std::nothrow) LiveFormInterfaceParam {
        .formId = std::to_string(formId)
    };
    if (dataParam == nullptr) {
        HILOG_ERROR("Failed to new dataParam, formId:%{public}" PRId64 ".", formId);
        delete work;
        return ERR_GET_INFO_FAILED;
    }
    work->data = dataParam;
    uv_queue_work(
        loop, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int status) {
            LiveFormInterfaceParam* dataParam = (LiveFormInterfaceParam*)work->data;
            if (dataParam != nullptr) {
                JsFormRouterProxyMgr::GetInstance()->GetFormRectInner(dataParam);
            }
            HILOG_INFO("getFormRect start notify.");
            std::unique_lock<std::mutex> lock(dataParam->mutex);
            dataParam->isReady = true;
            dataParam->condition.notify_all();
            delete work;
        });
    std::unique_lock<std::mutex> lock(dataParam->mutex);
    dataParam->condition.wait(lock, [&] { return dataParam->isReady; });
    bool result = dataParam->result;
    rect = std::move(dataParam->formRect);
    delete dataParam;
    return result ? ERR_OK : ERR_GET_INFO_FAILED;
}

void CallBackReturn(const Rect &item, LiveFormInterfaceParam* liveFormInterfaceParam, bool ret)
{
    if (liveFormInterfaceParam == nullptr) {
        HILOG_INFO("getFormRect callback param has been released");
        return;
    }
    liveFormInterfaceParam->result = ret;
    liveFormInterfaceParam->formRect = item;
    HILOG_INFO("getFormRect end.");
}
 
void JsFormRouterProxyMgr::GetFormRectInner(LiveFormInterfaceParam *dataParam)
{
    HILOG_INFO("call");
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(getFormRectEnv_, &scope);
    if (scope == nullptr) {
        HILOG_ERROR("null scope");
        return;
    }
    AbilityRuntime::HandleEscape handleEscape(getFormRectEnv_);
    napi_value callbackValue;
    napi_create_string_utf8(getFormRectEnv_, dataParam->formId.c_str(), NAPI_AUTO_LENGTH, &callbackValue);
 
    napi_value myCallback = nullptr;
    napi_get_reference_value(getFormRectEnv_, getFormRectCallbackRef_, &myCallback);
    napi_valuetype valueType;
    napi_typeof(getFormRectEnv_, myCallback, &valueType);

    if (valueType != napi_function) {
        dataParam->result = false;
        napi_close_handle_scope(getFormRectEnv_, scope);
        return;
    }
    napi_value callResult = nullptr;
    napi_status status =
        napi_call_function(getFormRectEnv_, nullptr, myCallback, ARGS_ONE, &callbackValue, &callResult);
    if (status != napi_ok) {
        dataParam->result = false;
        napi_close_handle_scope(getFormRectEnv_, scope);
        return;
    }

    napi_valuetype returnType;
    napi_typeof(getFormRectEnv_, callResult, &returnType);

    if (returnType == napi_undefined) {
        dataParam->result = false;
        napi_close_handle_scope(getFormRectEnv_, scope);
        return;
    }
    bool isPromise = false;
    napi_value funcResult = handleEscape.Escape(callResult);
    napi_is_promise(getFormRectEnv_, funcResult, &isPromise);
    if (!isPromise) {
        HILOG_INFO("result not promise");
        std::unique_ptr<AppExecFwk::Rect> item = std::make_unique<AppExecFwk::Rect>();
        bool ret = ConvertFunctionResult(getFormRectEnv_, funcResult, *item);
        CallBackReturn(*item, dataParam, ret);
        napi_close_handle_scope(getFormRectEnv_, scope);
        return;
    }
    CallPromise(funcResult, dataParam);
    napi_close_handle_scope(getFormRectEnv_, scope);
}
 
void JsFormRouterProxyMgr::CallPromise(napi_value funcResult, LiveFormInterfaceParam *params)
{
    HILOG_INFO("call");
    napi_value promiseThen = nullptr;
    napi_value promiseCatch = nullptr;
    napi_get_named_property(getFormRectEnv_, funcResult, "then", &promiseThen);
    napi_get_named_property(getFormRectEnv_, funcResult, "catch", &promiseCatch);
 
    bool isCallable = false;
    napi_is_callable(getFormRectEnv_, promiseThen, &isCallable);
    if (!isCallable) {
        HILOG_ERROR("property then is not callable.");
        return;
    }
    napi_is_callable(getFormRectEnv_, promiseCatch, &isCallable);
    if (!isCallable) {
        HILOG_ERROR("property catch is not callable.");
        return;
    }
 
    napi_value promiseCallback = nullptr;
    auto *callbackInfo = PromiseCallbackInfo::Create(params);
    napi_create_function(getFormRectEnv_, "promiseCallback", strlen("promiseCallback"), PromiseCallback,
        callbackInfo, &promiseCallback);
 
    napi_status status;
    napi_value argvPromise[1] = { promiseCallback };
 
    status = napi_call_function(getFormRectEnv_, funcResult, promiseThen, ARGS_ONE, argvPromise, nullptr);
    if (status != napi_ok) {
        HILOG_ERROR("Invoke pushCheck promise then error.");
        PromiseCallbackInfo::Destroy(callbackInfo);
        Rect info;
        CallBackReturn(info, params, false);
        return;
    }
 
    status = napi_call_function(getFormRectEnv_, funcResult, promiseCatch, ARGS_ONE, argvPromise, nullptr);
    if (status != napi_ok) {
        HILOG_ERROR("Invoke pushCheck promise catch error.");
        PromiseCallbackInfo::Destroy(callbackInfo);
        Rect info;
        CallBackReturn(info, params, false);
        return;
    }
}
 
napi_value JsFormRouterProxyMgr::PromiseCallback(napi_env env, napi_callback_info info)
{
    HILOG_INFO("enter");
    if (info == nullptr) {
        HILOG_ERROR("PromiseCallback, invalid input info");
        return nullptr;
    }
 
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    void *data = nullptr;
 
    napi_get_cb_info(env, info, &argc, &argv[PARAM0], nullptr, &data);
    std::unique_ptr<AppExecFwk::Rect> item = std::make_unique<AppExecFwk::Rect>();
    bool ret = ConvertFunctionResult(env, argv[PARAM0], *item);
    if (data == nullptr) {
        HILOG_ERROR("PromiseCallback, invalid data");
        return nullptr;
    }
 
    auto *callbackInfo = static_cast<PromiseCallbackInfo *>(data);
    if (callbackInfo == nullptr) {
        HILOG_ERROR("PromiseCallback, invalid callbackInfo");
        return nullptr;
    }
    CallBackReturn(*item, callbackInfo->GetJsCallBackParam(), ret);
 
    PromiseCallbackInfo::Destroy(callbackInfo);
    callbackInfo = nullptr;
    return nullptr;
}
 
bool JsFormRouterProxyMgr::ConvertFunctionResult(napi_env env, napi_value funcResult, Rect &item)
{
    if (funcResult == nullptr) {
        HILOG_ERROR("The funcResult is error.");
        return false;
    }
 
    napi_valuetype rectType = napi_undefined;
    napi_typeof(env, funcResult, &rectType);
    if (rectType != napi_object) {
        HILOG_ERROR("form rect type not napi_object");
        return false;
    }
    bool isItemValid = CreateFormRectInfo(env, funcResult, item);
    if (!isItemValid) {
        HILOG_ERROR("create form rect error");
        return false;
    }
 
    return true;
}
 
PromiseCallbackInfo::PromiseCallbackInfo(LiveFormInterfaceParam* liveFormInterfaceParam)
    : liveFormInterfaceParam_(liveFormInterfaceParam)
{}
 
PromiseCallbackInfo::~PromiseCallbackInfo() = default;
 
PromiseCallbackInfo* PromiseCallbackInfo::Create(LiveFormInterfaceParam* liveFormInterfaceParam)
{
    return new (std::nothrow) PromiseCallbackInfo(liveFormInterfaceParam);
}
 
void PromiseCallbackInfo::Destroy(PromiseCallbackInfo *callbackInfo)
{
    delete callbackInfo;
}
 
LiveFormInterfaceParam* PromiseCallbackInfo::GetJsCallBackParam()
{
    return liveFormInterfaceParam_;
}
} // namespace AbilityRuntime
} // namespace OHOS
