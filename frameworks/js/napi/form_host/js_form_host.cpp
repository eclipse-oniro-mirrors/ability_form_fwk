
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
            HILOG_INFO("handler is nullptr");
            return;
        }
        handler_->PostSyncTask([thisWeakPtr = weak_from_this(), formId]() {
            auto sharedThis = thisWeakPtr.lock();
            if (sharedThis == nullptr) {
                HILOG_ERROR("sharedThis is nullptr.");
                return;
            }
            HILOG_DEBUG("task complete formId: form: %{public}" PRId64 ".", formId);
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
    HILOG_DEBUG("AddFormUninstallCallback start");
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
        HILOG_ERROR("failed to emplace callback");
        return false;
    }
    return true;
}

bool DelFormUninstallCallback(napi_value callback)
{
    HILOG_DEBUG("DelFormUninstallCallback start");
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
        HILOG_INFO("JsFormHost::Finalizer is called");
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

    static napi_value GetRunningFormInfos(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnGetRunningFormInfos);
    }

    static napi_value GetFormInstanceById(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormHost, OnGetFormInstanceById);
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
            HILOG_ERROR("convert strFormId failed.");
            return false;
        }

        if (strFormId.empty()) {
            HILOG_ERROR("strFormId is empty.");
            return false;
        }

        if (!ConvertStringToInt64(strFormId, formId)) {
            HILOG_ERROR("convert string formId to int64 failed.");
            return false;
        }
        return true;
    }

    bool GetStringsValue(napi_env env, napi_value array, std::vector<std::string> &strList)
    {
        napi_valuetype paramType = napi_undefined;
        napi_typeof(env, array, &paramType);
        if (paramType == napi_undefined || paramType == napi_null) {
            HILOG_ERROR("input array is napi_undefined or napi_null.");
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
            HILOG_ERROR("convert strFormIdList failed!");
            return false;
        }

        for (size_t i = 0; i < strFormIdList.size(); i++) {
            int64_t formIdValue;
            if (!ConvertStringToInt64(strFormIdList[i], formIdValue)) {
                HILOG_ERROR("convert formIdValue failed!");
                return false;
            }
            formIds.push_back(formIdValue);
        }
        return true;
    }

    bool ConvertDeviceId(napi_env env, napi_value jsValue, std::string &deviceId)
    {
        if (!ConvertFromJsValue(env, jsValue, deviceId)) {
            HILOG_ERROR("convert deviceId failed.");
            return false;
        }

        if (deviceId.empty()) {
            HILOG_ERROR("deviceId is empty.");
            return false;
        }

        return true;
    }

    bool ParseParameter(napi_env env, napi_value *argv, int32_t &formErrorCode, std::string &messageInfo)
    {
        napi_valuetype param1Type = napi_undefined;
        napi_typeof(env, argv[1], &param1Type);
        if (param1Type != napi_object) {
            HILOG_ERROR("result is not napi_object.");
            return false;
        }
        napi_value publishFormErrorCode = nullptr;
        napi_status codeRet = napi_get_named_property(env, argv[1], "code", &publishFormErrorCode);
        napi_value message = nullptr;
        napi_status messageRet = napi_get_named_property(env, argv[1], "message", &message);
        if (codeRet != napi_ok || messageRet != napi_ok) {
            HILOG_ERROR("get property failed.");
            return false;
        }
        messageInfo = GetStringFromNapi(env, message);
        if (napi_get_value_int32(env, publishFormErrorCode, &formErrorCode) == napi_ok) {
            if (formErrorCode < static_cast<int32_t>(Constants::PublishFormErrorCode::SUCCESS) ||
                    formErrorCode > static_cast<int32_t>(Constants::PublishFormErrorCode::INTERNAL_ERROR)) {
                HILOG_ERROR("PublishFormResult is convert fail.");
                return false;
            }
        } else {
            HILOG_ERROR("PublishFormErrorCode is not number.");
            return false;
        }
        return true;
    }

    napi_value OnAddForm(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_INFO("called.");

        if (argc != ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1");
            return CreateJsUndefined(env);
        }

        Want want;
        if (!UnwrapWant(env, argv[PARAM0], want)) {
            HILOG_ERROR("UnwrapWant failed");
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
            HILOG_INFO("return ret: %{public}d, formId: %{public}" PRId64 "", *ret, runningFormInfo->formId);
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
        HILOG_DEBUG("%{public}s called.", __func__);
        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("OnDeleteForm wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        NapiAsyncTask::CompleteCallback complete = [formId](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().DeleteForm(formId, FormHostClient::GetInstance());
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnDeleteForm",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnReleaseForm(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("%{public}s called.", __func__);

        if (argc > ARGS_THREE || argc < ARGS_ONE) {
            HILOG_ERROR("OnReleaseForm wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2 or 3");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        bool isReleaseCache = false;
        if ((argc == ARGS_TWO || argc == ARGS_THREE) && !IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            if (!ConvertFromJsValue(env, argv[PARAM1], isReleaseCache)) {
                HILOG_ERROR("convert isReleaseCache failed!");
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
        HILOG_DEBUG("%{public}s called.", __func__);

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
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
        HILOG_DEBUG("%{public}s called.", __func__);

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        if (argc == ARGS_TWO && !IsTypeForNapiValue(env, argv[PARAM1], napi_object)) {
            HILOG_ERROR("second input param is invalid.");
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
        HILOG_DEBUG("%{public}s called.", __func__);

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
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
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
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
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
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
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
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
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> iFormIds;
        if (!ConvertFromIds(env, argv[PARAM0], iFormIds)) {
            HILOG_ERROR("form id list is invalid.");
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
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("This app is not system-app, can not use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }

        if (argc > ARGS_ONE || argc < ARGS_ZERO) {
            HILOG_ERROR("wrong number of arguments.");
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
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
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
            HILOG_DEBUG("AcquireFormState failed.");
            asyncTask->Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, result));
            FormHostClient::GetInstance()->RemoveFormState(want);
        }
    }

    napi_value OnAcquireFormState(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);
        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        Want want;
        napi_value argWant = argv[PARAM0];
        if (!UnwrapWant(env, argWant, want)) {
            HILOG_ERROR("want is invalid.");
            NapiFormUtil::ThrowParamTypeError(env, "want", "Want");
            return CreateJsUndefined(env);
        }

        napi_value lastParam = (argc == ARGS_ONE) ? nullptr : argv[PARAM1];
        napi_value result = nullptr;

        std::unique_ptr<AbilityRuntime::NapiAsyncTask> uasyncTask =
            AbilityRuntime::CreateAsyncTaskWithLastParam(env, lastParam, nullptr, nullptr, &result);
        std::shared_ptr<AbilityRuntime::NapiAsyncTask> asyncTask = std::move(uasyncTask);

        JsFormStateCallbackClient::AcquireFormStateTask task = [env, asyncTask](int32_t state, Want want) {
            HILOG_DEBUG("task complete state: %{public}d", state);
            napi_value objValue = nullptr;
            napi_create_object(env, &objValue);
            napi_set_named_property(env, objValue, "want", CreateJsWant(env, want));
            napi_set_named_property(env, objValue, "formState", CreateJsValue(env, state));
            asyncTask->ResolveWithNoError(env, objValue);
        };

        InnerAcquireFormState(env, asyncTask, std::move(task), want);
        return result;
    }

    napi_value OnRegisterFormUninstallObserver(napi_env env, size_t argc, napi_value* argv)
    {
        // Check the number of input parameters.
        if (argc != ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2");
            return CreateJsUndefined(env);
        }

        // Check the type of the PARAM1.
        if (!IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            HILOG_ERROR("param1 is invalid");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<string>");
            return CreateJsUndefined(env);
        }
        FormHostClient::GetInstance()->RegisterUninstallCallback(FormUninstallCallback);
        AddFormUninstallCallback(env, argv[1]);
        return CreateJsUndefined(env);
    }

    napi_value OnSetRouterProxy(napi_env env, size_t argc, napi_value* argv)
    {
        if (argc > ARGS_THREE || argc < ARGS_TWO) {
            HILOG_ERROR("Wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2 or 3");
            return CreateJsUndefined(env);
        }
        decltype(argc) convertArgc = 0;

        // Check the type of the PARAM0.
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("Form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        // Check the type of the PARAM1.
        if (!IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            HILOG_ERROR("Param2 is invalid");
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
    }

    napi_value OnClearRouterProxy(napi_env env, size_t argc, napi_value* argv)
    {
        // Check the number of input parameters.
        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("Wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }
        decltype(argc) convertArgc = 0;

        // Check the type of the PARAM0.
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("Form id list is invalid.");
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
    }

    napi_value OnRegisterFormObserver(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("called.");

        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("This app is not system-app, can not use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }

        std::string type;
        if (!ConvertFromJsValue(env, argv[PARAM0], type)) {
            HILOG_ERROR("convert type failed!");
            NapiFormUtil::ThrowParamTypeError(env, "type",
                "formAdd, formRemove, formUninstall, notifyVisible or notifyInvisible.");
            return CreateJsUndefined(env);
        }

        if (type == "formUninstall") {
            return OnRegisterFormUninstallObserver(env, argc, argv);
        } else {
            HILOG_ERROR("args[0] should be formUninstall.");
            NapiFormUtil::ThrowParamTypeError(env, "type", "formUninstall");
            return CreateJsUndefined(env);
        }
    }

    napi_value OnUnregisterFormUninstallObserver(napi_env env, size_t argc, napi_value* argv)
    {
        // Check the number of input parameters.
        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        // Check the type of the PARAM1.
        if (argc == ARGS_TWO && !IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            HILOG_ERROR("param1 is invalid");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<string>");
            return CreateJsUndefined(env);
        }

        if (argc == ARGS_TWO) {
            DelFormUninstallCallback(argv[PARAM1]);
            return CreateJsUndefined(env);
        }

        ClearFormUninstallCallback();
        return CreateJsUndefined(env);
    }

    napi_value OnUnregisterFormObserver(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("called.");

        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("This application is not system-app, can not use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }

        // Check the type of the PARAM0 and convert it to string.
        std::string type;
        if (!ConvertFromJsValue(env, argv[PARAM0], type)) {
            HILOG_ERROR("convert type error!");
            NapiFormUtil::ThrowParamTypeError(env, "type",
                "formAdd, formRemove, formUninstall, notifyVisible or notifyInvisible.");
            return CreateJsUndefined(env);
        }

        if (type == "formUninstall") {
            return OnUnregisterFormUninstallObserver(env, argc, argv);
        } else {
            HILOG_ERROR("args[0] should be formUninstall.");
            NapiFormUtil::ThrowParamTypeError(env, "type", "formUninstall");
            return CreateJsUndefined(env);
        }
    }

    napi_value OnNotifyFormsVisible(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (argc > ARGS_THREE || argc < ARGS_TWO) {
            HILOG_ERROR("wrong number of parameter.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2 or 3");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        bool isVisible = false;
        if (!ConvertFromJsValue(env, argv[PARAM1], isVisible)) {
            HILOG_ERROR("convert isVisible failed!");
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
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (argc > ARGS_THREE || argc < ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2 or 3");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        bool isEnableUpdate = false;
        if (!ConvertFromJsValue(env, argv[PARAM1], isEnableUpdate)) {
            HILOG_ERROR("convert isEnableUpdate failed!");
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
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);
        if (argc > ARGS_ONE || argc < ARGS_ZERO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "0 or 1");
            return CreateJsUndefined(env);
        }

        auto errCodeVal = std::make_shared<int32_t>(0);
        auto formInfoList = std::make_shared<std::vector<FormInfo>>();
        NapiAsyncTask::ExecuteCallback execute = [formInfos = formInfoList, errCode = errCodeVal]() {
            if (formInfos == nullptr || errCode == nullptr) {
                HILOG_ERROR("The param is invalid.");
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
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);
        if (argc != ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
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
                HILOG_ERROR("The param is invalid.");
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
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);
        if (argc == ARGS_ONE && IsTypeForNapiValue(env, argv[PARAM0], napi_object)) {
            return GetFormsInfoByFilter(env, argc, argv);
        }
        if (argc > ARGS_THREE || argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2 or 3");
            return CreateJsUndefined(env);
        }
        decltype(argc) convertArgc = 0;
        std::string bName("");
        if (!ConvertFromJsValue(env, argv[PARAM0], bName)) {
            HILOG_ERROR("bundle name convert failed.");
            NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;
        std::string mName("");
        if ((argc == ARGS_TWO || argc == ARGS_THREE) && !IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            if (!ConvertFromJsValue(env, argv[PARAM1], mName)) {
                HILOG_ERROR("module name convert failed.");
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
                HILOG_ERROR("The param is invalid.");
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
                HILOG_ERROR("The param is invalid.");
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
            HILOG_INFO("%{public}s, share form failed.", __func__);
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
            HILOG_ERROR("acquire form failed.");
            asyncTask->Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            FormHostClient::GetInstance()->RemoveAcquireDataCallback(requestCode);
        }
    }

    napi_value OnShareForm(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);
        if (argc > ARGS_THREE || argc < ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2 or 3");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        std::string devicedId;
        if (!ConvertDeviceId(env, argv[PARAM1], devicedId)) {
            HILOG_ERROR("deviced id is invalid.");
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
            HILOG_DEBUG("task complete code: %{public}d", code);
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
        HILOG_DEBUG("OnAcquireFormData is called");
        if (argc > ARGS_TWO || argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        // The promise form has only one parameters
        decltype(argc) unwrapArgc = 1;
        int64_t formId = 0;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
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
    }

    napi_value OnNotifyFormsPrivacyProtected(napi_env env, size_t argc, napi_value* argv)
    {
        HILOG_INFO("%{public}s is called", __func__);
        if (argc > ARGS_THREE || argc < ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2 or 3");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        bool isProtected = false;
        if (!ConvertFromJsValue(env, argv[PARAM1], isProtected)) {
            HILOG_ERROR("convert isProtected failed!");
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

    bool ParseGetRunningFormInfosOneParam(const napi_env &env, const napi_value *argv, std::string &bundleName,
        bool &hasBundleName, bool &isUnusedIncluded)
    {
        HILOG_DEBUG("called.");
        if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM0], napi_string)) {
            if (!ConvertFromJsValue(env, argv[PARAM0], bundleName)) {
                HILOG_ERROR("Convert bundleName failed.");
                NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
                return false;
            }
            hasBundleName = true;
        } else if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM0], napi_boolean)) {
            if (!ConvertFromJsValue(env, argv[PARAM0], isUnusedIncluded)) {
                HILOG_ERROR("Convert isUnusedIncluded failed.");
                NapiFormUtil::ThrowParamTypeError(env, "isUnusedIncluded", "bool");
                return false;
            }
        } else {
            HILOG_ERROR("Input params is not a string or boolean.");
            NapiFormUtil::ThrowParamTypeError(env, "the first param", "string or boolean");
            return false;
        }
        return true;
    }

    bool ParseGetRunningFormInfosParams(const napi_env &env, const napi_value *argv, std::string &bundleName,
        bool &isUnusedIncluded, int startPos)
    {
        HILOG_DEBUG("called.");
        if (!ConvertFromJsValue(env, argv[startPos], isUnusedIncluded)) {
            HILOG_ERROR("Convert isUnusedIncluded failed.");
            NapiFormUtil::ThrowParamTypeError(env, "isUnusedIncluded", "bool");
            return false;
        }
        if (!ConvertFromJsValue(env, argv[startPos + 1], bundleName)) {
            HILOG_ERROR("Convert bundleName failed.");
            NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
            return false;
        }
        return true;
    }

    bool ParseGetRunningFormInfosTwoParams(const napi_env &env, const napi_value *argv, std::string &bundleName,
        bool &hasBundleName, bool &isUnusedIncluded)
    {
        HILOG_DEBUG("called.");
        if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM0], napi_function)) {
            if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_string)) {
                if (!ConvertFromJsValue(env, argv[PARAM1], bundleName)) {
                    HILOG_ERROR("Convert bundleName failed.");
                    NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
                    return false;
                }
                hasBundleName = true;
            } else if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_boolean)) {
                if (!ConvertFromJsValue(env, argv[PARAM1], isUnusedIncluded)) {
                    HILOG_ERROR("Convert isUnusedIncluded failed.");
                    NapiFormUtil::ThrowParamTypeError(env, "isUnusedIncluded", "bool");
                    return false;
                }
            } else {
                HILOG_ERROR("Input params is not a string or boolean.");
                NapiFormUtil::ThrowParamTypeError(env, "the second param", "string or boolean");
                return false;
            }
        } else {
            if (!ParseGetRunningFormInfosParams(env, argv, bundleName, isUnusedIncluded, PARAM0)) {
                return false;
            }
            hasBundleName = true;
        }
        return true;
    }

    napi_value OnGetRunningFormInfos(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("called.");
        if (argc > ARGS_THREE) {
            HILOG_ERROR("Wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "0 or 1 or 2 or 3");
            return CreateJsUndefined(env);
        }

        std::string bundleName("");
        bool hasBundleName = false;
        bool isUnusedIncluded = false;
        if (argc == ARGS_ONE && !AppExecFwk::IsTypeForNapiValue(env, argv[PARAM0], napi_function)) {
            if (!ParseGetRunningFormInfosOneParam(env, argv, bundleName, hasBundleName, isUnusedIncluded)) {
                return CreateJsUndefined(env);
            }
        } else if (argc == ARGS_TWO) {
            if (!ParseGetRunningFormInfosTwoParams(env, argv, bundleName, hasBundleName, isUnusedIncluded)) {
                return CreateJsUndefined(env);
            }
        } else if (argc == ARGS_THREE) {
            if (!ParseGetRunningFormInfosParams(env, argv, bundleName, isUnusedIncluded, PARAM1)) {
                return CreateJsUndefined(env);
            }
            hasBundleName = true;
        }

        auto complete = [hostBundleName = bundleName, isUnusedIncluded, hasBundleName](
                            napi_env env, NapiAsyncTask &task, int32_t status) {
            std::vector<AppExecFwk::RunningFormInfo> runningFormInfos;
            auto ret = hasBundleName ? FormMgr::GetInstance().GetRunningFormInfosByBundleName(
                hostBundleName, isUnusedIncluded, runningFormInfos)
                                     : FormMgr::GetInstance().GetRunningFormInfos(isUnusedIncluded, runningFormInfos);
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            task.ResolveWithNoError(env, CreateRunningFormInfos(env, runningFormInfos));
        };
        napi_value result = nullptr;
        napi_value callbackParam =
            (argc >= ARGS_ONE) &&
                (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM0], napi_function)) ? argv[PARAM0] : nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnGetRunningFormInfos", env,
            CreateAsyncTaskWithLastParam(env, callbackParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnGetFormInstanceById(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("called.");
        if (argc < ARGS_ONE || argc > ARGS_THREE) {
            HILOG_ERROR("Wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2 or 3");
            return CreateJsUndefined(env);
        }
        decltype(argc) convertArgc = 0;
        int64_t formId;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("Convert strFormIdList failed.");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;
        bool isUnusedIncluded = false;
        if ((argc == ARGS_TWO || argc == ARGS_THREE) &&
            !AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            if (!ConvertFromJsValue(env, argv[PARAM1], isUnusedIncluded)) {
                HILOG_ERROR("Convert isUnusedIncluded failed.");
                NapiFormUtil::ThrowParamTypeError(env, "isUnusedIncluded", "bool");
                return CreateJsUndefined(env);
            }
            convertArgc++;
        }
        if (argc == ARGS_THREE && !AppExecFwk::IsTypeForNapiValue(env, argv[PARAM2], napi_function)) {
            HILOG_ERROR("The third param is invalid.");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<string>");
            return CreateJsUndefined(env);
        }
        std::shared_ptr<AppExecFwk::FormInstance> formInstance = std::make_shared<AppExecFwk::FormInstance>();
        auto apiResult = std::make_shared<int32_t>();
        auto execute = [formId, isUnusedIncluded, formInstance, ret = apiResult]() {
            *ret = FormMgr::GetInstance().GetFormInstanceById(formId, isUnusedIncluded, *formInstance);
        };

        auto complete =
            [formInstance, ret = apiResult](napi_env env, NapiAsyncTask &task, int32_t status) {
                if (*ret != ERR_OK) {
                    HILOG_ERROR("Get formInstance by id failed.");
                    task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, *ret));
                } else {
                    task.ResolveWithNoError(env, CreateFormInstance(env, *formInstance));
                }
            };
        napi_value lastParam = (argc == convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnGetFormInstanceById",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnSetFormsRecyclable(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("called.");
        if (argc < ARGS_ONE) {
            HILOG_ERROR("Wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
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
    }

    napi_value OnRecoverForms(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("called.");
        if (argc < ARGS_ONE) {
            HILOG_ERROR("Wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(env, "formIds", "Array<string>");
            return CreateJsUndefined(env);
        }
        convertArgc++;

        NapiAsyncTask::CompleteCallback complete = [formIds](napi_env env, NapiAsyncTask &task, int32_t status) {
            Want want;
            auto ret = FormMgr::GetInstance().RecoverForms(formIds, want);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            }
        };

        napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormHost::OnRecoverForms",
            env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnRecycleForms(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("called.");
        if (argc < ARGS_ONE) {
            HILOG_ERROR("Wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
            return CreateJsUndefined(env);
        }

        decltype(argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(env, argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
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

    napi_value OnUpdateFormLocation(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("UpdateFormLocation called.");
        if (argc != ARGS_TWO) {
            HILOG_ERROR("Wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "argc != 2");
            return CreateJsUndefined(env);
        }

        int64_t formId = -1;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("Convert strFormIdList failed.");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        HILOG_INFO("UpdateFormLocation formId value=%{public}s", std::to_string(formId).c_str());
        int32_t formLocation = INVALID_FORM_LOCATION;
        if (napi_get_value_int32(env, argv[PARAM1], &formLocation) == napi_ok) {
            if (formLocation < static_cast<int32_t>(Constants::FormLocation::OTHER) ||
                 formLocation > static_cast<int32_t>(Constants::FormLocation::AI_SUGGESTION)) {
                HILOG_ERROR("formLocation is not FormLocation enum.");
                NapiFormUtil::ThrowParamTypeError(env, "formLocation", "FormLocation enum");
                return CreateJsUndefined(env);
            }
        } else {
            HILOG_ERROR("formLocation is not number.");
            NapiFormUtil::ThrowParamTypeError(env, "formLocation", "number");
            return CreateJsUndefined(env);
        }
        HILOG_INFO("UpdateFormLocation formLocation value=%{public}s", std::to_string(formLocation).c_str());
        auto ret = FormMgr::GetInstance().UpdateFormLocation(formId, formLocation);
        if (ret == ERR_OK) {
            return CreateJsUndefined(env);
        }
        NapiFormUtil::ThrowByInternalErrorCode(env, ret);
        return CreateJsUndefined(env);
    }

    napi_value OnSetPublishFormResult(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("OnSetPublishFormResult called.");
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("This application is not system-app, can not use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }
        if (argc != ARGS_TWO) {
            HILOG_ERROR("Wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2");
            return CreateJsUndefined(env);
        }
        decltype(argc) convertArgc = 0;
        int64_t formId;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("Convert strFormId failed.");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;
        std::string messageInfo = "";
        int32_t formErrorCode = INVALID_FORM_RESULT_ERRCODE;
        if (!ParseParameter(env, argv, formErrorCode, messageInfo)) {
            HILOG_ERROR("Parsing Argument Errors.");
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
};

napi_value JsFormHostInit(napi_env env, napi_value exportObj)
{
    HILOG_DEBUG("JsFormHostInit is called");

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
    BindNativeFunction(env, exportObj, "getRunningFormInfos", moduleName, JsFormHost::GetRunningFormInfos);
    BindNativeFunction(env, exportObj, "getRunningFormInfoById", moduleName, JsFormHost::GetFormInstanceById);
    BindNativeFunction(env, exportObj, "setFormsRecyclable", moduleName, JsFormHost::SetFormsRecyclable);
    BindNativeFunction(env, exportObj, "recoverForms", moduleName, JsFormHost::RecoverForms);
    BindNativeFunction(env, exportObj, "recycleForms", moduleName, JsFormHost::RecycleForms);
    BindNativeFunction(env, exportObj, "updateFormLocation", moduleName, JsFormHost::UpdateFormLocation);
    BindNativeFunction(env, exportObj, "setPublishFormResult", moduleName, JsFormHost::SetPublishFormResult);
    BindNativeFunction(env, exportObj, "addForm", moduleName, JsFormHost::AddForm);

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
    HILOG_INFO("ProcessFormRouterProxy start");
    if (handler_ == nullptr) {
        HILOG_ERROR("Handler is nullptr");
        return;
    }
    handler_->PostSyncTask([thisWeakPtr = weak_from_this(), want]() {
        auto sharedThis = thisWeakPtr.lock();
        if (sharedThis == nullptr) {
            HILOG_ERROR("SharedThis is nullptr.");
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
                HILOG_ERROR("Error, failed to create JsFormRouterProxyMgr.");
            }
        }
    }
    return instance_;
}

ErrCode JsFormRouterProxyMgr::RouterEvent(int64_t formId, const Want &want)
{
    HILOG_DEBUG("called.");

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
    HILOG_DEBUG("called.");
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
}

void JsFormRouterProxyMgr::RemoveFormRouterProxyCallback(const std::vector<int64_t> &formIds)
{
    HILOG_INFO("Start");
    std::lock_guard<std::mutex> lock(FormRouterProxyCallbackMutex_);
    for (const auto &formId : formIds) {
        auto iter = formRouterProxyCallbackMap_.find(formId);
        if (iter != formRouterProxyCallbackMap_.end()) {
            formRouterProxyCallbackMap_.erase(formId);
        }
    }
}
} // namespace AbilityRuntime
} // namespace OHOS
