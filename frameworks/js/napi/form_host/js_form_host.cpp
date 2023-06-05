
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

#include "form_info.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "form_callback_interface.h"
#include "form_host_client.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"
#include "js_form_state_observer.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
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

class FormUninstallCallbackClient : public std::enable_shared_from_this<FormUninstallCallbackClient>
{
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
        HILOG_INFO("isStrictEqual: %{public}d", isEqual);
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
    HILOG_INFO("%{public}d form uninstall callback deleted.", count);
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

    static void Finalizer(NativeEngine* engine, void* data, void* hint)
    {
        HILOG_INFO("JsFormHost::Finalizer is called");
        std::unique_ptr<JsFormHost>(static_cast<JsFormHost*>(data));
    }

    static NativeValue* DeleteForm(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnDeleteForm(*engine, *info) : nullptr;
    }

    static NativeValue* ReleaseForm(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnReleaseForm(*engine, *info) : nullptr;
    }

    static NativeValue* RequestForm(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnRequestForm(*engine, *info) : nullptr;
    }

    static NativeValue* CastTempForm(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnCastTempForm(*engine, *info) : nullptr;
    }

    static NativeValue* NotifyVisibleForms(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnNotifyVisibleForms(*engine, *info) : nullptr;
    }

    static NativeValue* NotifyInvisibleForms(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnNotifyInvisibleForms(*engine, *info) : nullptr;
    }

    static NativeValue* EnableFormsUpdate(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnEnableFormsUpdate(*engine, *info) : nullptr;
    }

    static NativeValue* DisableFormsUpdate(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnDisableFormsUpdate(*engine, *info) : nullptr;
    }

    static NativeValue* IsSystemReady(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnIsSystemReady(*engine, *info) : nullptr;
    }

    static NativeValue* DeleteInvalidForms(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnDeleteInvalidForms(*engine, *info) : nullptr;
    }

    static NativeValue* AcquireFormState(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnAcquireFormState(*engine, *info) : nullptr;
    }

    static NativeValue* RegisterFormObserver(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnRegisterFormObserver(*engine, *info) : nullptr;
    }

    static NativeValue* UnregisterFormObserver(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnUnregisterFormObserver(*engine, *info) : nullptr;
    }

    static NativeValue* NotifyFormsVisible(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnNotifyFormsVisible(*engine, *info) : nullptr;
    }

    static NativeValue* NotifyFormsEnableUpdate(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnNotifyFormsEnableUpdate(*engine, *info) : nullptr;
    }

    static NativeValue* GetAllFormsInfo(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnGetAllFormsInfo(*engine, *info) : nullptr;
    }

    static NativeValue* GetFormsInfo(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnGetFormsInfo(*engine, *info) : nullptr;
    }

    static NativeValue* GetRunningFormInfos(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnGetRunningFormInfos(*engine, *info) : nullptr;
    }

    static NativeValue* ShareForm(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnShareForm(*engine, *info) : nullptr;
    }

    static NativeValue* AcquireFormData(NativeEngine *engine, NativeCallbackInfo *info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnAcquireFormData(*engine, *info) : nullptr;
    }

    static NativeValue* NotifyFormsPrivacyProtected(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsFormHost* me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnNotifyFormsPrivacyProtected(*engine, *info) : nullptr;
    }
    static NativeValue* GetFormInstancesByFilter(NativeEngine *engine, NativeCallbackInfo *info)
    {
        JsFormHost *me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnGetFormInstancesByFilter(*engine, *info) : nullptr;
    }

    static NativeValue* GetFormInstanceById(NativeEngine *engine, NativeCallbackInfo *info)
    {
        JsFormHost *me = CheckParamsAndGetThis<JsFormHost>(engine, info);
        return (me != nullptr) ? me->OnGetFormInstanceById(*engine, *info) : nullptr;
    }
private:
    bool CheckCallerIsSystemApp()
    {
        auto selfToken = IPCSkeleton::GetSelfTokenID();
        return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
    }

    static bool ConvertFromId(NativeEngine& engine, NativeValue* jsValue, int64_t &formId)
    {
        if (jsValue->TypeOf() != NATIVE_STRING) {
            HILOG_ERROR("input params is not string.");
            return false;
        }

        std::string strFormId;
        if (!ConvertFromJsValue(engine, jsValue, strFormId)) {
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

    bool GetStringsValue(NativeEngine &engine, NativeValue *object, std::vector<std::string> &strList)
    {
        auto array = ConvertNativeValueTo<NativeArray>(object);
        if (array == nullptr) {
            HILOG_ERROR("input params error");
            return false;
        }

        for (uint32_t i = 0; i < array->GetLength(); i++) {
            std::string itemStr("");
            if ((array->GetElement(i))->TypeOf() != NATIVE_STRING) {
                HILOG_ERROR("GetElement is not string");
                return false;
            }
            if (!ConvertFromJsValue(engine, array->GetElement(i), itemStr)) {
                HILOG_ERROR("GetElement from to array [%{public}u] error", i);
                return false;
            }
            strList.push_back(itemStr);
        }

        return true;
    }

    bool ConvertFromIds(NativeEngine& engine, NativeValue* jsValue, std::vector<int64_t> &formIds)
    {
        if (!(jsValue->IsArray())) {
            HILOG_ERROR("input params0 is not array!");
            return false;
        }

        std::vector<string> strFormIdList;
        if(!GetStringsValue(engine, jsValue, strFormIdList)) {
            HILOG_ERROR("convert strFormIdList failed!");
            return false;
        }

        for(size_t i = 0; i < strFormIdList.size(); i++) {
            int64_t formIdValue;
            if (!ConvertStringToInt64(strFormIdList[i], formIdValue)) {
                HILOG_ERROR("convert formIdValue failed!");
                return false;
            }
            formIds.push_back(formIdValue);
        }
        return true;
    }

    bool ConvertDeviceId(NativeEngine& engine, NativeValue* jsValue, std::string &deviceId)
    {
        if (jsValue->TypeOf() != NATIVE_STRING) {
            HILOG_ERROR("input params is not string.");
            return false;
        }

        if (!ConvertFromJsValue(engine, jsValue, deviceId)) {
            HILOG_ERROR("convert deviceId failed.");
            return false;
        }

        if (deviceId.empty()) {
            HILOG_ERROR("deviceId is empty.");
            return false;
        }

        return true;
    }

    NativeValue* OnDeleteForm(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s called.", __func__);

        if (info.argc > ARGS_TWO || info.argc < ARGS_ONE) {
            HILOG_ERROR("OnDeleteForm wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        HILOG_DEBUG("info.argv[PARAM0]->TypeOf() %{public}d", info.argv[PARAM0]->TypeOf());
        int64_t formId = 0;
        if (!ConvertFromId(engine, info.argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formId", "string");
            return engine.CreateUndefined();
        }
        convertArgc++;

        AsyncTask::CompleteCallback complete = [formId](NativeEngine &engine, AsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().DeleteForm(formId, FormHostClient::GetInstance());
            if (ret == ERR_OK) {
                task.ResolveWithNoError(engine, engine.CreateUndefined());
            } else {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            }
        };

        NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue* result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnDeleteForm",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnReleaseForm(NativeEngine &engine, const NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s called.", __func__);

        if (info.argc > ARGS_THREE || info.argc < ARGS_ONE) {
            HILOG_ERROR("OnReleaseForm wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2 or 3");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(engine, info.argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formId", "string");
            return engine.CreateUndefined();
        }
        convertArgc++;

        bool isReleaseCache = false;
        if ((info.argc == ARGS_TWO || info.argc == ARGS_THREE) && info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
            if (info.argv[PARAM1]->TypeOf() != NATIVE_BOOLEAN) {
                HILOG_ERROR("promise second param type is illegal");
                NapiFormUtil::ThrowParamTypeError(engine, "isReleaseCache", "boolean");
                return engine.CreateUndefined();
            }

            if (!ConvertFromJsValue(engine, info.argv[PARAM1], isReleaseCache)) {
                HILOG_ERROR("convert isReleaseCache failed!");
                NapiFormUtil::ThrowParamTypeError(engine, "isReleaseCache", "boolean");
                return engine.CreateUndefined();
            }
            convertArgc++;
        }

        AsyncTask::CompleteCallback complete = [formId, isReleaseCache]
            (NativeEngine &engine, AsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().ReleaseForm(formId, FormHostClient::GetInstance(), isReleaseCache);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(engine, engine.CreateUndefined());
            } else {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            }
        };

        NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue* result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnReleaseForm",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnRequestForm(NativeEngine &engine, const NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s called.", __func__);

        if (info.argc > ARGS_TWO || info.argc < ARGS_ONE) {
            HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(engine, info.argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formId", "string");
            return engine.CreateUndefined();
        }
        convertArgc++;

        AsyncTask::CompleteCallback complete = [formId](NativeEngine &engine, AsyncTask &task, int32_t status) {
            Want want;
            auto ret = FormMgr::GetInstance().RequestForm(formId, FormHostClient::GetInstance(), want);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(engine, engine.CreateUndefined());
            } else {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            }
        };

        NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue* result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnRequestForm",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnCastTempForm(NativeEngine &engine, const NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s called.", __func__);

        if (info.argc > ARGS_TWO || info.argc < ARGS_ONE) {
            HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        int64_t formId = 0;
        if (!ConvertFromId(engine, info.argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formId", "string");
            return engine.CreateUndefined();
        }
        convertArgc++;

        AsyncTask::CompleteCallback complete = [formId](NativeEngine &engine, AsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().CastTempForm(formId, FormHostClient::GetInstance());
            if (ret == ERR_OK) {
                task.ResolveWithNoError(engine, engine.CreateUndefined());
            } else {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            }
        };

        NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue* result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnCastTempForm",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnNotifyVisibleForms(NativeEngine &engine, const NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (info.argc > ARGS_TWO|| info.argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(engine, info.argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formIds", "Array<string>");
            return engine.CreateUndefined();
        }
        convertArgc++;

        auto complete = [formIds](NativeEngine &engine, AsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, FormHostClient::GetInstance(),
                Constants::FORM_VISIBLE);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(engine, engine.CreateUndefined());
            } else {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            }
        };

        NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnEnableFormsUpdate",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnNotifyInvisibleForms(NativeEngine &engine, const NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (info.argc > ARGS_TWO|| info.argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(engine, info.argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formIds", "Array<string>");
            return engine.CreateUndefined();
        }
        convertArgc++;

        auto complete = [formIds](NativeEngine &engine, AsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, FormHostClient::GetInstance(),
                Constants::FORM_INVISIBLE);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(engine, engine.CreateUndefined());
            } else {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            }
        };

        NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnEnableFormsUpdate",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnEnableFormsUpdate(NativeEngine &engine, const NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (info.argc > ARGS_TWO|| info.argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(engine, info.argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formIds", "Array<string>");
            return engine.CreateUndefined();
        }
        convertArgc++;

        auto complete = [formIds](NativeEngine &engine, AsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().LifecycleUpdate(formIds, FormHostClient::GetInstance(), true);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(engine, engine.CreateUndefined());
            } else {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            }
        };

        NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnEnableFormsUpdate",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnDisableFormsUpdate(NativeEngine &engine, const NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (info.argc > ARGS_TWO || info.argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            return engine.CreateUndefined();
    }

        decltype(info.argc) convertArgc = 0;
        std::vector<int64_t> iFormIds;
        if (!ConvertFromIds(engine, info.argv[PARAM0], iFormIds)) {
            HILOG_ERROR("form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formIds", "Array<string>");
            return engine.CreateUndefined();
        }
        convertArgc++;

        auto complete = [formIds = iFormIds](NativeEngine &engine, AsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().LifecycleUpdate(formIds, FormHostClient::GetInstance(), false);
            if (ret != ERR_OK) {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
                return;
            }
            task.ResolveWithNoError(engine, engine.CreateUndefined());
        };

        NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnDisableFormsUpdate",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnIsSystemReady(NativeEngine &engine, const NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("This application is not system-app, can not use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(engine, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return engine.CreateUndefined();
        }

        if (info.argc > ARGS_ONE || info.argc < ARGS_ZERO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "0 or 1");
            return engine.CreateUndefined();
        }

        auto complete = [](NativeEngine &engine, AsyncTask &task, int32_t status) {
            // Use original logic.
            // Use the error code to return whether the function executed successfully.
            auto ret = FormMgr::GetInstance().CheckFMSReady() ? 0 : 1;
            if( ret == ERR_OK ) {
                task.ResolveWithNoError(engine, engine.CreateUndefined());
            } else {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            }
        };

        auto callback = (info.argc == ARGS_ZERO) ? nullptr : info.argv[PARAM0];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnIsSystemReady",
            engine, CreateAsyncTaskWithLastParam(engine, callback, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnDeleteInvalidForms(NativeEngine &engine, const NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (info.argc > ARGS_TWO|| info.argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(engine, info.argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formIds", "Array<string>");
            return engine.CreateUndefined();
        }
        convertArgc++;

        auto complete = [formIds](NativeEngine &engine, AsyncTask &task, int32_t status) {
            int32_t num;
            auto ret = FormMgr::GetInstance().DeleteInvalidForms(formIds, FormHostClient::GetInstance(), num);
            if (ret == ERR_OK) {
                task.ResolveWithNoError(engine, CreateJsValue(engine, num));
            } else {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            }
        };

        NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnEnableFormsUpdate",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    void InnerAcquireFormState(
        NativeEngine &engine,
        const std::shared_ptr<AsyncTask> &asyncTask,
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
            asyncTask->Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, result));
            FormHostClient::GetInstance()->RemoveFormState(want);
        }
    }

    NativeValue* OnAcquireFormState(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);
        if (info.argc > ARGS_TWO || info.argc < ARGS_ONE) {
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            return engine.CreateUndefined();
        }

        Want want;
        auto env = reinterpret_cast<napi_env>(&engine);
        auto argWant = reinterpret_cast<napi_value>(info.argv[PARAM0]);
        if (!UnwrapWant(env, argWant, want)) {
            HILOG_ERROR("want is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "want", "Want");
            return engine.CreateUndefined();
        }

        NativeValue *lastParam = (info.argc == ARGS_ONE) ? nullptr : info.argv[PARAM1];
        NativeValue *result = nullptr;

        std::unique_ptr<AbilityRuntime::AsyncTask> uasyncTask =
            AbilityRuntime::CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, nullptr, &result);
        std::shared_ptr<AbilityRuntime::AsyncTask> asyncTask = std::move(uasyncTask);

        JsFormStateCallbackClient::AcquireFormStateTask task = [&engine, asyncTask](int32_t state, Want want) {
            HILOG_DEBUG("task complete state: %{public}d", state);
            NativeValue *objValue = engine.CreateObject();
            NativeObject *object = ConvertNativeValueTo<NativeObject>(objValue);
            object->SetProperty("want", CreateJsWant(engine, want));
            object->SetProperty("formState", CreateJsValue(engine, state));
            asyncTask->ResolveWithNoError(engine, objValue);
        };

        InnerAcquireFormState(engine, asyncTask, std::move(task), want);
        return result;
    }

    NativeValue* OnRegisterFormAddObserver(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("called.");
        decltype(info.argc) convertArgc = 1;
        // Check the number of input parameters.
        if (info.argc > ARGS_THREE|| info.argc < ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "2 or 3");
            return engine.CreateUndefined();
        }

        // Check the type of the PARAM1.
        if (info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
            HILOG_ERROR("param1 is invalid");
            NapiFormUtil::ThrowParamTypeError(engine, "callback", "Callback<formInfo.RunningFormInfo>");
            return engine.CreateUndefined();
        }

        std::string bundleName("");
        if (info.argc == ARGS_THREE) {
            // Check the type of the PARAM2 and convert it to string.
            if (info.argv[PARAM2]->TypeOf() != NATIVE_STRING) {
                HILOG_ERROR("param2 is invalid");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
            if (!ConvertFromJsValue(engine, info.argv[PARAM2], bundleName)) {
                HILOG_ERROR("convert type failed!");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
            convertArgc++;
        }

        // Check the size of the map.
        if (!JsFormStateObserver::GetInstance()->CheckMapSize("formAdd", bundleName)) {
            NapiFormUtil::ThrowParamError(engine,
                "The number of bundleNames registered to listen has exceeded the limit");
            return engine.CreateUndefined();
        }

        // if there is a full observer.
        if (info.argc == ARGS_TWO) {
            bundleName = "all";
        }

        if (!JsFormStateObserver::GetInstance()->RegisterFormAddCallback(reinterpret_cast<napi_env>(&engine),
            bundleName, reinterpret_cast<napi_value>(info.argv[1]))) {
            return engine.CreateUndefined();
        }
        FormMgr::GetInstance().RegisterFormAddObserverByBundle(bundleName, JsFormStateObserver::GetInstance());
        return engine.CreateUndefined();
    }

    NativeValue* OnRegisterFormRemoveObserver(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("called.");
        decltype(info.argc) convertArgc = 1;
        // Check the number of input parameters.
        if (info.argc > ARGS_THREE|| info.argc < ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "2 or 3");
            return engine.CreateUndefined();
        }

        // Check the type of the PARAM1.
        if (info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
            HILOG_ERROR("param1 is invalid");
            NapiFormUtil::ThrowParamTypeError(engine, "callback", "Callback<formInfo.RunningFormInfo>");
            return engine.CreateUndefined();
        }

        std::string bundleName("");
        if (info.argc == ARGS_THREE) {
            // Check the type of the PARAM2 and convert it to string.
            if (info.argv[PARAM2]->TypeOf() != NATIVE_STRING) {
                HILOG_ERROR("param2 is invalid");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
            if (!ConvertFromJsValue(engine, info.argv[PARAM2], bundleName)) {
                HILOG_ERROR("convert type failed!");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
            convertArgc++;
        }

        // Check the size of the map.
        if (!JsFormStateObserver::GetInstance()->CheckMapSize("formRemove", bundleName)) {
            NapiFormUtil::ThrowParamError(engine,
                "The number of bundleNames registered to listen has exceeded the limit");
            return engine.CreateUndefined();
        }

        // if there is a full observer.
        if (info.argc == ARGS_TWO) {
            bundleName = "all";
        }

        if (!JsFormStateObserver::GetInstance()->RegisterFormRemoveCallback(reinterpret_cast<napi_env>(&engine),
            bundleName, reinterpret_cast<napi_value>(info.argv[1]))) {
            return engine.CreateUndefined();
        }

        FormMgr::GetInstance().RegisterFormRemoveObserverByBundle(bundleName, JsFormStateObserver::GetInstance());
        return engine.CreateUndefined();
    }
    NativeValue* OnRegisterFormUninstallObserver(NativeEngine &engine, NativeCallbackInfo &info)
    {
        // Check the number of input parameters.
        if (info.argc != ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "2");
            return engine.CreateUndefined();
        }

        // Check the type of the PARAM1.
        if (info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
            HILOG_ERROR("param1 is invalid");
            NapiFormUtil::ThrowParamTypeError(engine, "callback", "Callback<string>");
            return engine.CreateUndefined();
        }
        FormHostClient::GetInstance()->RegisterUninstallCallback(FormUninstallCallback);
        AddFormUninstallCallback(reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(info.argv[1]));
        return engine.CreateUndefined();
    }

    NativeValue* OnRegisterFormObserver(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("called.");

        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("This application is not system-app, can not use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(engine, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return engine.CreateUndefined();
        }

        // Check the type of the PARAM0 and convert it to string.
        if (info.argv[PARAM0]->TypeOf() != NATIVE_STRING) {
            HILOG_ERROR("param0 is invalid");
            NapiFormUtil::ThrowParamTypeError(engine, "type",
                "formAdd, formRemove, formUninstall, notifyVisible or notifyInvisible.");
            return engine.CreateUndefined();
        }

        std::string type;
        if (!ConvertFromJsValue(engine, info.argv[PARAM0], type)) {
            HILOG_ERROR("convert type failed!");
            NapiFormUtil::ThrowParamTypeError(engine, "type",
                "formAdd, formRemove, formUninstall, notifyVisible or notifyInvisible.");
            return engine.CreateUndefined();
        }

        if (type == "formAdd") {
            return OnRegisterFormAddObserver(engine, info);
        } else if (type == "formRemove") {
            return OnRegisterFormRemoveObserver(engine, info);
        } else if (type == "formUninstall") {
            return OnRegisterFormUninstallObserver(engine, info);
        } else if (type == "notifyVisible") {
            return OnRegisteFormIsVisibleObserver(engine, info, true);
        } else if (type == "notifyInvisible") {
            return OnRegisteFormIsVisibleObserver(engine, info, false);
        } else {
            HILOG_ERROR("args[0] should be formAdd, formRemove, formUninstall, notifyVisible or notifyInvisible.");
            NapiFormUtil::ThrowParamTypeError(engine, "type",
                "formAdd, formRemove, formUninstall, notifyVisible or notifyInvisible");
            return engine.CreateUndefined();
        }
    }

    NativeValue* OnRegisteFormIsVisibleObserver(NativeEngine &engine, NativeCallbackInfo &info, bool isVisibility)
    {
        HILOG_DEBUG("called.");
        if (info.argc < ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "2");
            return engine.CreateUndefined();
        }
        if (info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
            HILOG_ERROR("param1 is invalid");
            NapiFormUtil::ThrowParamTypeError(engine, "callback", "Callback<Array<RunningFormInfo>>");
            return engine.CreateUndefined();
        }
        std::string bundleName("all");
        if (info.argc >= ARGS_THREE) {
            HILOG_DEBUG("three or more params");
            if (info.argv[PARAM2]->TypeOf() == NATIVE_UNDEFINED || info.argv[PARAM2]->TypeOf() == NATIVE_NULL) {
                HILOG_DEBUG("param2 type is undefined or null");
            } else if (info.argv[PARAM2]->TypeOf() == NATIVE_STRING) {
                if (!ConvertFromJsValue(engine, info.argv[PARAM2], bundleName)) {
                    HILOG_ERROR("param2 is invalid");
                    NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                    return engine.CreateUndefined();
                }
                if (bundleName.empty()) {
                    HILOG_ERROR("bundleName is empty!");
                    NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                    return engine.CreateUndefined();
                }
            } else {
                HILOG_ERROR("param2 is invalid");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
        }
        if (formObserver_ == nullptr) {
            HILOG_ERROR("formObserver_ is nullptr");
            formObserver_ = JsFormStateObserver::GetInstance();
        }
        FormMgr::GetInstance().RegisterAddObserver(bundleName, formObserver_);
        JsFormStateObserver::GetInstance()->
            RegisterFormInstanceCallback(engine, info.argv[PARAM1], isVisibility, bundleName);
        return engine.CreateUndefined();
    }

    NativeValue* OnUnregisterFormIsVisibleObserver(NativeEngine &engine, NativeCallbackInfo &info, bool isVisibility)
    {
        HILOG_DEBUG("called.");
        if (info.argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2 or 3");
            return engine.CreateUndefined();
        }
        std::string bundleName = "all";
        bool callerflag = false;
        if (info.argc >= ARGS_TWO) {
            if (info.argv[PARAM1]->TypeOf() == NATIVE_FUNCTION) {
                HILOG_DEBUG("param1 is function");
                callerflag = true;
            } else if(info.argv[PARAM1]->TypeOf() == NATIVE_UNDEFINED ||
                info.argv[PARAM1]->TypeOf() == NATIVE_NULL) {
                HILOG_DEBUG("param1 is undefined or null");
            } else if (info.argv[PARAM1]->TypeOf() == NATIVE_STRING) {
                if (!ConvertFromJsValue(engine, info.argv[PARAM1], bundleName)) {
                    HILOG_ERROR("convert bundleName failed!");
                    NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                    return engine.CreateUndefined();
                }
                if (bundleName.empty()) {
                    HILOG_ERROR("bundleName is empty!");
                    NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                    return engine.CreateUndefined();
                }
            } else {
                NapiFormUtil::ThrowParamTypeError(engine, "param 2", "type");
                return engine.CreateUndefined();
            }
        }
        if (info.argc >= ARGS_THREE) {
            if (info.argv[PARAM2]->TypeOf() == NATIVE_UNDEFINED || info.argv[PARAM2]->TypeOf() == NATIVE_NULL) {
                HILOG_DEBUG("param2 is undefined or null");
            } else if (info.argv[PARAM2]->TypeOf() == NATIVE_STRING) {
                if (!ConvertFromJsValue(engine, info.argv[PARAM2], bundleName)) {
                    HILOG_ERROR("convert bundleName failed!");
                    NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                    return engine.CreateUndefined();
                }
                if (bundleName.empty()) {
                    HILOG_ERROR("bundleName is empty!");
                    NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                    return engine.CreateUndefined();
                }
                if(info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
                    HILOG_ERROR("param1 is invalid");
                    NapiFormUtil::ThrowParamTypeError(engine, "callback", "Callback<Array<RunningFormInfo>>");
                    return engine.CreateUndefined();
                }
            } else {
                NapiFormUtil::ThrowParamTypeError(engine, "param 3", "type");
                return engine.CreateUndefined();
            }
        }
        if (callerflag) {
            JsFormStateObserver::GetInstance()->
                DelFormNotifyVisibleCallbackByBundle(bundleName, isVisibility, info.argv[PARAM1]);
            FormMgr::GetInstance().RegisterRemoveObserver(bundleName, formObserver_);
            return engine.CreateUndefined();
        }

        JsFormStateObserver::GetInstance()->ClearFormNotifyVisibleCallbackByBundle(bundleName, isVisibility);
        FormMgr::GetInstance().RegisterRemoveObserver(bundleName, formObserver_);
        return engine.CreateUndefined();
    }

    NativeValue* OnUnregisterFormUninstallObserver(NativeEngine &engine, NativeCallbackInfo &info)
    {
        // Check the number of input parameters.
        if (info.argc > ARGS_TWO|| info.argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            return engine.CreateUndefined();
        }

        // Check the type of the PARAM1.
        if (info.argc == ARGS_TWO && info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
            HILOG_ERROR("param1 is invalid");
            NapiFormUtil::ThrowParamTypeError(engine, "callback", "Callback<string>");
            return engine.CreateUndefined();
        }

        if (info.argc == ARGS_TWO) {
            DelFormUninstallCallback(reinterpret_cast<napi_value>(info.argv[PARAM1]));
            return engine.CreateUndefined();
        }

        ClearFormUninstallCallback();
        return engine.CreateUndefined();
    }

    NativeValue* OnUnregisterFormRemoveObserver(NativeEngine &engine, NativeCallbackInfo &info)
    {
        // Check the number of input parameters.
        if (info.argc > ARGS_THREE|| info.argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2 or 3");
            return engine.CreateUndefined();
        }

        // If there is only one argument, all listening will be cancelled.
        if (info.argc == ARGS_ONE) {
            JsFormStateObserver::GetInstance()->ClearFormRemoveCallbackByBundle("all");
            return engine.CreateUndefined();
        }

        if (info.argc == ARGS_TWO) {
            if (info.argv[PARAM1]->TypeOf() == NATIVE_FUNCTION) {
                JsFormStateObserver::GetInstance()->DelFormRemoveCallbackByBundle(
                    reinterpret_cast<napi_value>(info.argv[PARAM1]), "all");
                return engine.CreateUndefined();
            } else if (info.argv[PARAM1]->TypeOf() == NATIVE_STRING) {
                std::string bundleName;
                if (!ConvertFromJsValue(engine, info.argv[PARAM1], bundleName)) {
                    HILOG_ERROR("convert bundleName failed!");
                    NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                    return engine.CreateUndefined();
                }
                JsFormStateObserver::GetInstance()->ClearFormRemoveCallbackByBundle(bundleName);
                return engine.CreateUndefined();
            } else {
                HILOG_ERROR("param1 is invalid");
                NapiFormUtil::ThrowParamTypeError(engine, "callback or bundleName",
                    "Callback<formInfo.RunningFormInfo> or string");
                return engine.CreateUndefined();
            }
        }

        if (info.argc == ARGS_THREE) {
            if (info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
                HILOG_ERROR("param1 is invalid");
                NapiFormUtil::ThrowParamTypeError(engine, "callback", "Callback<formInfo.RunningFormInfo>");
                return engine.CreateUndefined();
            }
            if (info.argv[PARAM2]->TypeOf() != NATIVE_STRING) {
                HILOG_ERROR("param2 is invalid");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
            std::string bundleName;
            if (!ConvertFromJsValue(engine, info.argv[PARAM2], bundleName)) {
                HILOG_ERROR("convert bundleName failed!");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
            JsFormStateObserver::GetInstance()->DelFormRemoveCallbackByBundle(
                reinterpret_cast<napi_value>(info.argv[PARAM1]), bundleName);
            return engine.CreateUndefined();
        }
        return engine.CreateUndefined();
    }

    NativeValue* OnUnregisterFormAddObserver(NativeEngine &engine, NativeCallbackInfo &info)
    {
        // Check the number of input parameters.
        if (info.argc > ARGS_THREE|| info.argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2 or 3");
            return engine.CreateUndefined();
        }

        // If there is only one argument, full listening will be cancelled.
        if (info.argc == ARGS_ONE) {
            JsFormStateObserver::GetInstance()->ClearFormAddCallbackByBundle("all");
            return engine.CreateUndefined();
        }

        if (info.argc == ARGS_TWO) {
            if (info.argv[PARAM1]->TypeOf() == NATIVE_FUNCTION) {
                JsFormStateObserver::GetInstance()->DelFormAddCallbackByBundle(
                    reinterpret_cast<napi_value>(info.argv[PARAM1]), "all");
                return engine.CreateUndefined();
            } else if (info.argv[PARAM1]->TypeOf() == NATIVE_STRING) {
                std::string bundleName;
                if (!ConvertFromJsValue(engine, info.argv[PARAM1], bundleName)) {
                    HILOG_ERROR("convert bundleName failed!");
                    NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                    return engine.CreateUndefined();
                }
                JsFormStateObserver::GetInstance()->ClearFormAddCallbackByBundle(bundleName);
                return engine.CreateUndefined();
            } else {
                HILOG_ERROR("param1 is invalid");
                NapiFormUtil::ThrowParamTypeError(engine, "callback or bundleName",
                    "Callback<formInfo.RunningFormInfo> or string");
                return engine.CreateUndefined();
            }
        }

        if (info.argc == ARGS_THREE) {
            if (info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
                HILOG_ERROR("param1 is invalid");
                NapiFormUtil::ThrowParamTypeError(engine, "callback", "Callback<formInfo.RunningFormInfo>");
                return engine.CreateUndefined();
            }
            if (info.argv[PARAM2]->TypeOf() != NATIVE_STRING) {
                HILOG_ERROR("param2 is invalid");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
            std::string bundleName;
            if (!ConvertFromJsValue(engine, info.argv[PARAM2], bundleName)) {
                HILOG_ERROR("convert bundleName failed!");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
            JsFormStateObserver::GetInstance()->DelFormAddCallbackByBundle(
                reinterpret_cast<napi_value>(info.argv[PARAM1]), bundleName);
            return engine.CreateUndefined();
        }
        return engine.CreateUndefined();
    }

    NativeValue* OnUnregisterFormObserver(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("called.");

        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("This application is not system-app, can not use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(engine, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return engine.CreateUndefined();
        }

        // Check the type of the PARAM0 and convert it to string.
        if (info.argv[PARAM0]->TypeOf() != NATIVE_STRING) {
            HILOG_ERROR("param0 is invalid");
            NapiFormUtil::ThrowParamTypeError(engine, "type",
                "formAdd, formRemove, formUninstall, notifyVisible or invisibility.");
            return engine.CreateUndefined();
        }
        std::string type;
        if (!ConvertFromJsValue(engine, info.argv[PARAM0], type)) {
            HILOG_ERROR("convert type failed!");
            NapiFormUtil::ThrowParamTypeError(engine, "type",
                "formAdd, formRemove, formUninstall, notifyVisible or notifyInvisible.");
            return engine.CreateUndefined();
        }

        if (type == "formAdd") {
            return OnUnregisterFormAddObserver(engine, info);
        } else if (type == "formRemove") {
            return OnUnregisterFormRemoveObserver(engine, info);
        } else if (type == "notifyVisible") {
            return OnUnregisterFormIsVisibleObserver(engine, info, true);
        } else if (type == "notifyInvisible") {
            return OnUnregisterFormIsVisibleObserver(engine, info, false);
        } else if (type == "formUninstall") {
            return OnUnregisterFormUninstallObserver(engine, info);
        } else {
            HILOG_ERROR("args[0] should be formAdd, formRemove, formUninstall, visibility or notifyInvisible.");
            NapiFormUtil::ThrowParamTypeError(engine,
                "type", "formAdd, formRemove, formUninstall, visibility or notifyInvisible");
            return engine.CreateUndefined();
        }
    }

    NativeValue* OnNotifyFormsVisible(NativeEngine &engine, const NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (info.argc > ARGS_THREE|| info.argc < ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "2 or 3");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(engine, info.argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formIds", "Array<string>");
            return engine.CreateUndefined();
        }
        convertArgc++;

        bool isVisible = false;
        if (info.argv[PARAM1]->TypeOf() != NATIVE_BOOLEAN) {
            HILOG_ERROR("promise second param type is illegal");
            NapiFormUtil::ThrowParamTypeError(engine, "isVisible", "boolean");
            return engine.CreateUndefined();
        }
        if (!ConvertFromJsValue(engine, info.argv[PARAM1], isVisible)) {
            HILOG_ERROR("convert isVisible failed!");
            NapiFormUtil::ThrowParamTypeError(engine, "isVisible", "boolean");
            return engine.CreateUndefined();
        }
        convertArgc++;

        auto complete = [formIds, isVisible](NativeEngine &engine, AsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().NotifyFormsVisible(formIds, isVisible,
                FormHostClient::GetInstance());
            if (ret == ERR_OK) {
                task.ResolveWithNoError(engine, engine.CreateUndefined());
            } else {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            }
        };

        NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnNotifyFormsVisible",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnNotifyFormsEnableUpdate(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);

        if (info.argc > ARGS_THREE|| info.argc < ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "2 or 3");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(engine, info.argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formIds", "Array<string>");
            return engine.CreateUndefined();
        }
        convertArgc++;

        bool isEnableUpdate = false;
        if (info.argv[PARAM1]->TypeOf() != NATIVE_BOOLEAN) {
            HILOG_ERROR("promise second param type is illegal");
            NapiFormUtil::ThrowParamTypeError(engine, "isEnableUpdate", "boolean");
            return engine.CreateUndefined();
        }
        if (!ConvertFromJsValue(engine, info.argv[PARAM1], isEnableUpdate)) {
            HILOG_ERROR("convert isEnableUpdate failed!");
            NapiFormUtil::ThrowParamTypeError(engine, "isEnableUpdate", "boolean");
            return engine.CreateUndefined();
        }
        convertArgc++;

        auto complete = [formIds, isEnableUpdate](NativeEngine &engine, AsyncTask &task, int32_t status) {
            auto ret = FormMgr::GetInstance().NotifyFormsEnableUpdate(formIds, isEnableUpdate,
                FormHostClient::GetInstance());
            if (ret == ERR_OK) {
                task.ResolveWithNoError(engine, engine.CreateUndefined());
            } else {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            }
        };

        NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnNotifyFormsVisible",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnGetAllFormsInfo(NativeEngine &engine, const NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);
        if (info.argc > ARGS_ONE || info.argc < ARGS_ZERO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "0 or 1");
            return engine.CreateUndefined();
        }

        auto complete = [](NativeEngine &engine, AsyncTask &task, int32_t status) {
            std::vector<FormInfo> formInfos;
            auto ret = FormMgr::GetInstance().GetAllFormsInfo(formInfos);
            if (ret != ERR_OK) {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
                return;
            }
            task.ResolveWithNoError(engine, CreateFormInfos(engine, formInfos));
        };

        auto callback = (info.argc == ARGS_ZERO) ? nullptr : info.argv[PARAM0];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("JsFormHost::OnGetAllFormsInfo",
            engine, CreateAsyncTaskWithLastParam(engine, callback, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnGetFormsInfo(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);
        if (info.argc > ARGS_THREE || info.argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2 or 3");
            return engine.CreateUndefined();
        }

        if (info.argv[PARAM0] && info.argv[PARAM0]->TypeOf() != NATIVE_STRING) {
            HILOG_ERROR("input params is not string.");
            NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        std::string bName("");
        if (!ConvertFromJsValue(engine, info.argv[PARAM0], bName)) {
            HILOG_ERROR("bundle name convert failed.");
            NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
            return engine.CreateUndefined();
        }
        convertArgc++;

        std::string mName("");
        if ((info.argc == ARGS_TWO || info.argc == ARGS_THREE) && info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
            if (info.argv[PARAM1]->TypeOf() != NATIVE_STRING) {
                HILOG_ERROR("input params is not string");
                NapiFormUtil::ThrowParamTypeError(engine, "moduleName", "string");
                return engine.CreateUndefined();
            }

            if (!ConvertFromJsValue(engine, info.argv[PARAM1], mName)) {
                HILOG_ERROR("module name convert failed.");
                NapiFormUtil::ThrowParamTypeError(engine, "moduleName", "string");
                return engine.CreateUndefined();
            }
            convertArgc++;
        }

        auto complete = [bName, mName, convertArgc](NativeEngine &engine, AsyncTask &task, int32_t status) {
            std::string bundleName(bName);
            std::string moduleName(mName);
            std::vector<FormInfo> formInfos;
            int ret = ERR_OK;
            if (convertArgc == ARGS_ONE) {
                ret = FormMgr::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
            } else {
                ret = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
            }

            if (ret != ERR_OK) {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
                return;
            }
            task.ResolveWithNoError(engine, CreateFormInfos(engine, formInfos));
        };

        NativeValue *result = nullptr;
        NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        AsyncTask::Schedule("JsFormHost::OnGetFormsInfo",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnGetRunningFormInfos(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("called");
        if (info.argc > ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "0 or 1 or 2");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        std::string bundleName("");
        if ((info.argc == ARGS_ONE) && (info.argv[PARAM0]->TypeOf() != NATIVE_FUNCTION)) {
            if (info.argv[PARAM0]->TypeOf() != NATIVE_STRING) {
                HILOG_ERROR("input params is not a string");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
            if (!ConvertFromJsValue(engine, info.argv[PARAM0], bundleName)) {
                HILOG_ERROR("bundleName convert failed.");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
            convertArgc++;
        }

        if (info.argc == ARGS_TWO) {
            if (info.argv[PARAM1]->TypeOf() != NATIVE_STRING) {
                HILOG_ERROR("input params is not a string");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
            if (!ConvertFromJsValue(engine, info.argv[PARAM1], bundleName)) {
                HILOG_ERROR("bundleName convert failed.");
                NapiFormUtil::ThrowParamTypeError(engine, "bundleName", "string");
                return engine.CreateUndefined();
            }
            convertArgc++;
        }

        auto complete = [bundleName, convertArgc](NativeEngine &engine, AsyncTask &task, int32_t status) {
            std::string hostBundleName(bundleName);
            std::vector<RunningFormInfo> runningFormInfos;
            int32_t ret = ERR_OK;
            if (convertArgc == ARGS_ZERO) {
                ret = FormMgr::GetInstance().GetRunningFormInfos(runningFormInfos);
            } else {
                ret = FormMgr::GetInstance().GetRunningFormInfosByBundleName(hostBundleName, runningFormInfos);
            }
            if (ret != ERR_OK) {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
                return;
            }
            task.ResolveWithNoError(engine, CreateRunningFormInfos(engine, runningFormInfos));
        };
        NativeValue *result = nullptr;
        NativeValue *lastParam = nullptr;
        if (info.argc == ARGS_TWO) {
            lastParam = info.argv[ARGS_ZERO];
        } else {
            lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        }
        AsyncTask::Schedule("JsFormHost::OnGetRunningFormInfos",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    void InnerShareForm(NativeEngine &engine, const std::shared_ptr<AbilityRuntime::AsyncTask> &asyncTask,
        ShareFormCallBackClient::ShareFormTask &&task, int64_t formId, const std::string &remoteDeviceId)
    {
        auto shareFormCallback = std::make_shared<ShareFormCallBackClient>(std::move(task));
        int64_t requestCode = SystemTimeMillis();
        FormHostClient::GetInstance()->AddShareFormCallback(shareFormCallback, requestCode);

        ErrCode ret = FormMgr::GetInstance().ShareForm(
            formId, remoteDeviceId, FormHostClient::GetInstance(), requestCode);
        if (ret != ERR_OK) {
            HILOG_INFO("%{public}s, share form failed.", __func__);
            asyncTask->Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            FormHostClient::GetInstance()->RemoveShareFormCallback(requestCode);
        }
    }

    void InnerAcquireFormData(NativeEngine &engine, const std::shared_ptr<AbilityRuntime::AsyncTask> &asyncTask,
       JsFormDataCallbackClient::AcquireFormDataTask &&task, int64_t formId)
    {
        auto formDataCallbackClient = std::make_shared<JsFormDataCallbackClient>(std::move(task));
        int64_t requestCode = SystemTimeMillis();
        FormHostClient::GetInstance()->AddAcqiureFormDataCallback(formDataCallbackClient, requestCode);

        AAFwk::WantParams formData;
        auto ret = FormMgr::GetInstance().AcquireFormData(formId, requestCode, FormHostClient::GetInstance(), formData);
        if (ret != ERR_OK) {
            HILOG_ERROR("acquire form failed.");
            asyncTask->Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            FormHostClient::GetInstance()->RemoveAcquireDataCallback(requestCode);
        }
    }

    NativeValue* OnShareForm(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("%{public}s is called", __FUNCTION__);
        if (info.argc > ARGS_THREE || info.argc < ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2 or 3");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        HILOG_DEBUG("info.argv[PARAM0]->TypeOf() %{public}d", info.argv[PARAM0]->TypeOf());
        int64_t formId = 0;
        if (!ConvertFromId(engine, info.argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formId", "string");
            return engine.CreateUndefined();
        }
        convertArgc++;

        std::string devicedId;
        if (!ConvertDeviceId(engine, info.argv[PARAM1], devicedId)) {
            HILOG_ERROR("deviced id is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "devicedId", "string");
            return engine.CreateUndefined();
        }
        convertArgc++;

        NativeValue *lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue *result = nullptr;

        std::unique_ptr<AbilityRuntime::AsyncTask> uasyncTask =
            AbilityRuntime::CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, nullptr, &result);
        std::shared_ptr<AbilityRuntime::AsyncTask> asyncTask = std::move(uasyncTask);

        ShareFormCallBackClient::ShareFormTask task = [&engine, asyncTask](int32_t code) {
            HILOG_DEBUG("task complete code: %{public}d", code);
            if (code == ERR_OK) {
                asyncTask->ResolveWithNoError(engine, engine.CreateUndefined());
            } else {
                asyncTask->Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, code));
            }
        };

        InnerShareForm(engine, asyncTask, std::move(task), formId, devicedId);

        return result;
    }

    NativeValue* OnAcquireFormData(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("OnAcquireFormData is called");
        if (info.argc > ARGS_TWO || info.argc < ARGS_ONE) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            return engine.CreateUndefined();
        }
        
        // The promise form has only one parameters
        decltype(info.argc) unwrapArgc = 1;
        int64_t formId = 0;
        if (!ConvertFromId(engine, info.argv[PARAM0], formId)) {
            HILOG_ERROR("form id is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formId", "string");
            return engine.CreateUndefined();
        }

        NativeValue *lastParam = (info.argc <= unwrapArgc) ? nullptr : info.argv[unwrapArgc];
        NativeValue *result = nullptr;

        std::unique_ptr<AbilityRuntime::AsyncTask> uasyncTask =
            AbilityRuntime::CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, nullptr, &result);
        std::shared_ptr<AbilityRuntime::AsyncTask> asyncTask = std::move(uasyncTask);

        JsFormDataCallbackClient::AcquireFormDataTask task = [&engine, asyncTask](AAFwk::WantParams data) {
            HILOG_DEBUG("task complete form data");
            NativeValue *objValue = engine.CreateObject();
            NativeObject *object = ConvertNativeValueTo<NativeObject>(objValue);
            object->SetProperty("formData", CreateJsWantParams(engine, data));
            asyncTask->ResolveWithNoError(engine, objValue);
        };

        InnerAcquireFormData(engine, asyncTask, std::move(task), formId);
        return result;
    }

    NativeValue* OnNotifyFormsPrivacyProtected(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_INFO("%{public}s is called", __func__);
        if (info.argc > ARGS_THREE || info.argc < ARGS_TWO) {
            HILOG_ERROR("wrong number of arguments.");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "2 or 3");
            return engine.CreateUndefined();
        }

        decltype(info.argc) convertArgc = 0;
        std::vector<int64_t> formIds;
        if (!ConvertFromIds(engine, info.argv[PARAM0], formIds)) {
            HILOG_ERROR("form id list is invalid.");
            NapiFormUtil::ThrowParamTypeError(engine, "formIds", "Array<string>");
            return engine.CreateUndefined();
        }
        convertArgc++;

        bool isProtected = false;
        if (info.argv[PARAM1]->TypeOf() != NATIVE_BOOLEAN) {
            HILOG_ERROR("promise second param type is illegal");
            NapiFormUtil::ThrowParamTypeError(engine, "isProtected", "boolean");
            return engine.CreateUndefined();
        }
        if (!ConvertFromJsValue(engine, info.argv[PARAM1], isProtected)) {
            HILOG_ERROR("convert isProtected failed!");
            NapiFormUtil::ThrowParamTypeError(engine, "isProtected", "boolean");
            return engine.CreateUndefined();
        }
        convertArgc++;

        AsyncTask::CompleteCallback complete =
            [formIds, isProtected](NativeEngine &engine, AsyncTask &task, int32_t status) {
                auto ret = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds,
                    isProtected, FormHostClient::GetInstance());
                if (ret == ERR_OK) {
                    task.ResolveWithNoError(engine, engine.CreateUndefined());
                } else {
                    task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
                }
            };

        NativeValue *lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("NapiFormHost::OnNotifyFormsPrivacyProtected",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnGetFormInstancesByFilter(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("is called");
        std::vector<int64_t> iFormIds;
        if (info.argc < ARGS_ONE || info.argc > ARGS_THREE) {
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            HILOG_ERROR("wrong number of arguments!");
            return engine.CreateUndefined();
        }

        FormInstancesFilter filter;
        if (info.argv[PARAM0]->TypeOf() != NATIVE_OBJECT) {
            HILOG_ERROR("input params is not object!");
            NapiFormUtil::ThrowParamTypeError(engine, "formProviderFilter", "object");
            return engine.CreateUndefined();
        }
        auto arg = reinterpret_cast<napi_value>(info.argv[PARAM0]);
        auto env = reinterpret_cast<napi_env>(&engine);
        if (!ParseParam(env, arg, filter)) {
            HILOG_ERROR("input params parse failed!");
            NapiFormUtil::ThrowParamTypeError(engine, "formProviderFilter", "object");
            return engine.CreateUndefined();
        }
        if (info.argc == ARGS_TWO && info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
            HILOG_ERROR("param1 is invalid");
            NapiFormUtil::ThrowParamTypeError(engine, "callback", "Callback<string>");
            return engine.CreateUndefined();
        }
        std::shared_ptr<std::vector<FormInstance>> formInstances = std::make_shared<std::vector<FormInstance>>();
        auto apiResult = std::make_shared<int32_t>();
        auto execute = [filter, formInstances, ret = apiResult]() {
            *ret = FormMgr::GetInstance().GetFormInstancesByFilter(filter, *formInstances);
        };

        auto complete =
            [formInstances, ret = apiResult](NativeEngine &engine, AsyncTask &task, int32_t status) {
                if (*ret != ERR_OK) {
                    HILOG_ERROR("failed");
                    task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, *ret));
                } else {
                    task.ResolveWithNoError(engine, CreateFormInstances(engine, *formInstances));
                }
            };
        NativeValue *lastParam = (info.argc == ARGS_ONE) ? nullptr : info.argv[PARAM1];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("NapiFormHost::OnGetFormInstancesByFilter",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    NativeValue* OnGetFormInstanceById(NativeEngine &engine, NativeCallbackInfo &info)
    {
        HILOG_DEBUG("called");
        std::vector<int64_t> iFormIds;
        if (info.argc < ARGS_ONE || info.argc > ARGS_THREE) {
            HILOG_ERROR("wrong number of arguments!");
            NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1 or 2");
            return engine.CreateUndefined();
        }

        int64_t formId;
        if (!ConvertFromId(engine, info.argv[PARAM0], formId)) {
            HILOG_ERROR("convert strFormIdList failed!");
            NapiFormUtil::ThrowParamTypeError(engine, "formId", "string");
            return engine.CreateUndefined();
        }
        if (info.argc == ARGS_TWO && info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
            HILOG_ERROR("param1 is invalid");
            NapiFormUtil::ThrowParamTypeError(engine, "callback", "Callback<string>");
            return engine.CreateUndefined();
        }
        std::shared_ptr<FormInstance> formInstance = std::make_shared<FormInstance>();
        auto apiResult = std::make_shared<int32_t>();
        auto execute = [formId, formInstance, ret = apiResult]() {
            *ret = FormMgr::GetInstance().GetFormInstanceById(formId, *formInstance);
        };

        auto complete =
            [formInstance, ret = apiResult](NativeEngine &engine, AsyncTask &task, int32_t status) {
                if (*ret != ERR_OK) {
                    HILOG_ERROR("failed");
                    task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, *ret));
                } else {
                    task.ResolveWithNoError(engine, CreateFormInstance(engine, *formInstance));
                }
            };
        NativeValue *lastParam = (info.argc == ARGS_ONE) ? nullptr : info.argv[PARAM1];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("NapiFormHost::OnGetFormInstanceById",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }
    sptr<JsFormStateObserver> formObserver_ = nullptr;
};

NativeValue* JsFormHostInit(NativeEngine* engine, NativeValue* exportObj)
{
    HILOG_INFO("JsFormHostInit is called");
    if (engine == nullptr || exportObj == nullptr) {
        HILOG_INFO("Invalid input parameters");
        return nullptr;
    }

    NativeObject* object = ConvertNativeValueTo<NativeObject>(exportObj);
    if (object == nullptr) {
        HILOG_INFO("object is nullptr");
        return nullptr;
    }

    std::unique_ptr<JsFormHost> jsFormHost = std::make_unique<JsFormHost>();
    object->SetNativePointer(jsFormHost.release(), JsFormHost::Finalizer, nullptr);

    const char *moduleName = "JsFormHost";
    BindNativeFunction(*engine, *object, "deleteForm", moduleName, JsFormHost::DeleteForm);
    BindNativeFunction(*engine, *object, "releaseForm", moduleName, JsFormHost::ReleaseForm);
    BindNativeFunction(*engine, *object, "requestForm", moduleName, JsFormHost::RequestForm);
    BindNativeFunction(*engine, *object, "castTempForm", moduleName, JsFormHost::CastTempForm);
    BindNativeFunction(*engine, *object, "castToNormalForm", moduleName, JsFormHost::CastTempForm);
    BindNativeFunction(*engine, *object, "notifyVisibleForms", moduleName, JsFormHost::NotifyVisibleForms);
    BindNativeFunction(*engine, *object, "notifyInvisibleForms", moduleName, JsFormHost::NotifyInvisibleForms);
    BindNativeFunction(*engine, *object, "enableFormsUpdate", moduleName, JsFormHost::EnableFormsUpdate);
    BindNativeFunction(*engine, *object, "disableFormsUpdate", moduleName, JsFormHost::DisableFormsUpdate);
    BindNativeFunction(*engine, *object, "isSystemReady", moduleName, JsFormHost::IsSystemReady);
    BindNativeFunction(*engine, *object, "deleteInvalidForms", moduleName, JsFormHost::DeleteInvalidForms);
    BindNativeFunction(*engine, *object, "acquireFormState", moduleName, JsFormHost::AcquireFormState);
    BindNativeFunction(*engine, *object, "on", moduleName, JsFormHost::RegisterFormObserver);
    BindNativeFunction(*engine, *object, "off", moduleName, JsFormHost::UnregisterFormObserver);
    BindNativeFunction(*engine, *object, "notifyFormsVisible", moduleName, JsFormHost::NotifyFormsVisible);
    BindNativeFunction(*engine, *object, "notifyFormsEnableUpdate", moduleName, JsFormHost::NotifyFormsEnableUpdate);
    BindNativeFunction(*engine, *object, "getAllFormsInfo", moduleName, JsFormHost::GetAllFormsInfo);
    BindNativeFunction(*engine, *object, "getFormsInfo", moduleName, JsFormHost::GetFormsInfo);
    BindNativeFunction(*engine, *object, "shareForm", moduleName, JsFormHost::ShareForm);
    BindNativeFunction(*engine, *object, "notifyFormsPrivacyProtected", moduleName,
        JsFormHost::NotifyFormsPrivacyProtected);
    BindNativeFunction(*engine, *object, "getRunningFormInfos", moduleName, JsFormHost::GetRunningFormInfos);
    BindNativeFunction(*engine, *object, "acquireFormData", moduleName, JsFormHost::AcquireFormData);
    BindNativeFunction(*engine, *object, "getRunningFormInfosByFilter", moduleName,
        JsFormHost::GetFormInstancesByFilter);
    BindNativeFunction(*engine, *object, "getRunningFormInfoById", moduleName, JsFormHost::GetFormInstanceById);
    return engine->CreateUndefined();
}
} // namespace AbilityRuntime
} // namespace OHOS