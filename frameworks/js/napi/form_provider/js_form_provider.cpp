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

#include "js_form_provider.h"

#include <cinttypes>
#include <vector>

#include "fms_log_wrapper.h"
#include "form_constants.h"
#ifdef NO_RUNTIME_EMULATOR
#include "form_event_hiappevent.h"
#endif
#include "form_instance.h"
#include "form_mgr_errors.h"
#include "form_mgr.h"
#include "running_form_info.h"
#include "js_runtime_utils.h"
#include "ipc_skeleton.h"
#include "napi_base_context.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_form_util.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "runtime.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
namespace {
constexpr size_t ARGS_SIZE_ZERO = 0;
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;
constexpr size_t ARGS_SIZE_FOUR = 4;
const std::string IS_FORM_AGENT = "isFormAgent";
enum class ActivationState : int32_t {
    Deactivated = 0,
    Activated = 1
};

bool CheckParamNum(napi_env env, size_t argc, size_t minParamNum, size_t maxParamNum)
{
    HILOG_DEBUG("argc is %{public}zu,param range is [%{public}zu,%{public}zu]",
        argc, minParamNum, maxParamNum);
    if (argc > maxParamNum || argc < minParamNum) {
        HILOG_ERROR("invalid param number %{public}zu", argc);
        std::string errMsg = "[" + std::to_string(minParamNum) + ", " + std::to_string(maxParamNum) + "]";
        NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), errMsg);
        return false;
    }
    return true;
}

static bool ConvertFormInfoFilterThrow(napi_env env, napi_value jsValue, AppExecFwk::FormInfoFilter &formInfoFilter)
{
    napi_valuetype jsValueType = napi_undefined;
    napi_typeof(env, jsValue, &jsValueType);
    if (jsValueType != napi_object) {
        HILOG_ERROR("an object is expected, but an argument of different type is passed in");
        NapiFormUtil::ThrowParamTypeError(env, "filter", "formInfo.FormInfoFilter");
        return false;
    }

    napi_value nativeDataValue = nullptr;
    napi_status ret = napi_get_named_property(env, jsValue, "moduleName", &nativeDataValue);
    if (ret != napi_ok) {
        HILOG_ERROR("get property failed");
        NapiFormUtil::ThrowParamError(env, "Failed to get property.");
        return false;
    }
    napi_valuetype nativeDataValueType = napi_undefined;
    napi_typeof(env, nativeDataValue, &nativeDataValueType);
    if (nativeDataValue == nullptr || (nativeDataValueType != napi_undefined &&
        !ConvertFromJsValue(env, nativeDataValue, formInfoFilter.moduleName))) {
        HILOG_ERROR("convert nativeDataValue failed");
        NapiFormUtil::ThrowParamError(env, "Failed to convert FormInfoFilter.");
        return false;
    }

    HILOG_INFO("module:%{public}s", formInfoFilter.moduleName.c_str());

    return true;
}

static bool ConvertFormId(napi_env env, napi_value jsValue, int64_t &formId)
{
    std::string strFormId;
    if (!ConvertFromJsValue(env, jsValue, strFormId)) {
        HILOG_ERROR("convert strFormId failed");
        return false;
    }

    if (strFormId.empty()) {
        HILOG_ERROR("empty strFormId");
    }

    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("convert string formId to int64 failed");
        return false;
    }
    return true;
}

bool CheckUIAbilityContext(napi_env env, napi_value jsContextValue)
{
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, jsContextValue, stageMode);
    if (status != napi_ok || !stageMode) {
        NapiFormUtil::ThrowParamError(env, "Parse param context failed, must be a context of stageMode.");
        return false;
    }

    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, jsContextValue);
    if (context == nullptr) {
        NapiFormUtil::ThrowParamError(env, "Parse param context failed, must not be nullptr.");
        return false;
    }
    
    auto abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
    if (abilityContext == nullptr) {
        NapiFormUtil::ThrowParamError(env, "The context is not ability context.");
        return false;
    }
    return true;
}
}

static std::string GetStringByProp(napi_env env, napi_value value, const std::string &prop)
{
    HILOG_DEBUG("GetStringByProp start");
    std::string result;
    bool propExist = false;
    napi_value propValue = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_has_named_property(env, value, prop.c_str(), &propExist);
    if (!propExist) {
        HILOG_ERROR("prop[%{public}s] absent", prop.c_str());
        return result;
    }
    napi_get_named_property(env, value, prop.c_str(), &propValue);
    if (propValue == nullptr) {
        HILOG_ERROR("prop[%{public}s] get error", prop.c_str());
        return result;
    }
    napi_typeof(env, propValue, &valueType);
    if (valueType != napi_string) {
        HILOG_ERROR("prop[%{public}s] not string", prop.c_str());
        return result;
    }
    size_t size = 0;
    if (napi_get_value_string_utf8(env, propValue, nullptr, 0, &size) != napi_ok) {
        HILOG_ERROR("prop[%{public}s] get size error", prop.c_str());
        return result;
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, propValue, result.data(), (size + 1), &size) != napi_ok) {
        HILOG_ERROR("prop[%{public}s] get value error", prop.c_str());
        return "";
    }
    return result;
}

void JsFormProvider::Finalizer(napi_env env, void *data, void *hint)
{
    HILOG_INFO("call");
    std::unique_ptr<JsFormProvider>(static_cast<JsFormProvider *>(data));
}

napi_value JsFormProvider::GetFormsInfo(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnGetFormsInfo);
}

bool JsFormProvider::OnGetFormsInfoParseParam(NapiParamPackage &napiParam,
    size_t &convertArgc, bool &isPromise, AppExecFwk::FormInfoFilter &formInfoFilter)
{
    napi_env env = napiParam.env;
    size_t argc  = napiParam.argc;
    napi_value* argv = napiParam.argv;
    // GetformsInfo()
    if (argc == ARGS_SIZE_ZERO) {
        isPromise = true;
    }
    if (argc == ARGS_SIZE_ONE) {
        napi_valuetype argvZeroType = napi_undefined;
        napi_typeof(env, argv[PARAM0], &argvZeroType);
        if (argvZeroType != napi_undefined) {
            // GetformsInfo(*)
            if (argvZeroType == napi_function) {
                // GetformsInfo(callback)
                isPromise = false;
            } else {
                // GetformsInfo(*);GetformsInfo(fliter)
                if (ConvertFormInfoFilterThrow(env, argv[PARAM0], formInfoFilter)) {
                    convertArgc++;
                    isPromise = true;
                } else {
                    // no default value
                    return false;
                }
            }
        } else {
            isPromise = true;
        }
    }

    if (argc >= ARGS_SIZE_TWO) {
        napi_valuetype argvType = napi_undefined;
        napi_typeof(env, argv[PARAM0], &argvType);
        if (argvType != napi_undefined) {
            if (argvType == napi_function) {
                // GetformsInfo(callback, *)
                isPromise = false;
            } else {
                // GetformsInfo(fliter, *) || GetformsInfo(fliter, callback)
                if (ConvertFormInfoFilterThrow(env, argv[PARAM0], formInfoFilter)) {
                    convertArgc++;
                    // GetformsInfo(fliter, callback)
                    napi_valuetype paramTwoType = napi_undefined;
                    napi_typeof(env, argv[PARAM1], &paramTwoType);
                    isPromise = paramTwoType != napi_function;
                } else {
                    HILOG_ERROR("convert form info filter failed");
                    return false;
                }
            }
        } else {
            isPromise = true;
        }
    }
    return true;
}

napi_value JsFormProvider::OnGetFormsInfo(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");

    size_t convertArgc = 0;
    bool isPromise = false;
    FormInfoFilter formInfoFilter;

    NapiParamPackage napiParam(env, argc, argv);

    if (!OnGetFormsInfoParseParam(napiParam, convertArgc, isPromise, formInfoFilter)) {
        HILOG_ERROR("parse param failed");
        return CreateJsUndefined(env);
    }

    NapiAsyncTask::CompleteCallback complete =
        [formInfoFilter](napi_env env, NapiAsyncTask &task, int32_t status) {
            std::vector<FormInfo> formInfos;
            auto ret = FormMgr::GetInstance().GetFormsInfo(formInfoFilter, formInfos);
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            task.ResolveWithNoError(env, CreateFormInfos(env, formInfos));
        };

    napi_value lastParam = isPromise ? nullptr : argv[convertArgc];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnGetFormsInfo",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::GetPublishedFormInfoById(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnGetPublishedFormInfoById);
}

napi_value JsFormProvider::OnGetPublishedFormInfoById(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");
    if (CheckParamNum(env, argc, ARGS_SIZE_ONE, ARGS_SIZE_TWO) == false) {
        return CreateJsUndefined(env);
    }
    napi_valuetype paramZeroType = napi_undefined;
    napi_typeof(env, argv[PARAM0], &paramZeroType);
    if (paramZeroType != napi_string) {
        NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
        return CreateJsUndefined(env);
    }
    int64_t formId = 0;
    std::string strFormId;
    if (!ConvertFromJsValue(env, argv[PARAM0], strFormId)) {
        HILOG_ERROR("ConvertFromJsValue failed");
        NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
        return CreateJsUndefined(env);
    }
    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("convert form string failed");
        NapiFormUtil::ThrowParamError(env, "Failed to convert formId.");
        return CreateJsUndefined(env);
    }

    HILOG_INFO("before GetPublishedFormInfoById, formId:%{public}" PRId64, formId);
    NapiAsyncTask::CompleteCallback complete =
        [formId](napi_env env, NapiAsyncTask &task, int32_t status) {
            RunningFormInfo formInfo;
            auto ret = FormMgr::GetInstance().GetPublishedFormInfoById(formId, formInfo);
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            task.ResolveWithNoError(env, CreateRunningFormInfo(env, formInfo));
        };

    napi_value lastParam = (argc == ARGS_SIZE_TWO) ? argv[PARAM1] : nullptr;
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnGetPublishedFormInfoById",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::GetPublishedFormInfos(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnGetPublishedFormInfos);
}

napi_value JsFormProvider::OnGetPublishedFormInfos(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");

    NapiAsyncTask::CompleteCallback complete =
        [](napi_env env, NapiAsyncTask &task, int32_t status) {
            std::vector<RunningFormInfo> formInfos;
            auto ret = FormMgr::GetInstance().GetPublishedFormInfos(formInfos);
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            task.ResolveWithNoError(env, CreateRunningFormInfos(env, formInfos));
        };

    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnGetPublishedFormInfos",
        env, CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
    return result;
}
napi_value JsFormProvider::OpenFormManager(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnOpenFormManager);
}

napi_value JsFormProvider::OnOpenFormManager(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");
    Want want;
    if (!AppExecFwk::UnwrapWant(env, argv[PARAM0], want)) {
        HILOG_ERROR("fail convert want");
        NapiFormUtil::ThrowParamError(env, "Failed to convert want.");
        return CreateJsUndefined(env);
    }

    const std::string bundleName = want.GetBundle();
    const std::string abilityName = want.GetElement().GetAbilityName();
    want.SetElementName(bundleName, abilityName);
    want.SetAction(AppExecFwk::Constants::FORM_PAGE_ACTION);
    want.SetParam(AppExecFwk::Constants::PARAM_PAGE_ROUTER_SERVICE_CODE,
                  AppExecFwk::Constants::PAGE_ROUTER_SERVICE_CODE_FORM_MANAGE);
    const std::string key = AppExecFwk::Constants::PARMA_REQUEST_METHOD;
    const std::string value = AppExecFwk::Constants::OPEN_FORM_MANAGE_VIEW;
    want.SetParam(key, value);
    HILOG_DEBUG("JsFormProvider OnOpenFormManager want:%{public}s", want.ToString().c_str());

#ifdef NO_RUNTIME_EMULATOR
    int64_t processorId = FormEventHiAppEvent::AddProcessor();
    HILOG_INFO("Add processor begin.Processor id is %{public}" PRId64, processorId);
    time_t beginTime = time(nullptr);
#endif
    auto ret = FormMgr::GetInstance().StartAbilityByFms(want);
#ifdef NO_RUNTIME_EMULATOR
    PublishFormData publishFormData = {want.GetBundle(), want.GetElement().GetAbilityName(),
        want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, -1),
        want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY),
        want.GetStringParam(Constants::PARAM_FORM_NAME_KEY)};
    FormEventHiAppEvent::WriteAppFormEndEvent(ret, beginTime, "OpenFormManager", publishFormData,
        processorId);
#endif
    if (ret != ERR_OK) {
        HILOG_ERROR("fail to StartAbilityByFms, error code: %{public}d", ret);
        if (ret == ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED ||
            ret == ERR_APPEXECFWK_FORM_GET_INFO_FAILED || ret == ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED) {
            NapiFormUtil::ThrowByInternalErrorCode(env, ret);
        } else {
            NapiFormUtil::Throw(env, ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR,
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR));
        }
    }
    return CreateJsUndefined(env);
}

napi_value JsFormProvider::OpenFormManagerCrossBundle(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnOpenFormManagerCrossBundle);
}
 
napi_value JsFormProvider::OnOpenFormManagerCrossBundle(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");
#ifdef NO_RUNTIME_EMULATOR
    int64_t processorId = FormEventHiAppEvent::AddProcessor();
    HILOG_INFO("Add processor begin.Processor id is %{public}" PRId64, processorId);
    time_t beginTime = time(nullptr);
#endif
    Want want;
    if (!AppExecFwk::UnwrapWant(env, argv[PARAM0], want)) {
        HILOG_ERROR("fail convert want");
        NapiFormUtil::ThrowParamError(env, "Failed to convert want.");
        return CreateJsUndefined(env);
    }
 
    const std::string bundleName = want.GetBundle();
    const std::string abilityName = want.GetElement().GetAbilityName();
    want.SetElementName(bundleName, abilityName);
    want.SetAction(AppExecFwk::Constants::FORM_PAGE_ACTION);
    want.SetParam(AppExecFwk::Constants::PARAM_PAGE_ROUTER_SERVICE_CODE,
                  AppExecFwk::Constants::PAGE_ROUTER_SERVICE_CODE_FORM_MANAGE);
    const std::string key = AppExecFwk::Constants::PARMA_REQUEST_METHOD;
    const std::string value = AppExecFwk::Constants::OPEN_FORM_MANAGE_VIEW;
    want.SetParam(key, value);
    HILOG_DEBUG("JsFormProvider OnOpenFormManagerCrossBundle want:%{public}s", want.ToString().c_str());
 
    auto ret = FormMgr::GetInstance().StartAbilityByCrossBundle(want);
    if (ret != ERR_OK) {
        NapiFormUtil::ThrowByInternalErrorCode(env, ret);
    }
#ifdef NO_RUNTIME_EMULATOR
    PublishFormData publishFormData = {want.GetBundle(), want.GetElement().GetAbilityName(),
        want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, -1),
        want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY),
        want.GetStringParam(Constants::PARAM_FORM_NAME_KEY)};
    FormEventHiAppEvent::WriteAppFormEndEvent(ret, beginTime, "OpenFormManagerCrossBundle", publishFormData,
        processorId);
#endif
    return CreateJsUndefined(env);
}

napi_value JsFormProvider::SetFormNextRefreshTime(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnSetFormNextRefreshTime);
}

napi_value JsFormProvider::OnSetFormNextRefreshTime(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");
    if (CheckParamNum(env, argc, ARGS_SIZE_TWO, ARGS_SIZE_THREE) == false) {
        return CreateJsUndefined(env);
    }
    napi_valuetype paramZeroType = napi_undefined;
    napi_typeof(env, argv[PARAM0], &paramZeroType);
    if (paramZeroType != napi_string) {
        NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
        return CreateJsUndefined(env);
    }
    int64_t formId = 0;
    std::string strFormId;
    if (!ConvertFromJsValue(env, argv[PARAM0], strFormId)) {
        HILOG_ERROR("ConvertFromJsValue failed");
        NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
        return CreateJsUndefined(env);
    }
    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("convert form string failed");
        NapiFormUtil::ThrowParamError(env, "Failed to convert formId.");
        return CreateJsUndefined(env);
    }
    napi_valuetype paramOneType = napi_undefined;
    napi_typeof(env, argv[PARAM1], &paramOneType);
    if (paramOneType != napi_number) {
        NapiFormUtil::ThrowParamTypeError(env, "minute", "number");
        return CreateJsUndefined(env);
    }
    int32_t time;
    if (!ConvertFromJsValue(env, argv[PARAM1], time)) {
        NapiFormUtil::ThrowParamTypeError(env, "minute", "number");
        return CreateJsUndefined(env);
    }
    NapiAsyncTask::CompleteCallback complete = [formId, time](napi_env env, NapiAsyncTask &task, int32_t status) {
        int32_t ret = FormMgr::GetInstance().SetNextRefreshTime(formId, time);
        if (ret != ERR_OK) {
            task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            return;
        }
        task.ResolveWithNoError(env, CreateJsUndefined(env));
    };
    napi_value lastParam = (argc == ARGS_SIZE_THREE) ? argv[PARAM2] : nullptr;
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnSetFormNextRefreshTime",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::UpdateForm(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnUpdateForm);
}

napi_value JsFormProvider::OnUpdateFormParseParam(napi_env env, size_t argc, napi_value* argv, int64_t &formId)
{
    if (CheckParamNum(env, argc, ARGS_SIZE_TWO, ARGS_SIZE_THREE) == false) {
        return CreateJsUndefined(env);
    }
    if (!ConvertFormId(env, argv[PARAM0], formId)) {
        HILOG_ERROR("convert form string failed");
        NapiFormUtil::ThrowParamError(env, "Failed to convert formId.");
        return CreateJsUndefined(env);
    }
    napi_valuetype paramOneType = napi_undefined;
    napi_typeof(env, argv[PARAM1], &paramOneType);
    if (paramOneType != napi_object) {
        HILOG_ERROR("formBindingData not napi_object");
        NapiFormUtil::ThrowParamTypeError(env, "formBindingData", "formBindingData.FormBindingData");
        return CreateJsUndefined(env);
    }
    return nullptr;
}

napi_value JsFormProvider::OnUpdateForm(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");

    int64_t formId = 0;
    napi_value parseResult = OnUpdateFormParseParam(env, argc, argv, formId);
    if (parseResult != nullptr) {
        HILOG_ERROR("parse param failed");
        return parseResult;
    }

    auto formProviderData = std::make_shared<OHOS::AppExecFwk::FormProviderData>();
    std::string formDataStr = GetStringByProp(env, argv[PARAM1], "data");
    formProviderData->SetDataString(formDataStr);
    formProviderData->ParseImagesData();

    std::vector<AppExecFwk::FormDataProxy> formDataProxies;
    napi_value nativeProxies = nullptr;
    napi_get_named_property(env, argv[PARAM1], "proxies", &nativeProxies);
    if (nativeProxies != nullptr) {
        ConvertFromDataProxies(env, nativeProxies, formDataProxies);
    }

    NapiAsyncTask::CompleteCallback complete =
        [formId, data = formProviderData, formDataProxies](napi_env env, NapiAsyncTask &task, int32_t status) {
            int32_t ret = FormMgr::GetInstance().UpdateForm(formId, *data, formDataProxies);
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            task.ResolveWithNoError(env, CreateJsUndefined(env));
        };
    napi_value lastParam = (argc == ARGS_SIZE_THREE) ? argv[PARAM2] : nullptr;
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnUpdateForm",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::IsRequestPublishFormSupported(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnIsRequestPublishFormSupported);
}

napi_value JsFormProvider::OnIsRequestPublishFormSupported(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");
    if (CheckParamNum(env, argc, ARGS_SIZE_ZERO, ARGS_SIZE_ONE) == false) {
        return CreateJsUndefined(env);
    }

    auto selfToken = IPCSkeleton::GetSelfTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        HILOG_ERROR("The application not system-app,can't use system-api");
        NapiFormUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
        return CreateJsUndefined(env);
    }

    NapiAsyncTask::CompleteCallback complete = [](napi_env env, NapiAsyncTask &task, int32_t status) {
        bool value = FormMgr::GetInstance().IsRequestPublishFormSupported();
        napi_value jsValue = nullptr;
        napi_get_boolean(env, value, &jsValue);
        task.ResolveWithNoError(env, jsValue);
    };
    napi_value lastParam = (argc == ARGS_SIZE_ONE) ? argv[PARAM0] : nullptr;
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnIsRequestPublishFormSupported",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::RequestPublishForm(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnRequestPublishForm);
}

napi_value JsFormProvider::OnRequestPublishForm(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");
    if (CheckParamNum(env, argc, ARGS_SIZE_ONE, ARGS_SIZE_THREE) == false) {
        return CreateJsUndefined(env);
    }

    auto asyncCallbackInfo = std::make_shared<RequestPublishFormCallbackInfo>();
    decltype(argc) convertArgc = 0;
    napi_valuetype paramZeroType = napi_undefined;
    napi_typeof(env, argv[PARAM0], &paramZeroType);
    if (paramZeroType != napi_object) {
        HILOG_ERROR("formId not napi_object");
        NapiFormUtil::ThrowParamTypeError(env, "want", "Want");
        return CreateJsUndefined(env);
    }
    if (!AppExecFwk::UnwrapWant(env, argv[PARAM0], asyncCallbackInfo->want)) {
        HILOG_ERROR("fail convert want");
        NapiFormUtil::ThrowParamError(env, "Failed to convert want.");
        return CreateJsUndefined(env);
    }
    convertArgc++;

    if (argc > ARGS_SIZE_ONE) {
        napi_valuetype paramOneType = napi_undefined;
        napi_typeof(env, argv[PARAM1], &paramOneType);
        if (paramOneType == napi_object) {
            asyncCallbackInfo->withFormBindingData = true;
            auto formProviderData = std::make_unique<FormProviderData>();
            std::string formDataStr = GetStringByProp(env, argv[PARAM1], "data");
            formProviderData->SetDataString(formDataStr);
            formProviderData->ParseImagesData();
            asyncCallbackInfo->formProviderData = std::move(formProviderData);

            napi_value nativeProxies = nullptr;
            napi_get_named_property(env, argv[PARAM1], "proxies", &nativeProxies);
            if (nativeProxies != nullptr) {
                ConvertFromDataProxies(env, nativeProxies, asyncCallbackInfo->formDataProxies);
            }
            convertArgc++;
        } else if (paramOneType == napi_function) {
            asyncCallbackInfo->withFormBindingData = false;
        } else {
            HILOG_ERROR("formBindingData not napi_object");
            NapiFormUtil::ThrowParamTypeError(env, "formBindingData", "formBindingData.FormBindingData");
            return CreateJsUndefined(env);
        }
    }

    NapiAsyncTask::CompleteCallback complete = [asyncCallbackInfo](napi_env env, NapiAsyncTask &task, int32_t status) {
        int64_t formId = 0;
        asyncCallbackInfo->want.SetParam(IS_FORM_AGENT, false);
        ErrCode ret = FormMgr::GetInstance().RequestPublishForm(asyncCallbackInfo->want,
            asyncCallbackInfo->withFormBindingData, asyncCallbackInfo->formProviderData, formId,
            asyncCallbackInfo->formDataProxies);
        if (ret != ERR_OK) {
            task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
            return;
        }
        std::string formIdStr = std::to_string(formId);
        napi_value result = nullptr;
        napi_create_string_utf8(env, formIdStr.c_str(), formIdStr.size(), &result);
        task.ResolveWithNoError(env, result);
    };
    napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnRequestPublishForm",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

bool JsFormProvider::ConvertFromDataProxies(napi_env env, napi_value value,
    std::vector<AppExecFwk::FormDataProxy> &formDataProxies)
{
    bool result = false;
    napi_is_array(env, value, &result);
    if (value == nullptr || !result) {
        HILOG_WARN("null jsValue not array");
        return false;
    }

    uint32_t length = 0;
    napi_get_array_length(env, value, &length);
    napi_value element = nullptr;
    for (uint32_t i = 0; i < length; i++) {
        AppExecFwk::FormDataProxy formDataProxy("", "");
        napi_get_element(env, value, i, &element);
        if (!ConvertFormDataProxy(env, element, formDataProxy)) {
            HILOG_ERROR("GetElement from array [%{public}u] error", i);
            continue;
        }
        formDataProxies.push_back(formDataProxy);
    }
    return true;
}

bool JsFormProvider::ConvertFormDataProxy(napi_env env, napi_value value,
    AppExecFwk::FormDataProxy &formDataProxy)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (value == nullptr || valueType != napi_object) {
        HILOG_WARN("null jsValue,not object");
        return false;
    }

    napi_value key = nullptr;
    napi_get_named_property(env, value, "key", &key);
    if (!ConvertFromJsValue(env, key, formDataProxy.key)) {
        HILOG_ERROR("Parse key error");
        return false;
    }

    napi_value subscribeId = nullptr;
    napi_get_named_property(env, value, "subscriberId", &subscribeId);
    if (subscribeId != nullptr && !ConvertFromJsValue(env, subscribeId, formDataProxy.subscribeId)) {
        HILOG_WARN("Parse subscribeId failed, use empty as default value");
        formDataProxy.subscribeId = "";
    }
    HILOG_INFO("key:%{public}s,subscribeId:%{public}s", formDataProxy.key.c_str(),
        formDataProxy.subscribeId.c_str());
    return true;
}

napi_value JsFormProvider::OpenFormEditAbility(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnOpenFormEditAbility);
}

napi_value JsFormProvider::OnOpenFormEditAbility(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");
    if (!CheckParamNum(env, argc, ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2 or 3");
        return CreateJsUndefined(env);
    }
    std::string abilityName;
    if (!ConvertFromJsValue(env, argv[PARAM0], abilityName)) {
        HILOG_ERROR("ConvertFromJsValue failed");
        NapiFormUtil::ThrowParamTypeError(env, "abilityName", "string");
        return CreateJsUndefined(env);
    }

    int64_t formId = 0;
    if (!ConvertFormId(env, argv[PARAM1], formId)) {
        HILOG_ERROR("ConvertFromJsValue");
        NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
        return CreateJsUndefined(env);
    }

    bool isMainPage = true;
    if (argc == ARGS_SIZE_THREE) {
        if (!ConvertFromJsValue(env, argv[PARAM2], isMainPage)) {
            isMainPage = true;
        }
    }
    HILOG_INFO("OnOpenFormEditAbility abilityName: %{public}s, formId: %{public}" PRId64 "isMainPage: %{public}s",
        abilityName.c_str(), formId, isMainPage ? "true" : "false");
    auto ret = FormMgr::GetInstance().OpenFormEditAbility(abilityName, formId, isMainPage);
    if (ret != ERR_OK) {
        NapiFormUtil::ThrowByInternalErrorCode(env, ret);
    }
    return CreateJsUndefined(env);
}

napi_value JsFormProvider::RequestOverflow(napi_env env, napi_callback_info info)
{
    HILOG_INFO("Call");
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnRequestOverflow);
}

napi_value JsFormProvider::OnRequestOverflow(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_INFO("Call");
    if (argc != ARGS_SIZE_TWO) {
        HILOG_ERROR("Wrong number of arguments");
        NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2");
        return CreateJsUndefined(env);
    }

    int64_t formId = 0;
    if (!ConvertFormId(env, argv[PARAM0], formId)) {
        HILOG_ERROR("Convert formId failed, formId:%{public}" PRId64 ".", formId);
        NapiFormUtil::ThrowParamError(env, "The formId is invalid");
        return CreateJsUndefined(env);
    }

    AppExecFwk::OverflowInfo* overflowInfo = new (std::nothrow) AppExecFwk::OverflowInfo {};
    if (overflowInfo == nullptr) {
        HILOG_ERROR("Failed to new overflowInfo");
        return CreateJsUndefined(env);
    }
    if (!ConvertFormOverflowInfo(env, argv[PARAM1], overflowInfo)) {
        HILOG_ERROR("convert overflowInfo failed");
        delete overflowInfo;
        NapiFormUtil::ThrowParamError(env, "The overflowInfo is invalid");
        return CreateJsUndefined(env);
    }

    NapiAsyncTask::CompleteCallback complete =
        [formId, overflowInfo](napi_env env, NapiAsyncTask &task, int32_t status) {
            ErrCode ret = FormMgr::GetInstance().RequestOverflow(formId, *overflowInfo, true);
            delete overflowInfo;
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            task.ResolveWithNoError(env, CreateJsUndefined(env));
        };
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnRequestOverflow",
        env, CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::CancelOverflow(napi_env env, napi_callback_info info)
{
    HILOG_INFO("call");
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnCancelOverflow);
}

napi_value JsFormProvider::OnCancelOverflow(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_INFO("call");
    if (argc != ARGS_SIZE_ONE) {
        HILOG_ERROR("wrong number of arguments");
        NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1");
        return CreateJsUndefined(env);
    }

    int64_t formId = 0;
    if (!ConvertFormId(env, argv[PARAM0], formId)) {
        HILOG_ERROR("convert formId failed, formId:%{public}" PRId64 ".", formId);
        NapiFormUtil::ThrowParamError(env, "The formId is invalid");
        return CreateJsUndefined(env);
    }

    AppExecFwk::OverflowInfo* overflowInfo = new (std::nothrow) AppExecFwk::OverflowInfo {};
    if (overflowInfo == nullptr) {
        HILOG_ERROR("Failed to new overflowInfo");
        return CreateJsUndefined(env);
    }
    NapiAsyncTask::CompleteCallback complete =
        [formId, overflowInfo](napi_env env, NapiAsyncTask &task, int32_t status) {
            HILOG_INFO("complete");
            bool ret = FormMgr::GetInstance().RequestOverflow(formId, *overflowInfo, false);
            delete overflowInfo;
            if (!ret) {
                HILOG_INFO("complete ret false");
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            HILOG_INFO("complete ret true");
            napi_value jsValue = nullptr;
            napi_get_boolean(env, ret, &jsValue);
            task.ResolveWithNoError(env, jsValue);
        };
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnCancelOverflow",
        env, CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
    HILOG_INFO("call end");
    return result;
}

napi_value JsFormProvider::ActivateSceneAnimation(napi_env env, napi_callback_info info)
{
    HILOG_INFO("call");
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnActivateSceneAnimation);
}

napi_value JsFormProvider::OnActivateSceneAnimation(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_INFO("call");
    if (argc != ARGS_SIZE_ONE) {
        HILOG_ERROR("OnActivateSceneAnimation wrong number of arguments.");
        NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1");
        return CreateJsUndefined(env);
    }

    int64_t formId;
    if (!ConvertFormId(env, argv[PARAM0], formId)) {
        HILOG_ERROR("Convert formId failed, formId:%{public}" PRId64 ".", formId);
        NapiFormUtil::ThrowParamError(env, "The formId is invalid");
        return CreateJsUndefined(env);
    }

    NapiAsyncTask::CompleteCallback complete =
        [formId](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto selfToken = IPCSkeleton::GetSelfTokenID();
            if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
                HILOG_ERROR("The application not system-app,can't use system-api");
                task.Reject(env,
                    NapiFormUtil::CreateErrorByInternalErrorCode(env, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS));
                return;
            }
            ErrCode ret = FormMgr::GetInstance().ChangeSceneAnimationState(formId,
                static_cast<int32_t>(ActivationState::Activated));
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            task.ResolveWithNoError(env, CreateJsUndefined(env));
        };
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnActivateSceneAnimation",
        env, CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::DeactivateSceneAnimation(napi_env env, napi_callback_info info)
{
    HILOG_INFO("call");
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnDeactivateSceneAnimation);
}

napi_value JsFormProvider::OnDeactivateSceneAnimation(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_INFO("call");
    if (argc != ARGS_SIZE_ONE) {
        HILOG_ERROR("OnDeactivateSceneAnimation wrong number of arguments");
        NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1");
        return CreateJsUndefined(env);
    }

    int64_t formId;
    if (!ConvertFormId(env, argv[PARAM0], formId)) {
        HILOG_ERROR("Convert formId failed, formId:%{public}" PRId64 ".", formId);
        NapiFormUtil::ThrowParamError(env, "The formId is invalid");
        return CreateJsUndefined(env);
    }

    NapiAsyncTask::CompleteCallback complete =
        [formId](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto selfToken = IPCSkeleton::GetSelfTokenID();
            if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
                HILOG_ERROR("The application not system-app,can't use system-api");
                task.Reject(env,
                    NapiFormUtil::CreateErrorByInternalErrorCode(env, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS));
                return;
            }
            ErrCode ret = FormMgr::GetInstance().ChangeSceneAnimationState(formId,
                static_cast<int32_t>(ActivationState::Deactivated));
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            task.ResolveWithNoError(env, CreateJsUndefined(env));
        };
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnDeactivateSceneAnimation",
        env, CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
    return result;
}

bool JsFormProvider::ConvertFormOverflowInfo(napi_env env, napi_value argv, AppExecFwk::OverflowInfo* overflowInfo)
{
    HILOG_INFO("call");
    napi_valuetype type = napi_undefined;
    napi_typeof(env, argv, &type);
    if (type != napi_object) {
        HILOG_ERROR("not napi_object");
        return false;
    }
    napi_value rangeArea = nullptr;
    napi_status areaRet = napi_get_named_property(env, argv, "area", &rangeArea);
    if (areaRet != napi_ok) {
        HILOG_ERROR("get overflowInfo area failed");
        return false;
    }
    napi_value rangeDuration;
    napi_status durationRet = napi_get_named_property(env, argv, "duration", &rangeDuration);
    int32_t duration = -1;
    if (durationRet != napi_ok) {
        HILOG_WARN("get overflowInfo duration failed");
        return false;
    }
    if (!ConvertFromJsValue(env, rangeDuration, duration)) {
        HILOG_ERROR("ConvertFromJsValue duration failed");
        return false;
    }
    overflowInfo->duration = duration;
    HILOG_INFO("ConvertFormOverflowInfo duration: %{public}d", duration);

    napi_value defaultAnimateNapiVal;
    napi_status defaultAnimateRet = napi_get_named_property(env, argv, "useDefaultAnimation", &defaultAnimateNapiVal);
    bool defaultAnimation = true;
    if (defaultAnimateRet == napi_ok) {
        if (!ConvertFromJsValue(env, defaultAnimateNapiVal, defaultAnimation)) {
            HILOG_ERROR("ConvertFormOverflowInfo defaultAnimation: failed");
        }
    } else {
        HILOG_WARN("get overflowInfo defaultAnimation failed");
    }
    overflowInfo->useDefaultAnimation = defaultAnimation;
    HILOG_INFO("ConvertFormOverflowInfo defaultAnimation: %{public}d", defaultAnimation);

    AppExecFwk::Rect area;
    if (!ConvertOverflowInfoArea(env, rangeArea, area)) {
        HILOG_ERROR("get overflowInfo area failed");
        return false;
    }
    overflowInfo->area = area;
    HILOG_INFO("ConvertFormOverflowInfo rect: %{public}f, %{public}f, %{public}f, %{public}f",
        area.left, area.top, area.width, area.height);
    return true;
}

bool JsFormProvider::GetAndConvertProperty(napi_env env, napi_value object, const char* propertyName, double& outValue)
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

bool JsFormProvider::ConvertOverflowInfoArea(napi_env env, napi_value rangeArea, AppExecFwk::Rect &area)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, rangeArea, &type);
    if (type == napi_undefined || type == napi_null) {
        HILOG_ERROR("input rangeArea is undefined or null");
        return false;
    }
    if (!GetAndConvertProperty(env, rangeArea, "left", area.left) ||
        !GetAndConvertProperty(env, rangeArea, "top", area.top) ||
        !GetAndConvertProperty(env, rangeArea, "width", area.width) ||
        !GetAndConvertProperty(env, rangeArea, "height", area.height)) {
        return false;
    }
    return true;
}

napi_value JsFormProvider::GetFormRect(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnGetFormRect);
}
 
napi_value CreateFormRect(napi_env env, const AppExecFwk::Rect &rect)
{
    HILOG_DEBUG("call");
 
    napi_value objContext = nullptr;
    napi_create_object(env, &objContext);
 
    napi_set_named_property(env, objContext, "left", CreateJsValue(env, rect.left));
    napi_set_named_property(env, objContext, "top", CreateJsValue(env, rect.top));
    napi_set_named_property(env, objContext, "width", CreateJsValue(env, rect.width));
    napi_set_named_property(env, objContext, "height", CreateJsValue(env, rect.height));
 
    return objContext;
}
 
napi_value JsFormProvider::OnGetFormRect(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_INFO("call");
    if (argc != ARGS_SIZE_ONE) {
        HILOG_ERROR("OnGetFormRect wrong number of arguments.");
        NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1");
        return CreateJsUndefined(env);
    }
 
    int64_t formId;
    if (!ConvertFormId(env, argv[PARAM0], formId)) {
        HILOG_ERROR("OnGetFormRect convert formId failed.");
        NapiFormUtil::ThrowParamError(env, "The formId is invalid");
        return CreateJsUndefined(env);
    }
 
    NapiAsyncTask::CompleteCallback complete =
        [formId](napi_env env, NapiAsyncTask &task, int32_t status) {
            HILOG_INFO("OnGetFormRect start");
            AppExecFwk::Rect item;
            ErrCode ret = FormMgr::GetInstance().GetFormRect(formId, item);
            if (ret != ERR_OK) {
                HILOG_INFO("OnGetFormRect failed, code:%{public}d", ret);
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            task.ResolveWithNoError(env, CreateFormRect(env, item));
        };
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnGetFormRect",
        env, CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::GetPublishedRunningFormInfos(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnGetPublishedRunningFormInfos);
}
 
napi_value JsFormProvider::OnGetPublishedRunningFormInfos(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");
 
    NapiAsyncTask::CompleteCallback complete =
        [](napi_env env, NapiAsyncTask &task, int32_t status) {
            std::vector<RunningFormInfo> runningFormInfos;
            auto ret = FormMgr::GetInstance().GetPublishedFormInfos(runningFormInfos);
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            task.ResolveWithNoError(env, CreateNewRunningFormInfos(env, runningFormInfos));
        };
 
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnGetPublishedRunningFormInfos",
        env, CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::GetPublishedRunningFormInfoById(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnGetPublishedRunningFormInfoById);
}
 
napi_value JsFormProvider::OnGetPublishedRunningFormInfoById(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");
    if (CheckParamNum(env, argc, ARGS_SIZE_ONE, ARGS_SIZE_TWO) == false) {
        return CreateJsUndefined(env);
    }
    napi_valuetype paramZeroType = napi_undefined;
    napi_typeof(env, argv[PARAM0], &paramZeroType);
    if (paramZeroType != napi_string) {
        NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
        return CreateJsUndefined(env);
    }
    int64_t formId = 0;
    std::string strFormId;
    if (!ConvertFromJsValue(env, argv[PARAM0], strFormId)) {
        HILOG_ERROR("ConvertFromJsValue failed");
        NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
        return CreateJsUndefined(env);
    }
    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("convert form string failed");
        NapiFormUtil::ThrowParamError(env, "Failed to convert formId.");
        return CreateJsUndefined(env);
    }
 
    HILOG_INFO("before GetPublishedRunningFormInfoById, formId:%{public}" PRId64, formId);
    NapiAsyncTask::CompleteCallback complete =
        [formId](napi_env env, NapiAsyncTask &task, int32_t status) {
            RunningFormInfo runningFormInfo;
            auto ret = FormMgr::GetInstance().GetPublishedFormInfoById(formId, runningFormInfo);
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            task.ResolveWithNoError(env, CreateNewRunningFormInfo(env, runningFormInfo));
        };
 
    napi_value lastParam = (argc == ARGS_SIZE_TWO) ? argv[PARAM1] : nullptr;
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnGetPublishedRunningFormInfoById",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::ReloadForms(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnReloadForms);
}

napi_value JsFormProvider::OnReloadForms(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");
    if (!CheckParamNum(env, argc, ARGS_SIZE_FOUR, ARGS_SIZE_FOUR)) {
        return CreateJsUndefined(env);
    }
    if (!CheckUIAbilityContext(env, argv[PARAM0])) {
        return CreateJsUndefined(env);
    }
    std::string moduleName;
    if (!ConvertFromJsValue(env, argv[PARAM1], moduleName)) {
        HILOG_ERROR("ConvertFromJsValue failed");
        NapiFormUtil::ThrowParamTypeError(env, "moduleName", "string");
        return CreateJsUndefined(env);
    }
    std::string abilityName;
    if (!ConvertFromJsValue(env, argv[PARAM2], abilityName)) {
        HILOG_ERROR("ConvertFromJsValue failed");
        NapiFormUtil::ThrowParamTypeError(env, "abilityName", "string");
        return CreateJsUndefined(env);
    }
    std::string formName;
    if (!ConvertFromJsValue(env, argv[PARAM3], formName)) {
        HILOG_ERROR("ConvertFromJsValue failed");
        NapiFormUtil::ThrowParamTypeError(env, "formName", "string");
        return CreateJsUndefined(env);
    }

    NapiAsyncTask::CompleteCallback complete =
        [moduleName, abilityName, formName](napi_env env, NapiAsyncTask &task, int32_t status) {
            int32_t reloadNum = 0;
            auto ret = FormMgr::GetInstance().ReloadForms(reloadNum, moduleName, abilityName, formName);
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            napi_value jsReloadNum = nullptr;
            napi_create_int32(env, reloadNum, &jsReloadNum);
            task.ResolveWithNoError(env, jsReloadNum);
        };
 
    napi_value lastParam = nullptr;
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnReloadForms",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::ReloadAllForms(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnReloadAllForms);
}

napi_value JsFormProvider::OnReloadAllForms(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("call");
    if (!CheckParamNum(env, argc, ARGS_SIZE_ONE, ARGS_SIZE_ONE)) {
        return CreateJsUndefined(env);
    }
    if (!CheckUIAbilityContext(env, argv[PARAM0])) {
        return CreateJsUndefined(env);
    }

    NapiAsyncTask::CompleteCallback complete =
        [](napi_env env, NapiAsyncTask &task, int32_t status) {
            int32_t reloadNum = 0;
            auto ret = FormMgr::GetInstance().ReloadAllForms(reloadNum);
            if (ret != ERR_OK) {
                task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, ret));
                return;
            }
            napi_value jsReloadNum = nullptr;
            napi_create_int32(env, reloadNum, &jsReloadNum);
            task.ResolveWithNoError(env, jsReloadNum);
        };
 
    napi_value lastParam = nullptr;
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnReloadAllForms",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
