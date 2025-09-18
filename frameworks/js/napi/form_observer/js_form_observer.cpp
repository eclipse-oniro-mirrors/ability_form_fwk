
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "js_form_observer.h"

#include "fms_log_wrapper.h"
#include "form_callback_interface.h"
#include "form_host_client.h"
#include "form_info.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"
#include "ipc_skeleton.h"
#include "js_form_state_observer.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_form_util.h"
#include "runtime.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
using FormMgr = AppExecFwk::FormMgr;
namespace {
const std::string EMPTY_BUNDLE = "";
const std::string EMPTY_TYPE = "";
}
class JsFormObserver {
public:
    JsFormObserver() = default;
    ~JsFormObserver() = default;

    static void Finalizer(napi_env env, void *data, void *hint)
    {
        HILOG_DEBUG("call");
        std::unique_ptr<JsFormObserver>(static_cast<JsFormObserver*>(data));
    }

    static napi_value RegisterFormObserver(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormObserver, OnRegisterFormObserver);
    }

    static napi_value UnregisterFormObserver(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormObserver, OnUnregisterFormObserver);
    }

    static napi_value GetRunningFormInfos(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormObserver, OnGetRunningFormInfos);
    }

    static napi_value GetFormInstancesByFilter(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormObserver, OnGetFormInstancesByFilter);
    }

    static napi_value GetFormInstanceById(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormObserver, OnGetFormInstanceById);
    }
private:
    bool CheckCallerIsSystemApp()
    {
        auto selfToken = IPCSkeleton::GetSelfTokenID();
        return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
    }

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

    static bool ConvertFromId(napi_env env, napi_value jsValue, int64_t &formId)
    {
        std::string strFormId;
        if (!ConvertFromJsValue(env, jsValue, strFormId)) {
            HILOG_ERROR("Convert strFormId failed");
            return false;
        }

        if (strFormId.empty()) {
            HILOG_ERROR("empty strFormId");
            return false;
        }

        if (!ConvertStringToInt64(strFormId, formId)) {
            HILOG_ERROR("Convert string formId to int64 failed");
            return false;
        }
        return true;
    }

    napi_value OnRegisterFormAddObserver(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("call");
        if (CheckParamNum(env, argc, ARGS_TWO, ARGS_THREE) == false) {
            return CreateJsUndefined(env);
        }

        std::string bundleName("");
        if (argc == ARGS_THREE) {
            if (!ConvertFromJsValue(env, argv[PARAM1], bundleName)) {
                HILOG_ERROR("Convert type failed");
                NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
                return CreateJsUndefined(env);
            }
        } else {
            bundleName = "all";
        }

        if (!AppExecFwk::IsTypeForNapiValue(env, argv[argc - 1], napi_function)) {
            HILOG_ERROR("invalid lastParam");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<formInfo.RunningFormInfo>");
            return CreateJsUndefined(env);
        }

        // Check the size of the map.
        if (!JsFormStateObserver::GetInstance()->CheckMapSize("formAdd", bundleName)) {
            NapiFormUtil::ThrowParamError(env,
                "The number of bundleNames registered to listen has exceeded the limit.");
            return CreateJsUndefined(env);
        }

        if (!JsFormStateObserver::GetInstance()->RegisterFormAddCallback(env, bundleName, argv[argc - 1])) {
            return CreateJsUndefined(env);
        }
        FormMgr::GetInstance().RegisterFormAddObserverByBundle(bundleName, JsFormStateObserver::GetInstance());
        return CreateJsUndefined(env);
    }

    napi_value OnRegisterFormRemoveObserver(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("call");
        if (CheckParamNum(env, argc, ARGS_TWO, ARGS_THREE) == false) {
            return CreateJsUndefined(env);
        }

        std::string bundleName("");
        if (argc == ARGS_THREE) {
            if (!ConvertFromJsValue(env, argv[PARAM1], bundleName)) {
                HILOG_ERROR("Convert type failed");
                NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
                return CreateJsUndefined(env);
            }
        } else {
            bundleName = "all";
        }

        if (!AppExecFwk::IsTypeForNapiValue(env, argv[argc - 1], napi_function)) {
            HILOG_ERROR("invalid lastParam");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<formInfo.RunningFormInfo>");
            return CreateJsUndefined(env);
        }

        // Check the size of the map.
        if (!JsFormStateObserver::GetInstance()->CheckMapSize("formRemove", bundleName)) {
            NapiFormUtil::ThrowParamError(env,
                "The number of bundleNames registered to listen has exceeded the limit.");
            return CreateJsUndefined(env);
        }

        if (!JsFormStateObserver::GetInstance()->RegisterFormRemoveCallback(env, bundleName, argv[argc - 1])) {
            return CreateJsUndefined(env);
        }

        FormMgr::GetInstance().RegisterFormRemoveObserverByBundle(bundleName, JsFormStateObserver::GetInstance());
        return CreateJsUndefined(env);
    }

    napi_value OnRegisterFormObserver(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("call");
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("The app not system-app,can't use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }

        std::string type;
        if (!ConvertFromJsValue(env, argv[PARAM0], type)) {
            HILOG_ERROR("Convert type failed");
            NapiFormUtil::ThrowParamTypeError(env, "type",
                "formAdd, formRemove, notifyVisible, notifyInvisible, router, message, call.");
            return CreateJsUndefined(env);
        }

        if (type == "formAdd") {
            return OnRegisterFormAddObserver(env, argc, argv);
        } else if (type == "formRemove") {
            return OnRegisterFormRemoveObserver(env, argc, argv);
        } else if (type == "notifyVisible") {
            return OnRegisterFormIsVisibleObserver(env, argc, argv, true);
        } else if (type == "notifyInvisible") {
            return OnRegisterFormIsVisibleObserver(env, argc, argv, false);
        } else if (type == "router" || type == "message" || type == "call") {
            return OnRegisterClickEventCallback(env, argc, argv, type);
        } else {
            HILOG_ERROR("args[0] not formAdd,formRemove,notifyVisible,notifyInvisible,router,message,call");
            NapiFormUtil::ThrowParamTypeError(env, "type",
                "formAdd, formRemove, notifyVisible, notifyInvisible, router, message, call.");
            return CreateJsUndefined(env);
        }
    }

    napi_value OnRegisterFormIsVisibleObserver(napi_env env, size_t argc, napi_value *argv, bool isVisibility)
    {
        HILOG_DEBUG("call");
        if (CheckParamNum(env, argc, ARGS_TWO, ARGS_THREE) == false) {
            return CreateJsUndefined(env);
        }

        int32_t funcPos = 0;
        std::string bundleName(EMPTY_BUNDLE);
        if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            // There are two or more arguments, and the type of argument2 is function.
            funcPos = PARAM1;
        } else if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_string)) {
            // There are three or more arguments, and the type of argument2 is string.
            if (!ConvertFromJsValue(env, argv[PARAM1], bundleName)) {
                HILOG_ERROR("invalid secondParam");
                NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
                return CreateJsUndefined(env);
            }
            if (bundleName.empty()) {
                HILOG_ERROR("empty bundleName");
                NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
                return CreateJsUndefined(env);
            }
            funcPos = PARAM2;
        } else {
            HILOG_ERROR("invalid secondParam");
            NapiFormUtil::ThrowParamTypeError(env, "param 2", "type");
            return CreateJsUndefined(env);
        }

        if (!AppExecFwk::IsTypeForNapiValue(env, argv[funcPos], napi_function)) {
            HILOG_ERROR("invalid lastParam");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<Array<RunningFormInfo>>");
            return CreateJsUndefined(env);
        }

        if (formObserver_ == nullptr) {
            HILOG_ERROR("null formObserver_");
            formObserver_ = JsFormStateObserver::GetInstance();
        }
        JsFormStateObserver::GetInstance()->
            RegisterFormInstanceCallback(env, argv[funcPos], isVisibility, bundleName, formObserver_);
        return CreateJsUndefined(env);
    }

    napi_value OnUnregisterFormIsVisibleObserver(napi_env env, size_t argc, napi_value *argv, bool isVisibility)
    {
        HILOG_DEBUG("argc is %{public}zu, isVisibility is %{public}d", argc, isVisibility);
        int32_t funcPos = 0;
        int32_t bundlePos = 0;
        if (CheckParamNum(env, argc, ARGS_ONE, ARGS_THREE) == false) {
            return CreateJsUndefined(env);
        }
        std::string bundleName(EMPTY_BUNDLE);
        if (argc == ARGS_TWO) {
            if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
                HILOG_DEBUG("The second param is function");
                funcPos = PARAM1;
            } else if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_string)) {
                bundlePos = PARAM1;
            } else {
                NapiFormUtil::ThrowParamTypeError(env, "param 2", "type");
                return CreateJsUndefined(env);
            }
        }

        if (argc == ARGS_THREE) {
            if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_string)
                && AppExecFwk::IsTypeForNapiValue(env, argv[PARAM2], napi_function)) {
                bundlePos = PARAM1;
                funcPos = PARAM2;
            } else {
                NapiFormUtil::ThrowParamTypeError(env, "param 2 or 3", "type");
                return CreateJsUndefined(env);
            }
        }

        if (bundlePos != 0) {
            if (!ConvertFromJsValue(env, argv[bundlePos], bundleName) || bundleName.empty()) {
                HILOG_ERROR("Convert bundleName failed.bundleName is %{public}s", bundleName.c_str());
                NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
                return CreateJsUndefined(env);
            }
        }

        if (funcPos != 0) {
            JsFormStateObserver::GetInstance()->
                DelFormNotifyVisibleCallbackByBundle(bundleName, isVisibility, argv[funcPos], formObserver_);
            return CreateJsUndefined(env);
        }
        // If there is only one argument.
        JsFormStateObserver::GetInstance()->
            ClearFormNotifyVisibleCallbackByBundle(bundleName, isVisibility, formObserver_);
        return CreateJsUndefined(env);
    }

    napi_value OnUnregisterFormRemoveObserverWithTwoParams(napi_env env, size_t argc, napi_value *argv)
    {
        if (argc != ARGS_TWO) {
            return CreateJsUndefined(env);
        }
        if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            JsFormStateObserver::GetInstance()->DelFormRemoveCallbackByBundle(
                reinterpret_cast<napi_value>(argv[PARAM1]), "all");
            return CreateJsUndefined(env);
        } else if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_string)) {
            std::string bundleName;
            if (!ConvertFromJsValue(env, argv[PARAM1], bundleName)) {
                HILOG_ERROR("Convert bundleName error");
                NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
                return CreateJsUndefined(env);
            }
            JsFormStateObserver::GetInstance()->ClearFormRemoveCallbackByBundle(bundleName);
            return CreateJsUndefined(env);
        } else {
            HILOG_ERROR("The second param is ineffective");
            NapiFormUtil::ThrowParamTypeError(env, "callback or bundleName",
                "Callback<formInfo.RunningFormInfo> or string");
            return CreateJsUndefined(env);
        }
        return CreateJsUndefined(env);
    }

    napi_value OnUnregisterFormRemoveObserverWithThreeParams(napi_env env, size_t argc, napi_value *argv)
    {
        if (argc != ARGS_THREE) {
            return CreateJsUndefined(env);
        }
        if (!AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_string)) {
            HILOG_ERROR("The second param is ineffective");
            NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
            return CreateJsUndefined(env);
        }
        if (!AppExecFwk::IsTypeForNapiValue(env, argv[PARAM2], napi_function)) {
            HILOG_ERROR("The third param is ineffective");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<formInfo.RunningFormInfo>");
            return CreateJsUndefined(env);
        }
        std::string bundleName;
        if (!ConvertFromJsValue(env, argv[PARAM1], bundleName)) {
            HILOG_ERROR("Convert bundleName failed");
            NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
            return CreateJsUndefined(env);
        }
        JsFormStateObserver::GetInstance()->DelFormRemoveCallbackByBundle(argv[PARAM2], bundleName);
        return CreateJsUndefined(env);
    }

    napi_value OnUnregisterFormRemoveObserver(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("call");
        if (CheckParamNum(env, argc, ARGS_ONE, ARGS_THREE) == false) {
            return CreateJsUndefined(env);
        }

        if (argc == ARGS_ONE) {
            // If there is only one argument, all listening will be cancelled.
            JsFormStateObserver::GetInstance()->ClearFormRemoveCallbackByBundle("all");
            return CreateJsUndefined(env);
        } else if (argc == ARGS_TWO) {
            return OnUnregisterFormRemoveObserverWithTwoParams(env, argc, argv);
        } else {
            return OnUnregisterFormRemoveObserverWithThreeParams(env, argc, argv);
        }
        return CreateJsUndefined(env);
    }

    napi_value OnUnregisterFormAddObserverWithTwoParams(napi_env env, size_t argc, napi_value *argv)
    {
        if (argc != ARGS_TWO) {
            return CreateJsUndefined(env);
        }
        if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            JsFormStateObserver::GetInstance()->DelFormAddCallbackByBundle(argv[PARAM1], "all");
            return CreateJsUndefined(env);
        } else if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_string)) {
            std::string bundleName;
            if (!ConvertFromJsValue(env, argv[PARAM1], bundleName)) {
                HILOG_ERROR("Convert bundleName failed");
                NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
                return CreateJsUndefined(env);
            }
            JsFormStateObserver::GetInstance()->ClearFormAddCallbackByBundle(bundleName);
            return CreateJsUndefined(env);
        } else {
            HILOG_ERROR("invalid secondParam");
            NapiFormUtil::ThrowParamTypeError(env, "callback or bundleName",
                "Callback<formInfo.RunningFormInfo> or string");
            return CreateJsUndefined(env);
        }
        return CreateJsUndefined(env);
    }

    napi_value OnUnregisterFormAddObserverWithThreeParams(napi_env env, size_t argc, napi_value *argv)
    {
        if (argc != ARGS_THREE) {
            return CreateJsUndefined(env);
        }
        if (!AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_string)) {
            HILOG_ERROR("invalid secondParam");
            NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
            return CreateJsUndefined(env);
        }
        if (!AppExecFwk::IsTypeForNapiValue(env, argv[PARAM2], napi_function)) {
            HILOG_ERROR("invalid thirdParam");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<formInfo.RunningFormInfo>");
            return CreateJsUndefined(env);
        }
        std::string bundleName;
        if (!ConvertFromJsValue(env, argv[PARAM1], bundleName)) {
            HILOG_ERROR("Convert bundleName failed");
            NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
            return CreateJsUndefined(env);
        }
        JsFormStateObserver::GetInstance()->DelFormAddCallbackByBundle(argv[PARAM2], bundleName);
        return CreateJsUndefined(env);
    }

    napi_value OnUnregisterFormAddObserver(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("call");
        if (CheckParamNum(env, argc, ARGS_ONE, ARGS_THREE) == false) {
            return CreateJsUndefined(env);
        }

        if (argc == ARGS_ONE) {
            // If there is only one argument, full listening will be cancelled.
            JsFormStateObserver::GetInstance()->ClearFormAddCallbackByBundle("all");
            return CreateJsUndefined(env);
        } else if (argc == ARGS_TWO) {
            return OnUnregisterFormAddObserverWithTwoParams(env, argc, argv);
        } else if (argc == ARGS_THREE) {
            return OnUnregisterFormAddObserverWithThreeParams(env, argc, argv);
        }
        return CreateJsUndefined(env);
    }

    napi_value OnUnregisterFormObserver(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("call");
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("The application not system-app, can't use system-api");
            NapiFormUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return CreateJsUndefined(env);
        }

        // Check the type of the PARAM0 and convert it to string.
        std::string type;
        if (!ConvertFromJsValue(env, argv[PARAM0], type)) {
            HILOG_ERROR("Convert type error");
            NapiFormUtil::ThrowParamTypeError(env, "type",
                "formAdd, formRemove, formUninstall, notifyVisible or notifyInvisible.");
            return CreateJsUndefined(env);
        }

        if (type == "formAdd") {
            return OnUnregisterFormAddObserver(env, argc, argv);
        } else if (type == "formRemove") {
            return OnUnregisterFormRemoveObserver(env, argc, argv);
        } else if (type == "notifyVisible") {
            return OnUnregisterFormIsVisibleObserver(env, argc, argv, true);
        } else if (type == "notifyInvisible") {
            return OnUnregisterFormIsVisibleObserver(env, argc, argv, false);
        } else if (type == "router" || type == "message" || type == "call") {
            return OnUnregisterClickEventCallback(env, argc, argv, type);
        } else {
            HILOG_ERROR("args[0] not formAdd,formRemove,notifyVisible,notifyInvisible,router,message,call");
            NapiFormUtil::ThrowParamTypeError(env, "type",
                "args[0] should be formAdd, formRemove,"
                "notifyVisible, notifyInvisible, router, message, call");
            return CreateJsUndefined(env);
        }
    }

    bool ParseGetRunningFormInfosOneParam(const napi_env &env, const napi_value *argv, std::string &bundleName,
        bool &hasBundleName, bool &isUnusedIncluded)
    {
        HILOG_DEBUG("call");
        if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM0], napi_string)) {
            if (!ConvertFromJsValue(env, argv[PARAM0], bundleName)) {
                HILOG_ERROR("Convert bundleName failed");
                NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
                return false;
            }
            if (bundleName.empty()) {
                HILOG_ERROR("empty bundleName");
                NapiFormUtil::ThrowParamError(env, "bundleName is empty.");
                return false;
            }
            hasBundleName = true;
        } else if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM0], napi_boolean)) {
            if (!ConvertFromJsValue(env, argv[PARAM0], isUnusedIncluded)) {
                HILOG_ERROR("Convert isUnusedIncluded failed");
                NapiFormUtil::ThrowParamTypeError(env, "isUnusedIncluded", "bool");
                return false;
            }
        } else {
            HILOG_ERROR("Input params not string or boolean");
            NapiFormUtil::ThrowParamTypeError(env, "the first param", "string or boolean");
            return false;
        }
        return true;
    }

    bool ParseGetRunningFormInfosParams(const napi_env &env, const napi_value *argv, std::string &bundleName,
        bool &isUnusedIncluded, int startPos)
    {
        HILOG_DEBUG("call");
        if (!ConvertFromJsValue(env, argv[startPos], isUnusedIncluded)) {
            HILOG_ERROR("Convert isUnusedIncluded failed");
            NapiFormUtil::ThrowParamTypeError(env, "isUnusedIncluded", "bool");
            return false;
        }
        if (!ConvertFromJsValue(env, argv[startPos + 1], bundleName)) {
            HILOG_ERROR("Convert bundleName failed");
            NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
            return false;
        }
        return true;
    }

    bool ParseGetRunningFormInfosTwoParams(const napi_env &env, const napi_value *argv, std::string &bundleName,
        bool &hasBundleName, bool &isUnusedIncluded)
    {
        HILOG_DEBUG("call");
        if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM0], napi_function)) {
            if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_string)) {
                if (!ConvertFromJsValue(env, argv[PARAM1], bundleName)) {
                    HILOG_ERROR("Convert bundleName failed");
                    NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
                    return false;
                }
                hasBundleName = true;
            } else if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_boolean)) {
                if (!ConvertFromJsValue(env, argv[PARAM1], isUnusedIncluded)) {
                    HILOG_ERROR("Convert isUnusedIncluded failed");
                    NapiFormUtil::ThrowParamTypeError(env, "isUnusedIncluded", "bool");
                    return false;
                }
            } else {
                HILOG_ERROR("Input params not a string or boolean");
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
        HILOG_DEBUG("call");
        if (CheckParamNum(env, argc, ARGS_ZERO, ARGS_THREE) == false) {
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
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormObserver::OnGetRunningFormInfos", env,
            CreateAsyncTaskWithLastParam(env, callbackParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnGetFormInstancesByFilter(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("call");
        if (CheckParamNum(env, argc, ARGS_ONE, ARGS_THREE) == false) {
            return CreateJsUndefined(env);
        }

        AppExecFwk::FormInstancesFilter filter;
        if (!AppExecFwk::IsTypeForNapiValue(env, argv[PARAM0], napi_object)) {
            HILOG_ERROR("Input params not object");
            NapiFormUtil::ThrowParamTypeError(env, "formProviderFilter", "object");
            return CreateJsUndefined(env);
        }
        if (!ParseParam(env, argv[PARAM0], filter)) {
            HILOG_ERROR("Input params parse failed");
            NapiFormUtil::ThrowParamTypeError(env, "formProviderFilter", "object");
            return CreateJsUndefined(env);
        }
        if (argc == ARGS_TWO && !AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            HILOG_ERROR("invalid secondParam");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<string>");
            return CreateJsUndefined(env);
        }
        auto formInstances = std::make_shared<std::vector<AppExecFwk::FormInstance>>();
        auto apiResult = std::make_shared<int32_t>();
        auto execute = [filter, formInstances, ret = apiResult]() {
            *ret = FormMgr::GetInstance().GetFormInstancesByFilter(filter, *formInstances);
        };

        auto complete =
            [formInstances, ret = apiResult](napi_env env, NapiAsyncTask &task, int32_t status) {
                if (*ret != ERR_OK) {
                    HILOG_ERROR("Get FormInstances by filter failed");
                    task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, *ret));
                } else {
                    task.ResolveWithNoError(env, CreateFormInstances(env, *formInstances));
                }
            };
        napi_value lastParam = (argc == ARGS_ONE) ? nullptr : argv[PARAM1];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormObserver::OnGetFormInstancesByFilter",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnGetFormInstanceById(napi_env env, size_t argc, napi_value *argv)
    {
        HILOG_DEBUG("call");
        if (CheckParamNum(env, argc, ARGS_ONE, ARGS_THREE) == false) {
            return CreateJsUndefined(env);
        }
        decltype(argc) convertArgc = 0;
        int64_t formId;
        if (!ConvertFromId(env, argv[PARAM0], formId)) {
            HILOG_ERROR("Convert strFormIdList failed");
            NapiFormUtil::ThrowParamTypeError(env, "formId", "string");
            return CreateJsUndefined(env);
        }
        convertArgc++;
        bool isUnusedIncluded = false;
        if ((argc == ARGS_TWO || argc == ARGS_THREE) &&
            !AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            if (!ConvertFromJsValue(env, argv[PARAM1], isUnusedIncluded)) {
                HILOG_ERROR("Convert isUnusedIncluded failed");
                NapiFormUtil::ThrowParamTypeError(env, "isUnusedIncluded", "bool");
                return CreateJsUndefined(env);
            }
            convertArgc++;
        }
        if (argc == ARGS_THREE && !AppExecFwk::IsTypeForNapiValue(env, argv[PARAM2], napi_function)) {
            HILOG_ERROR("invalid thirdParam");
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
                    HILOG_ERROR("Get formInstance by id failed");
                    task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, *ret));
                } else {
                    task.ResolveWithNoError(env, CreateFormInstance(env, *formInstance));
                }
            };
        napi_value lastParam = (argc == convertArgc) ? nullptr : argv[convertArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleWithDefaultQos("JsFormObserver::OnGetFormInstanceById",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }
    sptr<JsFormStateObserver> formObserver_ = nullptr;

    napi_value OnRegisterClickEventCallback(
        napi_env env, size_t argc, napi_value *argv, const std::string &type)
    {
        HILOG_DEBUG("call");
        if (argc < ARGS_TWO) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2");
            return CreateJsUndefined(env);
        }
        std::string bundleName(EMPTY_BUNDLE);
        napi_value callFunc = nullptr;
        if (argc >= ARGS_THREE) {
            if (!ConvertFromJsValue(env, argv[PARAM1], bundleName)) {
                HILOG_ERROR("Convert bundleName from js fail");
                NapiFormUtil::ThrowParamTypeError(env, "bundleName", "string");
                return CreateJsUndefined(env);
            }
            if (!AppExecFwk::IsTypeForNapiValue(env, argv[PARAM2], napi_function)) {
                HILOG_ERROR("invalid thirdParam");
                NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<formInfo.RunningFormInfo>");
                return CreateJsUndefined(env);
            }
            callFunc = argv[PARAM2];
            JsFormStateObserver::GetInstance()->RegisterClickEventCallback(env, bundleName, callFunc, type);
            return CreateJsUndefined(env);
        }
        if (!AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            HILOG_ERROR("invalid secondParam");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<formInfo.RunningFormInfo>");
            return CreateJsUndefined(env);
        }
        callFunc = argv[PARAM1];
        JsFormStateObserver::GetInstance()->RegisterClickEventCallback(env, bundleName, callFunc, type);
        return CreateJsUndefined(env);
    }

    napi_value OnUnregisterClickEventCallback(
        napi_env env, size_t argc, napi_value *argv, const std::string &type)
    {
        HILOG_DEBUG("call");
        std::string bundleName(EMPTY_BUNDLE);
        napi_value callback = nullptr;
        if (argc < ARGS_ONE) {
            HILOG_ERROR("invalid argc");
            NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1");
            return CreateJsUndefined(env);
        }
        if (argc == ARGS_ONE) {
            JsFormStateObserver::GetInstance()->ClearFormClickCallbackByBundleName(type, EMPTY_BUNDLE);
            return CreateJsUndefined(env);
        }
        if (argc == ARGS_TWO) {
            if (!AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_string)) {
                HILOG_DEBUG("secondParam bundlename not string");
                JsFormStateObserver::GetInstance()->ClearFormClickCallbackByBundleName(type, EMPTY_BUNDLE);
                return CreateJsUndefined(env);
            } else if (!ConvertFromJsValue(env, argv[PARAM1], bundleName)) {
                HILOG_ERROR("Convert bundleName failed");
                return CreateJsUndefined(env);
            }
            JsFormStateObserver::GetInstance()->ClearFormClickCallbackByBundleName(type, bundleName);
            return CreateJsUndefined(env);
        }
        if (!AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_string)) {
            HILOG_DEBUG("secondParam bundlename not string");
        } else if (!ConvertFromJsValue(env, argv[PARAM1], bundleName)) {
            HILOG_ERROR("Convert bundleName failed");
            return CreateJsUndefined(env);
        }
        if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM2], napi_null) ||
            AppExecFwk::IsTypeForNapiValue(env, argv[PARAM2], napi_undefined)) {
            HILOG_DEBUG("null or undefined thirdParam");
            JsFormStateObserver::GetInstance()->ClearFormClickCallbackByBundleName(type, bundleName);
            return CreateJsUndefined(env);
        } else if (AppExecFwk::IsTypeForNapiValue(env, argv[PARAM2], napi_function)) {
            HILOG_DEBUG("The third param is callback");
            callback = argv[PARAM2];
            JsFormStateObserver::GetInstance()->ClearFormClickCallback(type, bundleName, callback);
            return CreateJsUndefined(env);
        } else {
            HILOG_ERROR("invalid thirdParam");
            NapiFormUtil::ThrowParamTypeError(env, "callback", "Callback<formInfo.RunningFormInfo>");
            return CreateJsUndefined(env);
        }
        return CreateJsUndefined(env);
    }
};

napi_value JsFormObserverInit(napi_env env, napi_value exportObj)
{
    HILOG_DEBUG("call");
    std::unique_ptr<JsFormObserver> jsFormObserver = std::make_unique<JsFormObserver>();
    napi_wrap(env, exportObj, jsFormObserver.release(), JsFormObserver::Finalizer, nullptr, nullptr);

    const char *moduleName = "JsFormObserver";
    BindNativeFunction(env, exportObj, "on", moduleName, JsFormObserver::RegisterFormObserver);
    BindNativeFunction(env, exportObj, "off", moduleName, JsFormObserver::UnregisterFormObserver);
    BindNativeFunction(env, exportObj, "getRunningFormInfos", moduleName, JsFormObserver::GetRunningFormInfos);
    BindNativeFunction(env, exportObj, "getRunningFormInfosByFilter", moduleName,
        JsFormObserver::GetFormInstancesByFilter);
    BindNativeFunction(env, exportObj, "getRunningFormInfoById", moduleName, JsFormObserver::GetFormInstanceById);

    return CreateJsUndefined(env);
}
} // namespace AbilityRuntime
} // namespace OHOS
