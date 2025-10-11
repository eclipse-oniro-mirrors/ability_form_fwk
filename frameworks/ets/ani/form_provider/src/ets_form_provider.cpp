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

#include <iostream>
#include <vector>
#include <cinttypes>
#include <regex>

#include "ani_common_want.h"
#include "js_runtime_utils.h"
#include "ani_helpers.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime::FormAniHelpers;
using namespace OHOS::AppExecFwk::Constants;

void SetFormNextRefreshTime([[maybe_unused]] ani_env *env, ani_string formId, ani_int minute, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, formId)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID), nullptr);
        return;
    }
    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    auto ret = FormMgr::GetInstance().SetNextRefreshTime(formIdNum, minute);
    if (ret != ERR_OK) {
        HILOG_ERROR("SetNextRefreshTime failed");
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }
    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void UpdateForm([[maybe_unused]] ani_env *env, ani_string formId, ani_string dataObjStr, ani_object callback,
    ani_object proxies)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, formId) || IsRefUndefined(env, dataObjStr)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID), nullptr);
        return;
    }

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    auto formProviderData = AppExecFwk::FormProviderData(ANIUtils_ANIStringToStdString(env, dataObjStr));
    std::vector<AppExecFwk::FormDataProxy> formDataProxies;
    if (!IsRefUndefined(env, proxies)) {
        ExtractProxyVector(env, formDataProxies, proxies);
    }
    auto ret = FormMgr::GetInstance().UpdateForm(formIdNum, formProviderData, formDataProxies);
    if (ret != ERR_OK) {
        HILOG_ERROR("UpdateForm failed. Return code: %{public}d", static_cast<int>(ret));
    }
    InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
    HILOG_DEBUG("End");
}

void GetFormsInfo([[maybe_unused]] ani_env *env, ani_object callback, ani_object filter)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);
    FormInfoFilter formInfoFilter;
    if (!IsRefUndefined(env, filter)) {
        ani_ref moduleName{};
        auto ret = env->Object_GetPropertyByName_Ref(filter, "moduleName", &moduleName);
        if (ret != ANI_OK) {
            HILOG_ERROR("moduleName Object_GetPropertyByName_Ref failed");
            InvokeAsyncWithBusinessError(env, callback, ERR_FORM_EXTERNAL_PARAM_INVALID, nullptr);
            return;
        }
        formInfoFilter.moduleName = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(moduleName));
    }
    
    std::vector<FormInfo> formInfos;
    auto ret = FormMgr::GetInstance().GetFormsInfo(formInfoFilter, formInfos);
    if (ret != ERR_OK) {
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    ani_object formInfosArray = GetANIArray(env, formInfos.size());

    ani_size index = 0;
    for (auto &formInfo : formInfos) {
        ani_object formInfoAni = CreateANIObject(env, FORM_INFO_INNER_CLASS_NAME);
        SetFormInfoFields(env, formInfoAni, formInfo);
        ani_status status = env->Object_CallMethodByName_Void(formInfosArray, ANI_SETTER_MARKER,
            "iC{std.core.Object}:", index, formInfoAni);
        if (status != ANI_OK) {
            HILOG_ERROR("Object_CallMethodByName_Void failed, error code: %{public}d", static_cast<int>(status));
            InvokeAsyncWithBusinessError(env, callback, ERR_APPEXECFWK_FORM_COMMON_CODE, nullptr);
            return;
        }
        index++;
    }
    
    InvokeAsyncWithBusinessError(env, callback, ret, formInfosArray);
    HILOG_DEBUG("End");
}

void OpenFormEditAbility([[maybe_unused]] ani_env *env, ani_string abilityName,
    ani_string formId, ani_boolean isMainPage)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, abilityName);
    CheckIfRefValidOrThrow(env, formId);

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    std::string stdAbilityName = ANIUtils_ANIStringToStdString(env, abilityName);
    if (stdAbilityName.empty()) {
        HILOG_ERROR("abilityName ANIUtils_ANIStringToStdString failed");
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    auto ret = FormMgr::GetInstance().OpenFormEditAbility(stdAbilityName, formIdNum, isMainPage);
    if (ret != ERR_OK) {
        HILOG_ERROR("OpenFormEditAbility failed, error code: %{public}d", ret);
        PrepareExceptionAndThrow(env, ret);
    }

    HILOG_DEBUG("End");
}

void OpenFormManager([[maybe_unused]] ani_env *env, ani_object wantObj)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, wantObj);
    Want want;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        HILOG_ERROR("want parsing failed");
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
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

    auto ret = FormMgr::GetInstance().StartAbilityByFms(want);
    HILOG_INFO("OpenFormManager StartAbilityByFms return code: %{public}d", static_cast<int>(ret));
    if (ret != ERR_OK) {
        HILOG_ERROR("OpenFormManager failed, error code: %{public}d", static_cast<int>(ret));
        PrepareExceptionAndThrow(env, ret);
        return;
    }

    HILOG_DEBUG("End");
}

void IsRequestPublishFormSupported(ani_env *env, ani_object callback)
{
    HILOG_INFO("Call");
    CheckEnvOrThrow(env);
    bool supported = FormMgr::GetInstance().IsRequestPublishFormSupported();
    HILOG_INFO("IsRequestPublishFormSupported End, supported: %{public}d", supported);
    ani_object callbackArg = CreateBool(env, supported);
    InvokeAsyncWithBusinessError(env, callback, ERR_OK, callbackArg);
}

void RequestPublishForm(ani_env *env, ani_object wantObj, ani_object callback, ani_boolean withFormBindingData,
    ani_string dataObjStr, ani_object proxies)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, wantObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID), nullptr);
        return;
    }

    ani_string formIdAniStr = nullptr;
    auto formProviderData = std::make_unique<FormProviderData>();
    if (withFormBindingData) {
        std::string formProviderDataStr = ANIUtils_ANIStringToStdString(env, dataObjStr);
        formProviderData->SetDataString(formProviderDataStr);
        formProviderData->ParseImagesData();
    }

    std::vector<AppExecFwk::FormDataProxy> formDataProxies;
    if (!IsRefUndefined(env, proxies)) {
        ExtractProxyVector(env, formDataProxies, proxies);
    }

    Want want;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        HILOG_ERROR("UnwrapWant failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID), nullptr);
        return;
    }

    int64_t formId;
    int32_t ret = FormMgr::GetInstance().RequestPublishForm(want, withFormBindingData, formProviderData, formId,
        formDataProxies);
    if (ret != ERR_OK) {
        HILOG_ERROR("RequestPublishForm failed with error: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    std::string formIdStr = std::to_string(formId);
    env->String_NewUTF8(formIdStr.c_str(), formIdStr.size(), &formIdAniStr);
    HILOG_INFO("End");
    InvokeAsyncWithBusinessError(env, callback, ret, formIdAniStr); // crash
}

void GetPublishedFormInfos([[maybe_unused]] ani_env *env, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);

    std::vector<RunningFormInfo> formInfos;
    auto ret = FormMgr::GetInstance().GetPublishedFormInfos(formInfos);
    if (ret != ERR_OK) {
        HILOG_ERROR("GetPublishedFormInfos failed, error code:  %{public}d", static_cast<int>(ret));
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    ani_object formInfosArray = GetANIArray(env, formInfos.size());
    ani_size index = 0;
    for (auto &formInfo : formInfos) {
        ani_object runningFormInfoAni = CreateANIObject(env, RUNNING_FORM_INFO_INNER_CLASS_NAME);
        SetRunningFormInfoFields(env, runningFormInfoAni, formInfo);
        ani_status status = env->Object_CallMethodByName_Void(
            formInfosArray, ANI_SETTER_MARKER, "iC{std.core.Object}:", index, runningFormInfoAni);
        if (status != ANI_OK) {
            HILOG_ERROR("Object_CallMethodByName_Void failed, error code: %{public}d", static_cast<int>(status));
            InvokeAsyncWithBusinessError(env, callback, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID),
                nullptr);
            break;
        }
        index++;
    }
    InvokeAsyncWithBusinessError(env, callback, ret, formInfosArray);
    HILOG_DEBUG("End");
}

void GetPublishedFormInfoById(ani_env* env, ani_string formId, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    
    if (IsRefUndefined(env, formId)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID), nullptr);
        return;
    }

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    RunningFormInfo formInfo;
    auto ret = FormMgr::GetInstance().GetPublishedFormInfoById(formIdNum, formInfo);
    if (ret != ERR_OK) {
        HILOG_ERROR("GetPublishedFormInfoById failed, error code: %{public}d", static_cast<int>(ret));
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    ani_object formInfoObj = CreateANIObject(env, RUNNING_FORM_INFO_INNER_CLASS_NAME);
    SetRunningFormInfoFields(env, formInfoObj, formInfo);
    InvokeAsyncWithBusinessError(env, callback, ret, formInfoObj);

    HILOG_DEBUG("End");
}

std::vector<ani_native_function> GetBindMethods()
{
    std::vector methods = {
        ani_native_function{"setFormNextRefreshTimeInner",
            "C{std.core.String}iC{@ohos.app.form.formProvider.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(SetFormNextRefreshTime)},
        ani_native_function{"updateFormInner",
            "C{std.core.String}C{std.core.String}C{@ohos.app.form.formProvider.AsyncCallbackWrapper}C{escompat.Array}:",
            reinterpret_cast<void *>(UpdateForm)},
        ani_native_function{"getFormsInfoInner",
            "C{@ohos.app.form.formProvider.AsyncCallbackWrapper}C{@ohos.app.form.formInfo.formInfo.FormInfoFilter}:",
            reinterpret_cast<void *>(GetFormsInfo)},
        ani_native_function{"openFormEditAbilityInner", "C{std.core.String}C{std.core.String}z:",
            reinterpret_cast<void *>(OpenFormEditAbility)},
        ani_native_function{"openFormManagerInner", "C{@ohos.app.ability.Want.Want}:",
            reinterpret_cast<void *>(OpenFormManager)},
        ani_native_function{"requestPublishFormInner",
            "C{@ohos.app.ability.Want.Want}"
            "C{@ohos.app.form.formProvider.AsyncCallbackWrapper}zC{std.core.String}C{escompat.Array}:",
            reinterpret_cast<void *>(RequestPublishForm)},
        ani_native_function{"isRequestPublishFormSupportedInner",
            "C{@ohos.app.form.formProvider.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(IsRequestPublishFormSupported)},
        ani_native_function{"getPublishedFormInfosInner", "C{@ohos.app.form.formProvider.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(GetPublishedFormInfos)},
        ani_native_function{"getPublishedFormInfoByIdInner",
            "C{std.core.String}C{@ohos.app.form.formProvider.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(GetPublishedFormInfoById)},
    };
    return methods;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    HILOG_INFO("Call ANI_Constructor");
    if (vm == nullptr || result == nullptr) {
        HILOG_ERROR("vm or result is nullptr");
        return ANI_ERROR;
    }

    ani_env *env = nullptr;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        HILOG_ERROR("Unsupported ANI_VERSION_1");
        return ANI_OUT_OF_REF;
    }

    const char *spaceName = "@ohos.app.form.formProvider.formProvider";
    ani_namespace spc;

    ani_status ret = env->FindNamespace(spaceName, &spc);
    if (ret != ANI_OK) {
        HILOG_ERROR("Not found %{public}s, ret = %{public}d", spaceName, static_cast<int>(ret));
        return ANI_NOT_FOUND;
    }

    std::vector methods = GetBindMethods();
    auto bindRet = env->Namespace_BindNativeFunctions(spc, methods.data(), methods.size());
    if (bindRet != ANI_OK) {
        HILOG_ERROR("Cannot bind native methods to %{public}s, return code is: %{public}" PRId32,
            spaceName, static_cast<int>(bindRet));
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
}  // namespace AbilityRuntime
}  // namespace OHOS
