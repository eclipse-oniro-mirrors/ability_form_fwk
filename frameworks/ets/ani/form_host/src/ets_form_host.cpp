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

#include "ani.h"
#include "ani_common_want.h"
#include "ani_helpers.h"
#include "fms_log_wrapper.h"
#include "form_mgr.h"
#include "form_host_client.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime::FormAniHelpers;

bool CheckCallerIsSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
}

ani_object AddForm([[maybe_unused]] ani_env *env, ani_object wantObject)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);

    Want want;
    bool result = UnwrapWant(env, wantObject, want);
    if (!result) {
        HILOG_ERROR("want parsing error");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return nullptr;
    }

    RunningFormInfo runningFormInfo;
    auto ret = FormMgr::GetInstance().CreateForm(want, runningFormInfo);
    if (ret != ERR_OK) {
        HILOG_ERROR("AddForm failed, error code: %{public}d", static_cast<int>(ret));
        PrepareExceptionAndThrow(env, ret);
        return nullptr;
    }

    ani_object runningFormInfoObject = CreateANIObject(env, RUNNING_FORM_INFO_INNER_CLASS_NAME);
    CheckIfRefValidOrThrow(env, runningFormInfoObject);
    SetRunningFormInfoFields(env, runningFormInfoObject, runningFormInfo);

    if (!runningFormInfoObject) {
        HILOG_ERROR("RunningFormInfo parsing error");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return nullptr;
    }
    HILOG_DEBUG("End");

    return runningFormInfoObject;
}

void DeleteForm([[maybe_unused]] ani_env *env, ani_string formId)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, formId);

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    HILOG_INFO("formId: %{public}" PRId64, formIdNum);

    auto ret = FormMgr::GetInstance().DeleteForm(formIdNum, FormHostClient::GetInstance());
    if (ret != ERR_OK) {
        HILOG_ERROR("DeleteForm failed, error code: %{public}d", static_cast<int>(ret));
        PrepareExceptionAndThrow(env, ret);
        return;
    }
    HILOG_DEBUG("End");
}

ani_int DeleteInvalidForms([[maybe_unused]] ani_env *env, ani_object arrayObj)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, arrayObj);

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return 0;
    }

    int32_t num = 0;
    auto ret = FormMgr::GetInstance().DeleteInvalidForms(formIds, FormHostClient::GetInstance(), num);
    if (ret != ERR_OK) {
        HILOG_ERROR("DeleteInvalidForm failed error code : %{public}d", static_cast<int>(ret));
        PrepareExceptionAndThrow(env, ret);
    }
    HILOG_DEBUG("End");
    return num;
}

ani_object GetFormsInfoByFilter([[maybe_unused]] ani_env *env, ani_object filterObj)
{
    HILOG_DEBUG("Call");
    AppExecFwk::FormInfoFilter filter;
    if (!GetStringProperty(env, filterObj, "bundleName", filter.bundleName)) {
        HILOG_ERROR("Cannot get bundle name from filter");
    }
    if (!GetStringProperty(env, filterObj, "moduleName", filter.moduleName)) {
        HILOG_ERROR("Cannot get bundle name from filter");
    }

    ani_array supportDimensionAni;
    if (env->Object_GetPropertyByName_Ref(filterObj, "supportedDimensions",
        reinterpret_cast<ani_ref*>(&supportDimensionAni))) {
        HILOG_ERROR("Cannot get support Dimension Ani");
    }
    ani_boolean isUndefined = true;
    if (env->Reference_IsUndefined(supportDimensionAni, &isUndefined) != ANI_OK) {
        HILOG_ERROR("Reference_IsUndefined failed");
    }
    if (!isUndefined) {
        AniParseIntArray(env, supportDimensionAni, filter.supportDimensions);
    }

    ani_array supportedShapes;
    if (env->Object_GetPropertyByName_Ref(filterObj, "supportedShapes", reinterpret_cast<ani_ref*>(&supportedShapes))) {
        HILOG_ERROR("Cannot get support Dimension Ani");
    }
    isUndefined = true;
    if (env->Reference_IsUndefined(supportedShapes, &isUndefined) != ANI_OK) {
        HILOG_ERROR("Reference_IsUndefined failed, status");
    }
    if (!isUndefined) {
        AniParseIntArray(env, supportedShapes, filter.supportShapes);
    }

    std::vector<FormInfo> formInfos;
    auto ret = FormMgr::GetInstance().GetFormsInfoByFilter(filter, formInfos);
    if (ret != ERR_OK) {
        HILOG_ERROR("Failed get formInfo with filter");
        PrepareExceptionAndThrow(env, ret);
    }
    HILOG_DEBUG("End");
    return CreateFormInfoAniArrayFromVec(env, formInfos);
}

ani_object GetAllFormsInfo([[maybe_unused]] ani_env *env)
{
    HILOG_DEBUG("Call");
    std::vector<FormInfo> allInfos;
    auto ret = FormMgr::GetInstance().GetAllFormsInfo(allInfos);
    if (ret != ERR_OK) {
        HILOG_ERROR("Error when get allformInfos");
        PrepareExceptionAndThrow(env, ret);
    }
    HILOG_DEBUG("End");
    return CreateFormInfoAniArrayFromVec(env, allInfos);
}

ani_object GetFormsInfo([[maybe_unused]] ani_env *env, ani_string bundleNameStr, ani_string moduleNameStr)
{
    HILOG_DEBUG("Call");
    std::string bundleName = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(bundleNameStr));
    std::string moduleName = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(moduleNameStr));
    std::vector<FormInfo> formInfos;
    int retCode;
    if (moduleName.empty()) {
        retCode = FormMgr::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
    } else {
        retCode = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
    }
    if (retCode != ERR_OK) {
        HILOG_ERROR("call error when get allformInfos");
        PrepareExceptionAndThrow(env, retCode);
    }
    HILOG_DEBUG("End");
    return CreateFormInfoAniArrayFromVec(env, formInfos);
}

void IsSystemReady([[maybe_unused]] ani_env *env)
{
    HILOG_DEBUG("Call");
    if (!CheckCallerIsSystemApp()) {
        HILOG_ERROR("caller is not system-app");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_NOT_SYSTEM_APP));
        return;
    }

    auto ret = FormMgr::GetInstance().CheckFMSReady() ? 0 : 1;
    if (ret != ERR_OK) {
        HILOG_ERROR("CheckFMSReady not ready");
        PrepareExceptionAndThrow(env, ret);
    }
    HILOG_DEBUG("End");
}

void NotifyFormsEnableUpdate([[maybe_unused]] ani_env *env, ani_object arrayObj, ani_boolean isEnabled)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, arrayObj);

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    auto ret = FormMgr::GetInstance().NotifyFormsEnableUpdate(formIds, isEnabled, FormHostClient::GetInstance());
    if (ret != ERR_OK) {
        HILOG_ERROR("NotifyFormsEnableUpdate failed, error code: %{public}d", ret);
        PrepareExceptionAndThrow(env, ret);
        return;
    }

    HILOG_DEBUG("End");
}

void NotifyFormsVisible([[maybe_unused]] ani_env *env, ani_object arrayObj, ani_boolean isVisible)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("Invalid formIdList");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    auto ret = FormMgr::GetInstance().NotifyFormsVisible(formIds, isVisible, FormHostClient::GetInstance());
    if (ret != ERR_OK) {
        HILOG_ERROR("NotifyFormsVisible failed, error code: %{public}d", ret);
        PrepareExceptionAndThrow(env, ret);
        return;
    }

    HILOG_DEBUG("End");
}

void SetEnableFormUpdate([[maybe_unused]] ani_env *env, ani_object arrayObj, ani_boolean isEnable)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, arrayObj);

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    auto ret = FormMgr::GetInstance().LifecycleUpdate(formIds, FormHostClient::GetInstance(), isEnable);
    if (ret != ERR_OK) {
        HILOG_ERROR("LifecycleUpdate failed, error code: %{public}d", ret);
        PrepareExceptionAndThrow(env, ret);
    }
    HILOG_DEBUG("End");
}

void ReleaseForm([[maybe_unused]] ani_env *env, ani_string formId, ani_boolean isReleaseCache)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, formId);

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    auto ret = FormMgr::GetInstance().ReleaseForm(formIdNum, FormHostClient::GetInstance(), isReleaseCache);
    if (ret != ERR_OK) {
        HILOG_ERROR("releaseform failed, error code: %{public}d", ret);
        PrepareExceptionAndThrow(env, ret);
        return;
    }
    HILOG_DEBUG("End");
}

void RequestForm([[maybe_unused]] ani_env *env, ani_string formId)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, formId);

    Want want;
    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    auto ret = FormMgr::GetInstance().RequestForm(formIdNum, FormHostClient::GetInstance(), want);
    if (ret != ERR_OK) {
        HILOG_ERROR("requestform failed error code: %{public}d", ret);
        PrepareExceptionAndThrow(env, ret);
        return;
    }
    HILOG_DEBUG("End");
}

void RequestFormWithParams([[maybe_unused]] ani_env *env, ani_string formId, ani_object wantParamsObject)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, formId);
    CheckIfRefValidOrThrow(env, wantParamsObject);

    Want want;
    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    AAFwk::WantParams wantParams;
    if (UnwrapWantParams(env, wantParamsObject, wantParams)) {
        want.SetParams(wantParams);
    }

    auto ret = FormMgr::GetInstance().RequestForm(formIdNum, FormHostClient::GetInstance(), want);
    if (ret != ERR_OK) {
        HILOG_ERROR("requestformwithparams failed error code: %{public}d", ret);
        PrepareExceptionAndThrow(env, ret);
        return;
    }
    HILOG_DEBUG("End");
}

void CastToNormalForm([[maybe_unused]] ani_env *env, ani_string formId)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, formId);

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    auto ret = FormMgr::GetInstance().CastTempForm(formIdNum, FormHostClient::GetInstance());
    if (ret != ERR_OK) {
        HILOG_ERROR("castToNormal form failed error code: %{public}d", ret);
        PrepareExceptionAndThrow(env, ret);
        return;
    }

    HILOG_DEBUG("End");
}

void NotifyVisibleForms([[maybe_unused]] ani_env *env, ani_object arrayObj)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, arrayObj);

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    auto ret = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, FormHostClient::GetInstance(),
        Constants::FORM_VISIBLE);
    if (ret != ERR_OK) {
        HILOG_ERROR("NotifyVisibleForms form failed error code: %{public}d", ret);
        PrepareExceptionAndThrow(env, ret);
        return;
    }

    HILOG_DEBUG("End");
}

void NotifyInvisibleForms([[maybe_unused]] ani_env *env, ani_object arrayObj)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, arrayObj);

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    auto ret = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, FormHostClient::GetInstance(),
        Constants::FORM_INVISIBLE);
    if (ret != ERR_OK) {
        HILOG_ERROR("NotifyInvisibleForms form failed error code: %{public}d", ret);
        PrepareExceptionAndThrow(env, ret);
        return;
    }

    HILOG_DEBUG("End");
}

void UpdateFormLocation(ani_env *env, ani_string formId, ani_object formLocation)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, formLocation);

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    ani_int formLocationValue = 0;
    ani_status formLocationValueStatus = GetEnumValueInt(env, formLocation, formLocationValue);
    if (formLocationValueStatus != ANI_OK) {
        HILOG_ERROR("enum value could not received %{public}d", formLocationValueStatus);
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    auto ret = FormMgr::GetInstance().UpdateFormLocation(formIdNum, static_cast<int32_t>(formLocationValue));
    if (ret != ERR_OK) {
        HILOG_ERROR("UpdateFormLocation failed, error code: %{public}d", static_cast<int>(ret));
        PrepareExceptionAndThrow(env, ret);
        return;
    }

    HILOG_DEBUG("End");
}

void SetFormsRecyclable([[maybe_unused]] ani_env *env, ani_object arrayObj)
{
    HILOG_DEBUG("Call");
    
    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, arrayObj);

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    auto ret = FormMgr::GetInstance().SetFormsRecyclable(formIds);
    if (ret != ERR_OK) {
        HILOG_ERROR("SetFormsRecyclable failed, error code: %{public}d", static_cast<int>(ret));
        PrepareExceptionAndThrow(env, ret);
        return;
    }

    HILOG_DEBUG("End");
}

void RecycleForms([[maybe_unused]] ani_env *env, ani_object arrayObj)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, arrayObj);

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    Want want;
    auto ret = FormMgr::GetInstance().RecycleForms(formIds, want);
    if (ret != ERR_OK) {
        HILOG_ERROR("RecycleForms failed, error code: %{public}d", ret);
        PrepareExceptionAndThrow(env, ret);
        return;
    }

    HILOG_DEBUG("End");
}

void RecoverForms([[maybe_unused]] ani_env *env, ani_object arrayObj)
{
    HILOG_DEBUG("Call");
    
    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, arrayObj);

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    Want want;
    auto ret = FormMgr::GetInstance().RecoverForms(formIds, want);
    if (ret != ERR_OK) {
        HILOG_ERROR("RecoverForms failed, error code: %{public}d", static_cast<int>(ret));
        PrepareExceptionAndThrow(env, ret);
        return;
    }

    HILOG_DEBUG("End");
}

std::vector<ani_native_function> GetBindMethods()
{
    std::vector methods = {
        ani_native_function {
            "addForm_inner", "C{@ohos.app.ability.Want.Want}:C{@ohos.app.form.formInfo.formInfo.RunningFormInfo}",
            reinterpret_cast<void *>(AddForm)},
        ani_native_function {
            "deleteForm_inner", "C{std.core.String}:", reinterpret_cast<void *>(DeleteForm)},
        ani_native_function {
            "deleteInvalidForms_inner", "C{std.core.Array}:i", reinterpret_cast<void *>(DeleteInvalidForms)},
        ani_native_function {
            "getAllFormsInfo_inner", ":C{std.core.Array}", reinterpret_cast<void *>(GetAllFormsInfo)},
        ani_native_function {
            "getFormsInfo_inner", "C{std.core.String}C{std.core.String}:C{std.core.Array}",
            reinterpret_cast<void *>(GetFormsInfo)},
        ani_native_function {
            "getFormsInfoByFilter_inner", "C{@ohos.app.form.formInfo.formInfo.FormInfoFilter}:C{std.core.Array}",
            reinterpret_cast<void *>(GetFormsInfoByFilter)},
        ani_native_function {"isSystemReady_inner", ":", reinterpret_cast<void *>(IsSystemReady)},
        ani_native_function {
            "releaseForm_inner", "C{std.core.String}z:", reinterpret_cast<void *>(ReleaseForm)},
        ani_native_function {
            "requestForm_inner", "C{std.core.String}:", reinterpret_cast<void *>(RequestForm)},
        ani_native_function {
            "requestFormWithParams_inner", "C{std.core.String}C{std.core.Record}:",
            reinterpret_cast<void *>(RequestFormWithParams)},
        ani_native_function {
            "castToNormalForm_inner", "C{std.core.String}:", reinterpret_cast<void *>(CastToNormalForm)},
        ani_native_function {
            "notifyVisibleForms_inner", "C{std.core.Array}:", reinterpret_cast<void *>(NotifyVisibleForms)},
        ani_native_function {
            "notifyInvisibleForms_inner", "C{std.core.Array}:", reinterpret_cast<void *>(NotifyInvisibleForms)},
        ani_native_function {
            "setFormUpdate_inner", "C{std.core.Array}z:", reinterpret_cast<void *>(SetEnableFormUpdate)},
        ani_native_function {
            "updateFormLocation", "C{std.core.String}C{@ohos.app.form.formInfo.formInfo.FormLocation}:",
            reinterpret_cast<void *>(UpdateFormLocation)},
        ani_native_function {
            "setFormsRecyclable_inner", "C{std.core.Array}:", reinterpret_cast<void *>(SetFormsRecyclable)},
        ani_native_function {
            "recycleForms_inner", "C{std.core.Array}:", reinterpret_cast<void *>(RecycleForms)},
        ani_native_function {
            "recoverForms_inner", "C{std.core.Array}:", reinterpret_cast<void *>(RecoverForms)},
        ani_native_function {
            "notifyFormsEnableUpdate_inner", "C{std.core.Array}z:",
            reinterpret_cast<void *>(NotifyFormsEnableUpdate)},
        ani_native_function {
            "notifyFormsVisible_inner", "C{std.core.Array}z:", reinterpret_cast<void *>(NotifyFormsVisible)},
    };
    return methods;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    HILOG_DEBUG("Call");
    if (vm == nullptr || result == nullptr) {
        HILOG_ERROR("vm or result is nullptr");
        return ANI_ERROR;
    }

    ani_env *env = nullptr;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        HILOG_ERROR("Unsupported ANI_VERSION_1");
        return ANI_OUT_OF_REF;
    }

    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return ANI_ERROR;
    }
    HILOG_INFO("before find namespace");
    const char *spaceName = "@ohos.app.form.formHost.formHost";
    ani_namespace spc;

    ani_status ret = env->FindNamespace(spaceName, &spc);
    if (ret != ANI_OK) {
        HILOG_ERROR("Not found %{public}s, ret = %{public}d", spaceName, ret);
        return ANI_NOT_FOUND;
    }

    std::vector methods = GetBindMethods();
    if (env->Namespace_BindNativeFunctions(spc, methods.data(), methods.size()) != ANI_OK) {
        HILOG_ERROR("Cannot bind native methods to %{public}s ", spaceName);
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    HILOG_DEBUG("End");
    return ANI_OK;
}
}
}
}