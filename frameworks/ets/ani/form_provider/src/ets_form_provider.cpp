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
#include "ani_base_context.h"
#include "ani_common_want.h"
#include "js_runtime_utils.h"
#include "ani_helpers.h"
#include "ani_form_common_util.h"
#include "ani_form_error_util.h"
#include "fms_log_wrapper.h"
#include "form_mgr.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime::FormAniHelpers;
using namespace OHOS::AppExecFwk::Constants;
namespace {
constexpr const char* FORM_RECT_INNER = "L@ohos/app/form/formInfo/formInfo/RectInner;";
constexpr const char* PROVIDER_CLASSNAME_ASYNC_CALLBACK_WRAPPER = "L@ohos/app/form/formProvider/AsyncCallbackWrapper;";
constexpr const char* PROVIDER_RECT_LEFT = "left";
constexpr const char* PROVIDER_RECT_TOP = "top";
constexpr const char* PROVIDER_RECT_WIDTH = "width";
constexpr const char* PROVIDER_RECT_HEIGHT = "height";
constexpr const char* PROVIDER_FORMINFO_MODULENAME = "moduleName";
constexpr const char* PROVIDER_SET_SIGNATURE = "iC{std.core.Object}:";
constexpr const char* PROVIDER_FORMOVERFLOWINFO_AREA = "area";
constexpr const char* PROVIDER_FORMOVERFLOWINFO_DURATION = "duration";
constexpr const char* PROVIDER_FORMOVERFLOWINFO_USEDEFAULTANIMATION = "useDefaultAnimation";
constexpr const char* PROVIDER_CLASS_CONSTRUCTOR = "<ctor>";
constexpr const char* PROVIDER_SIGNATURE_VOID_VOID = ":V";

enum class ActivationState : int32_t {
    DEACTIVATED = 0,
    ACTIVATED = 1
};

bool CheckUIAbilityContext(ani_env *env, ani_object etsContext)
{
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, etsContext);
    if (context == nullptr) {
        HILOG_ERROR("Null context");
        EtsFormErrorUtil::ThrowParamError(env, "Parse param context failed, must not be nullptr");
        return false;
    }
    auto uiAbilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (uiAbilityContext == nullptr) {
        HILOG_ERROR("Null UIAbilityContext");
        EtsFormErrorUtil::ThrowParamError(env, "Parse param context failed, must be UIAbilityContext");
        return false;
    }
    return true;
}
}

int ConvertStringToInt(const std::string &strInfo)
{
    return static_cast<int>(strtoll(strInfo.c_str(), nullptr, FormAniHelpers::BASE_REQUEST_CODE_NUM));
}

void SetFormNextRefreshTime([[maybe_unused]] ani_env *env, ani_string formId, ani_int minute, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, formId)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
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
            static_cast<int>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
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
        auto ret = env->Object_GetPropertyByName_Ref(filter, PROVIDER_FORMINFO_MODULENAME, &moduleName);
        if (ret != ANI_OK) {
            HILOG_ERROR("moduleName Object_GetPropertyByName_Ref failed");
            InvokeAsyncWithBusinessError(env, callback, ERR_APPEXECFWK_FORM_INVALID_PARAM, nullptr);
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
            PROVIDER_SET_SIGNATURE, index, formInfoAni);
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
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_APPEXECFWK_FORM_INVALID_PARAM));
        return;
    }

    auto ret = FormMgr::GetInstance().OpenFormEditAbility(stdAbilityName, formIdNum, isMainPage);
    if (ret != ERR_OK) {
        HILOG_ERROR("OpenFormEditAbility failed, error code: %{public}d", ret);
        PrepareExceptionAndThrow(env, ret);
    }

    HILOG_DEBUG("End");
}

void CloseFormEditAbility(ani_env *env, ani_boolean isMainPage)
{
    HILOG_DEBUG("Call");

    CheckEnvOrThrow(env);

    auto ret = FormMgr::GetInstance().CloseFormEditAbility(isMainPage);
    if (ret != ERR_OK) {
        HILOG_ERROR("CloseFormEditAbility failed, error code: %{public}d", ret);
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
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_APPEXECFWK_FORM_INVALID_PARAM));
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

ani_object WrapRectInner(ani_env *env, ani_object rectobject,
    const AppExecFwk::Rect &rect)
{
    HILOG_DEBUG("call");
    if (env == nullptr || rectobject == nullptr) {
        HILOG_ERROR("env is nullptr");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    status = env->Object_SetPropertyByName_Double(rectobject, PROVIDER_RECT_LEFT, rect.left);
    if (status != ANI_OK) {
        HILOG_ERROR("set exitCode failed status: %{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Double(rectobject, PROVIDER_RECT_TOP, rect.top);
    if (status != ANI_OK) {
        HILOG_ERROR("set exitCode failed status: %{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Double(rectobject, PROVIDER_RECT_WIDTH, rect.width);
    if (status != ANI_OK) {
        HILOG_ERROR("set exitCode failed status: %{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Double(rectobject, PROVIDER_RECT_HEIGHT, rect.height);
    if (status != ANI_OK) {
        HILOG_ERROR("set exitCode failed status: %{public}d", status);
        return nullptr;
    }
    return rectobject;
}

bool ConvertFormOverflowInfo(ani_env *env, ani_object aniOverflowInfo, AppExecFwk::OverflowInfo* overflowInfo)
{
    HILOG_INFO("call");
    if (env == nullptr || aniOverflowInfo == nullptr) {
        HILOG_ERROR("env or aniOverflowInfo is nullptr");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_ref areaRef = nullptr;
    status = env->Object_GetPropertyByName_Ref(aniOverflowInfo, PROVIDER_FORMOVERFLOWINFO_AREA, &areaRef);
    if (ANI_OK != status) {
        HILOG_ERROR("get area failed status: %{public}d", status);
        return false;
    }
    double leftValue = 0.0;
    double topValue = 0.0;
    double widthValue = 0.0;
    double heightValue = 0.0;
    if (GetPropertyDoubleObject(env, static_cast<ani_object>(areaRef), PROVIDER_RECT_LEFT, leftValue) &&
        GetPropertyDoubleObject(env, static_cast<ani_object>(areaRef), PROVIDER_RECT_TOP, topValue) &&
        GetPropertyDoubleObject(env, static_cast<ani_object>(areaRef), PROVIDER_RECT_WIDTH, widthValue) &&
        GetPropertyDoubleObject(env, static_cast<ani_object>(areaRef), PROVIDER_RECT_HEIGHT, heightValue)) {
        overflowInfo->area.left = leftValue;
        overflowInfo->area.top = topValue;
        overflowInfo->area.width = widthValue;
        overflowInfo->area.height = heightValue;
    } else {
        HILOG_ERROR("convert area failed");
        return false;
    }

    int32_t durationValue = -1;
    if (GetPropertyIntObject(env, aniOverflowInfo, PROVIDER_FORMOVERFLOWINFO_DURATION, durationValue)) {
        overflowInfo->duration = durationValue;
    } else {
        HILOG_ERROR("convert duration failed");
        return false;
    }

    bool defaultAnimation = true;
    if (GetPropertyBoolByName(env, aniOverflowInfo, PROVIDER_FORMOVERFLOWINFO_USEDEFAULTANIMATION, defaultAnimation)) {
        overflowInfo->useDefaultAnimation = defaultAnimation;
    } else {
        HILOG_ERROR("convert useDefaultAnimation failed");
    }
    HILOG_INFO("ConvertFormOverflowInfo rect: %{public}f, %{public}f, %{public}f, %{public}f",
        overflowInfo->area.left, overflowInfo->area.top, overflowInfo->area.width, overflowInfo->area.height);
    return true;
}

ani_object CreateFormRect(ani_env *env, const AppExecFwk::Rect &rect)
{
    HILOG_DEBUG("call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return nullptr;
    }
    ani_class rectClass = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object rectobject = nullptr;
    if ((status = env->FindClass(FORM_RECT_INNER, &rectClass)) != ANI_OK || rectClass == nullptr) {
        HILOG_ERROR("FindClass status: %{public}d or null rectClass", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(rectClass, PROVIDER_CLASS_CONSTRUCTOR,
        PROVIDER_SIGNATURE_VOID_VOID, &method)) != ANI_OK || method == nullptr) {
        HILOG_ERROR("Class_FindMethod status: %{public}d or null method", status);
        return nullptr;
    }
    if ((status = env->Object_New(rectClass, method, &rectobject)) != ANI_OK || rectobject == nullptr) {
        HILOG_ERROR("Object_New status: %{public}d or null rectobject", status);
        return nullptr;
    }
    return WrapRectInner(env, rectobject, rect);
}


void GetFormRect(ani_env *env, ani_string formId, ani_object callback)
{
    HILOG_INFO("call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    std::string stdFormId = "";
    if (!GetStdString(env, formId, stdFormId)) {
        HILOG_ERROR("GetStdString failed");
        EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
        return;
    }
    int64_t formIdInt = -1;
    if (!FormAniHelpers::ConvertStringToInt64(stdFormId, formIdInt)) {
        HILOG_ERROR("formId ConvertStringToInt64 failed");
        EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
        return;
    }
    AppExecFwk::Rect item;
    ErrCode ret = FormMgr::GetInstance().GetFormRect(formIdInt, item);
    if (ret != ERR_OK) {
        HILOG_INFO("OnGetFormRect failed, code:%{public}d", ret);
        AsyncCallback(env, PROVIDER_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
            callback, EtsFormErrorUtil::CreateErrorByInternalErrorCode(env, ret), nullptr);
        return;
    }
    ani_object rectObj = CreateFormRect(env, item);
    if (rectObj == nullptr) {
        HILOG_ERROR("OnGetFormRect CreateFormRect failed");
        AsyncCallback(env, PROVIDER_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
            callback, EtsFormErrorUtil::CreateErrorByInternalErrorCode(env, ret), nullptr);
        return;
    }
    AsyncCallback(env, PROVIDER_CLASSNAME_ASYNC_CALLBACK_WRAPPER, callback, EtsFormErrorUtil::CreateError(env, ret),
        rectObj);
    return;
}

void CancelOverflow(ani_env *env, ani_string formId, ani_object callback)
{
    HILOG_INFO("call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    std::string stdFormId = "";
    if (!GetStdString(env, formId, stdFormId)) {
        HILOG_ERROR("GetStdString failed");
        EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
        return;
    }
    int64_t formIdInt = -1;
    if (!FormAniHelpers::ConvertStringToInt64(stdFormId, formIdInt)) {
        HILOG_ERROR("formId ConvertStringToInt64 failed");
        EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
        return;
    }
    AppExecFwk::OverflowInfo* overflowInfo = new (std::nothrow) AppExecFwk::OverflowInfo {};
    if (overflowInfo == nullptr) {
        HILOG_ERROR("Failed to new overflowInfo");
        return;
    }
    ErrCode ret = FormMgr::GetInstance().RequestOverflow(formIdInt, *overflowInfo, false);
    delete overflowInfo;
    if (ret != ERR_OK) {
        HILOG_INFO("complete ret false");
        AsyncCallback(env, PROVIDER_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
            callback, EtsFormErrorUtil::CreateErrorByInternalErrorCode(env, ret), nullptr);
        return;
    }
    HILOG_INFO("complete ret true");
    AsyncCallback(env, PROVIDER_CLASSNAME_ASYNC_CALLBACK_WRAPPER, callback, EtsFormErrorUtil::CreateError(env, ret),
        nullptr);
    return;
}

void RequestOverflow(ani_env *env, ani_string formId,
    ani_object aniOverflowInfo, ani_object callback)
{
    HILOG_INFO("call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    std::string stdFormId = "";
    if (!GetStdString(env, formId, stdFormId)) {
        HILOG_ERROR("GetStdString failed");
        EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
        return;
    }
    int64_t formIdInt = -1;
    if (!FormAniHelpers::ConvertStringToInt64(stdFormId, formIdInt)) {
        HILOG_ERROR("formId ConvertStringToInt64 failed");
        EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
        return;
    }
    AppExecFwk::OverflowInfo* overflowInfo = new (std::nothrow) AppExecFwk::OverflowInfo {};
    if (overflowInfo == nullptr) {
        HILOG_ERROR("Failed to new overflowInfo");
        return;
    }
    if (!ConvertFormOverflowInfo(env, aniOverflowInfo, overflowInfo)) {
        HILOG_ERROR("convert overflowInfo failed");
        delete overflowInfo;
        EtsFormErrorUtil::ThrowParamError(env, "The overflowInfo is invalid");
        return;
    }
    ErrCode ret = FormMgr::GetInstance().RequestOverflow(formIdInt, *overflowInfo, true);
    delete overflowInfo;
    if (ret != ERR_OK) {
        AsyncCallback(env, PROVIDER_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
            callback, EtsFormErrorUtil::CreateErrorByInternalErrorCode(env, ret), nullptr);
        return;
    }
    AsyncCallback(env, PROVIDER_CLASSNAME_ASYNC_CALLBACK_WRAPPER, callback, EtsFormErrorUtil::CreateError(env, ret),
        nullptr);
    return;
}

void DeactivateSceneAnimation(ani_env *env, ani_string formId, ani_object callback)
{
    HILOG_INFO("call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    std::string stdFormId = "";
    if (!GetStdString(env, formId, stdFormId)) {
        HILOG_ERROR("GetStdString failed");
        EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
        return;
    }
    int64_t formIdInt = -1;
    if (!FormAniHelpers::ConvertStringToInt64(stdFormId, formIdInt)) {
        HILOG_ERROR("formId ConvertStringToInt64 failed");
        EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
        return;
    }
    ErrCode ret = FormMgr::GetInstance().ChangeSceneAnimationState(formIdInt,
        static_cast<int32_t>(ActivationState::DEACTIVATED));
    if (ret != ERR_OK) {
        AsyncCallback(env, PROVIDER_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
            callback, EtsFormErrorUtil::CreateErrorByInternalErrorCode(env, ret), nullptr);
        return;
    }
    AsyncCallback(env, PROVIDER_CLASSNAME_ASYNC_CALLBACK_WRAPPER, callback, EtsFormErrorUtil::CreateError(env, ret),
        nullptr);
    return;
}

void ActivateSceneAnimation(ani_env *env, ani_string formId, ani_object callback)
{
    HILOG_INFO("call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    std::string stdFormId = "";
    if (!GetStdString(env, formId, stdFormId)) {
        HILOG_ERROR("GetStdString failed");
        EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
        return;
    }
    int64_t formIdInt = -1;
    if (!FormAniHelpers::ConvertStringToInt64(stdFormId, formIdInt)) {
        HILOG_ERROR("formId ConvertStringToInt64 failed");
        EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
        return;
    }
    ErrCode ret = FormMgr::GetInstance().ChangeSceneAnimationState(formIdInt,
        static_cast<int32_t>(ActivationState::ACTIVATED));
    if (ret != ERR_OK) {
        AsyncCallback(env, PROVIDER_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
            callback, EtsFormErrorUtil::CreateErrorByInternalErrorCode(env, ret), nullptr);
        return;
    }
    AsyncCallback(env, PROVIDER_CLASSNAME_ASYNC_CALLBACK_WRAPPER, callback, EtsFormErrorUtil::CreateError(env, ret),
        nullptr);
    return;
}

void OpenFormManagerCrossBundle(ani_env *env, ani_object aniWant)
{
    HILOG_INFO("call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    Want want;
    if (!AppExecFwk::UnwrapWant(env, aniWant, want)) {
        HILOG_ERROR("fail convert want");
        EtsFormErrorUtil::ThrowParamError(env, "Failed to convert want.");
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
    HILOG_DEBUG("stsFormProvider OpenFormManagerCrossBundle want:%{public}s", want.ToString().c_str());

    auto ret = FormMgr::GetInstance().StartAbilityByCrossBundle(want);
    if (ret != ERR_OK) {
        EtsFormErrorUtil::ThrowByInternalErrorCode(env, ret);
    }
    return;
}

void CheckFormIDParam(ani_env *env, ani_string formId)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    std::string stdFormId = "";
    if (!GetStdString(env, formId, stdFormId)) {
        HILOG_ERROR("GetStdString failed");
        EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
        return;
    }
    HILOG_INFO("stdFormId %{public}s", stdFormId.c_str());
    int64_t formIdInt = -1;
    if (!FormAniHelpers::ConvertStringToInt64(stdFormId, formIdInt)) {
        HILOG_ERROR("formId ConvertStringToInt64 failed");
        EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
        return;
    }
}

void CheckOverflowInfoParam(ani_env *env, ani_object aniOverflowInfo)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    AppExecFwk::OverflowInfo* overflowInfo = new (std::nothrow) AppExecFwk::OverflowInfo {};
    if (overflowInfo == nullptr) {
        HILOG_ERROR("Failed to new overflowInfo");
        return;
    }
    if (!ConvertFormOverflowInfo(env, aniOverflowInfo, overflowInfo)) {
        HILOG_ERROR("convert overflowInfo failed");
        delete overflowInfo;
        EtsFormErrorUtil::ThrowParamError(env, "The overflowInfo is invalid");
        return;
    }
    delete overflowInfo;
}

void RequestPublishForm(ani_env *env, ani_object wantObj, ani_object callback, ani_boolean withFormBindingData,
    ani_string dataObjStr, ani_object proxies)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, wantObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
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
            static_cast<int>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
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
            formInfosArray, ANI_SETTER_MARKER, PROVIDER_SET_SIGNATURE, index, runningFormInfoAni);
        if (status != ANI_OK) {
            HILOG_ERROR("Object_CallMethodByName_Void failed, error code: %{public}d", static_cast<int>(status));
            InvokeAsyncWithBusinessError(env, callback, static_cast<int>(ERR_APPEXECFWK_FORM_COMMON_CODE),
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
            static_cast<int>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
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


void ReloadForms(ani_env* env, ani_object etsContext, ani_string moduleName, ani_string abilityName,
    ani_string formName, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);

    if (!CheckUIAbilityContext(env, etsContext)) {
        return;
    }

    std::string moduleNameStr = ANIUtils_ANIStringToStdString(env, moduleName);
    std::string abilityNameStr = ANIUtils_ANIStringToStdString(env, abilityName);
    std::string formNameStr = ANIUtils_ANIStringToStdString(env, formName);
    int32_t reloadNum = 0;
    auto ret = FormMgr::GetInstance().ReloadForms(reloadNum, moduleNameStr, abilityNameStr, formNameStr);
    if (ret != ERR_OK) {
        HILOG_ERROR("ReloadForms failed, error code: %{public}d", static_cast<int>(ret));
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    ani_object etsReloadNum = createInt(env, reloadNum);
    InvokeAsyncWithBusinessError(env, callback, ret, etsReloadNum);

    HILOG_DEBUG("End");
}

void ReloadAllForms(ani_env* env, ani_object etsContext, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);

    if (!CheckUIAbilityContext(env, etsContext)) {
        return;
    }

    int32_t reloadNum = 0;
    auto ret = FormMgr::GetInstance().ReloadAllForms(reloadNum);
    if (ret != ERR_OK) {
        HILOG_ERROR("ReloadAllForms failed, error code: %{public}d", static_cast<int>(ret));
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    ani_object etsReloadNum = createInt(env, reloadNum);
    InvokeAsyncWithBusinessError(env, callback, ret, etsReloadNum);

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
        ani_native_function{"openFormEditAbilityInner",
            "C{std.core.String}C{std.core.String}z:",
            reinterpret_cast<void *>(OpenFormEditAbility)},
        ani_native_function{"closeFormEditAbilityInner", "z:", reinterpret_cast<void *>(CloseFormEditAbility)},
        ani_native_function{
            "openFormManagerInner", "C{@ohos.app.ability.Want.Want}:", reinterpret_cast<void *>(OpenFormManager)},
        ani_native_function{"requestPublishFormInner",
            "C{@ohos.app.ability.Want.Want}"
            "C{@ohos.app.form.formProvider.AsyncCallbackWrapper}zC{std.core.String}C{escompat.Array}:",
            reinterpret_cast<void *>(RequestPublishForm)},
        ani_native_function{"isRequestPublishFormSupportedInner",
            "C{@ohos.app.form.formProvider.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(IsRequestPublishFormSupported)},
        ani_native_function{"getPublishedFormInfosInner",
            "C{@ohos.app.form.formProvider.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(GetPublishedFormInfos)},
        ani_native_function{"getPublishedFormInfoByIdInner",
            "C{std.core.String}C{@ohos.app.form.formProvider.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(GetPublishedFormInfoById)},
        ani_native_function{"nativeGetFormRect", nullptr, reinterpret_cast<void *>(GetFormRect)},
        ani_native_function{"nativeCancelOverflow", nullptr, reinterpret_cast<void *>(CancelOverflow)},
        ani_native_function{"nativeRequestOverflow", nullptr, reinterpret_cast<void *>(RequestOverflow)},
        ani_native_function{
            "nativeDeactivateSceneAnimation", nullptr, reinterpret_cast<void *>(DeactivateSceneAnimation)},
        ani_native_function{"nativeActivateSceneAnimation", nullptr, reinterpret_cast<void *>(ActivateSceneAnimation)},
        ani_native_function{
            "nativeOpenFormManagerCrossBundle", nullptr, reinterpret_cast<void *>(OpenFormManagerCrossBundle)},
        ani_native_function{"checkFormIDParam", nullptr, reinterpret_cast<void *>(CheckFormIDParam)},
        ani_native_function{"checkOverflowInfoParam", nullptr, reinterpret_cast<void *>(CheckOverflowInfoParam)},
        ani_native_function{"nativeReloadForms", nullptr, reinterpret_cast<void *>(ReloadForms)},
        ani_native_function{"nativeReloadAllForms", nullptr, reinterpret_cast<void *>(ReloadAllForms)},
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

    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return ANI_ERROR;
    }

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
