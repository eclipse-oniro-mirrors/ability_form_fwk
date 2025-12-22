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

#include "ani_form_util.h"

#include "ani_form_common_util.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* ETS_FUNINTERACTIONPARAMS_NAME = "@ohos.app.form.formInfo.formInfo.FunInteractionParamsInner";
constexpr const char* ETS_FORMINFO_NAME = "@ohos.app.form.formInfo.formInfo.FormInfoInner";
constexpr const char* ETS_SCENEANIMATIONPARAMS_NAME = "@ohos.app.form.formInfo.formInfo.SceneAnimationParamsInner";
constexpr const char* DELEGATOR_RECORD_KEY = "keys";
constexpr const char* DELEGATOR_RECORD_NEXT = "next";
constexpr const char* DELEGATOR_RECORD_DONE = "done";
constexpr const char* DELEGATOR_RECORD_VALUE = "value";
constexpr const char* DELEGATOR_RECORD_CLASS_NAME = "std.core.Record";
constexpr const char* DELEGATOR_RECORD_GET = "$_get";
constexpr const char* DELEGATOR_RECORD_GET_NAME =
    "X{C{std.core.BaseEnum}C{std.core.Numeric}C{std.core.String}}:C{std.core.Object}";
}

ani_object CreateFunInteractionParamsDatas(ani_env* env,
    const OHOS::AppExecFwk::FormFunInteractionParams &funInteractionParamsDatas)
{
    ani_object object = CreateAniObject(env, ETS_FUNINTERACTIONPARAMS_NAME);
    SetPropertyStringByName(env, object, "abilityName", funInteractionParamsDatas.abilityName);
    SetPropertyStringByName(env, object, "targetBundleName", funInteractionParamsDatas.targetBundleName);
    SetPropertyStringByName(env, object, "subBundleName", funInteractionParamsDatas.subBundleName);
    SetPropertyIntByName(env, object, "keepStateDuration", funInteractionParamsDatas.keepStateDuration);
    return object;
}

ani_object CreateSceneAnimationParamsDatas(ani_env* env,
    const AppExecFwk::FormSceneAnimationParams &sceneAnimationParamsDatas)
{
    ani_object object = CreateAniObject(env, ETS_SCENEANIMATIONPARAMS_NAME);
    SetPropertyStringByName(env, object, "abilityName", sceneAnimationParamsDatas.abilityName);
    SetPropertyStringByName(env, object, "disabledDesktopBehaviors",
        sceneAnimationParamsDatas.disabledDesktopBehaviors);
    return object;
}

ani_object CreateFormInfo(ani_env* env, const OHOS::AppExecFwk::FormInfo &formInfo)
{
    ani_object object = CreateAniObject(env, ETS_FORMINFO_NAME);
    SetPropertyByName(env, object, "funInteractionParams",
        CreateFunInteractionParamsDatas(env, formInfo.funInteractionParams));
    SetPropertyByName(env, object, "sceneAnimationParams",
        CreateSceneAnimationParamsDatas(env, formInfo.sceneAnimationParams));
    SetPropertyStringByName(env, object, "groupId", formInfo.groupId);
    SetPropertyBoolByName(env, object, "resizable", formInfo.resizable);
    return object;
}

ani_object CreateFormInfos(ani_env* env, const std::vector<OHOS::AppExecFwk::FormInfo> &formInfos)
{
    ani_status status = ANI_OK;
    ani_object arrayObj = CreateArrayObject(env);
    ani_size index = 0;
    for (auto &info : formInfos) {
        ani_object aniInfo = CreateFormInfo(env, info);
        if (aniInfo == nullptr) {
            HILOG_ERROR("null aniInfo");
            break;
        }
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", index, aniInfo);
        if (status != ANI_OK) {
            HILOG_ERROR("Object_CallMethodByName_Void failed status: %{public}d", status);
            break;
        }
        index++;
    }
    return arrayObj;
}

bool GetPropertyDoubleByName(ani_env *env, ani_object object, const char *name, ani_double& value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetPropertyByName_Double(object, name, &value)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return false;
    }
    return true;
}

bool UnwrapFormRect(ani_env *env, ani_object rectobject, AppExecFwk::Rect &rect)
{
    HILOG_DEBUG("call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return false;
    }
    ani_double left = 0.0;
    if (!GetPropertyDoubleByName(env, rectobject, "left", left)) {
        HILOG_ERROR("GetPropertyDoubleByName failed");
        return false;
    }
    ani_double top = 0.0;
    if (!GetPropertyDoubleByName(env, rectobject, "top", top)) {
        HILOG_ERROR("GetPropertyDoubleByName failed");
        return false;
    }
    ani_double width = 0.0;
    if (!GetPropertyDoubleByName(env, rectobject, "width", width)) {
        HILOG_ERROR("GetPropertyDoubleByName failed");
        return false;
    }
    ani_double height = 0.0;
    if (!GetPropertyDoubleByName(env, rectobject, "height", height)) {
        HILOG_ERROR("GetPropertyDoubleByName failed");
        return false;
    }
    rect.left = left;
    rect.top = top;
    rect.width = width;
    rect.height = height;
    return true;
}

bool ParseRecordString(ani_env *env, ani_object aniMockList, std::unordered_map<std::string, std::string> &mockList)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return false;
    }
    ani_ref iter = nullptr;
    ani_status status = ANI_ERROR;
    status = env->Object_CallMethodByName_Ref(aniMockList, DELEGATOR_RECORD_KEY, nullptr, &iter);
    if (ANI_OK != status) {
        HILOG_ERROR("Failed to get keys iterator status: %{public}d", status);
        return false;
    }
    ani_ref next = nullptr;
    ani_boolean done = false;
    while (ANI_OK == env->Object_CallMethodByName_Ref(
        static_cast<ani_object>(iter), DELEGATOR_RECORD_NEXT, nullptr, &next)) {
        status = env->Object_GetFieldByName_Boolean(static_cast<ani_object>(next), DELEGATOR_RECORD_DONE, &done);
        if (ANI_OK != status) {
            HILOG_ERROR("Failed to check iterator done status: %{public}d", status);
            return false;
        }
        if (done) {
            HILOG_DEBUG("[forEachMapEntry] done break");
            return true;
        }
        ani_ref aniKey = nullptr;
        ani_ref aniValue = nullptr;
        if (!ParseRecordStringInner(env, next, aniMockList, aniKey, aniValue)) {
            HILOG_ERROR("ParseRecordStringInner failed");
            return false;
        }
        SetRecordStringToMap(env, static_cast<ani_string>(aniKey), static_cast<ani_string>(aniValue), mockList);
    }
    return true;
}

bool ParseRecordStringInner(ani_env *env, ani_ref next, ani_object aniMockList, ani_ref &aniKey, ani_ref &aniValue)
{
    ani_status status = ANI_ERROR;
    status = env->Object_GetFieldByName_Ref(static_cast<ani_object>(next), DELEGATOR_RECORD_VALUE, &aniKey);
    if (ANI_OK != status) {
        HILOG_ERROR("Failed to get value status: %{public}d", status);
        return false;
    }
    ani_class recordCls = nullptr;
    status = env->FindClass(DELEGATOR_RECORD_CLASS_NAME, &recordCls);
    if (status != ANI_OK) {
        HILOG_ERROR("FindClass failed status: %{public}d", status);
        return false;
    }
    ani_method recordGetMethod = nullptr;
    status = env->Class_FindMethod(recordCls, DELEGATOR_RECORD_GET, DELEGATOR_RECORD_GET_NAME, &recordGetMethod);
    if (status != ANI_OK) {
        HILOG_ERROR("Class_FindMethod failed status: %{public}d", status);
        return false;
    }
    status = env->Object_CallMethod_Ref(aniMockList, recordGetMethod, &aniValue, static_cast<ani_string>(aniKey));
    if (status != ANI_OK) {
        HILOG_ERROR("Object_CallMethod_Void failed status: %{public}d", status);
        return false;
    }
    return true;
}

void SetRecordStringToMap(ani_env *env, ani_string aniKey, ani_string aniValue,
    std::unordered_map<std::string, std::string> &uMap)
{
    std::string mapKey = "";
    if (!GetStdString(env, aniKey, mapKey)) {
        HILOG_ERROR("GetStdString failed");
        return;
    }
    std::string mapValue = "";
    if (!GetStdString(env, aniValue, mapValue)) {
        HILOG_ERROR("GetStdString failed");
        return;
    }
    uMap.emplace(mapKey, mapValue);
}
} // namespace AbilityRuntime
} // namespace OHOS