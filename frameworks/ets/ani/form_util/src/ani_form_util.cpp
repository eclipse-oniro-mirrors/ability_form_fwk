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
constexpr const char* ETS_FUNINTERACTIONPARAMS_NAME = "L@ohos/app/form/formInfo/formInfo/FunInteractionParamsInner;";
constexpr const char* ETS_FORMINFO_NAME = "L@ohos/app/form/formInfo/formInfo/FormInfoInner;";
constexpr const char* ETS_SCENEANIMATIONPARAMS_NAME = "L@ohos/app/form/formInfo/formInfo/SceneAnimationParamsInner;";
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
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, aniInfo);
        if (status != ANI_OK) {
            HILOG_ERROR("Object_CallMethodByName_Void failed status: %{public}d", status);
            break;
        }
        index++;
    }
    return arrayObj;
}
} // namespace AbilityRuntime
} // namespace OHOS