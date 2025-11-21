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

#ifndef OHOS_FORM_FWK_ANI_FORM_UTIL_H
#define OHOS_FORM_FWK_ANI_FORM_UTIL_H

#include "ani.h"
#include "fms_log_wrapper.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"
#include "running_form_info.h"
#include "runtime.h"

namespace OHOS {
namespace AbilityRuntime {
ani_object CreateFunInteractionParamsDatas(ani_env* env,
    const OHOS::AppExecFwk::FormFunInteractionParams &funInteractionParamsDatas);
ani_object CreateSceneAnimationParamsDatas(ani_env* env,
    const AppExecFwk::FormSceneAnimationParams &sceneAnimationParamsDatas);
ani_object CreateFormInfo(ani_env* env, const OHOS::AppExecFwk::FormInfo &formInfo);
ani_object CreateFormInfos(ani_env* env, const std::vector<OHOS::AppExecFwk::FormInfo> &formInfos);
bool UnwrapFormRect(ani_env *env, ani_object rectobject, AppExecFwk::Rect &rect);
bool GetRefProperty(ani_env *env, ani_object param, const char *name, ani_ref &value);
bool GetDoublePropertyObject(ani_env *env, ani_object param, const char *name, double &value);
bool ParseRecordString(ani_env *env, ani_object aniMockList, std::unordered_map<std::string, std::string> &mockList);
bool ParseRecordStringInner(ani_env *env, ani_ref next, ani_object aniMockList, ani_ref &aniKey, ani_ref &aniValue);
void SetRecordStringToMap(ani_env *env, ani_string aniKey, ani_string aniValue,
    std::unordered_map<std::string, std::string> &uMap);
} // namespace AbilityRuntime
} // namespace OHOS
#endif /* OHOS_FORM_FWK_ANI_FORM_UTIL_H */