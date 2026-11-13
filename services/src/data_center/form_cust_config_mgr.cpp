/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "data_center/form_cust_config_mgr.h"
 
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "parameters.h"
 
namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *FORM_EXT_PROCESS_POOL_THRESHOLD_KEY = "persist.sys.fms.form_extension.process_pool.threshold";
constexpr const char *LIVE_FORM_SUPPORT_KEY = "persist.sys.fms.support.liveForm";
constexpr const char *GAME_CARD_SUPPORT_KEY = "persist.sceneboard.desktop.game_card";
constexpr const char *LIVE_FORM_NONE = "0";
constexpr const char *GAME_CARD_DISABLED = "false";
constexpr int32_t DEFAULT_POOL_THRESHOLD = 20;
constexpr int32_t POOL_THRESHOLD_LIMIT = 50;
}

FormCustConfigMgr::FormCustConfigMgr()
{
    HILOG_INFO("create");
    InitCustConfigParameters();
}
 
FormCustConfigMgr::~FormCustConfigMgr()
{
    HILOG_INFO("destroy");
}
 
void FormCustConfigMgr::InitCustConfigParameters()
{
    liveFormSupportType = OHOS::system::GetParameter(LIVE_FORM_SUPPORT_KEY, LIVE_FORM_NONE);
    gameCardSupportEnable = OHOS::system::GetParameter(GAME_CARD_SUPPORT_KEY, GAME_CARD_DISABLED);
    int32_t rawThreshold = OHOS::system::GetIntParameter(FORM_EXT_PROCESS_POOL_THRESHOLD_KEY, DEFAULT_POOL_THRESHOLD);
    processPoolThreshold_ = SanitizePoolThreshold(rawThreshold);
    HILOG_INFO("process pool threshold: %{public}zu (raw %{public}d)", processPoolThreshold_, rawThreshold);
}

size_t FormCustConfigMgr::GetFormExtensionProcessPoolMax() const
{
    return processPoolThreshold_;
}

size_t FormCustConfigMgr::SanitizePoolThreshold(int32_t rawThreshold)
{
    // 0 keeps 0: pool gating disabled (rollback switch).
    if (rawThreshold < 0) {
        return DEFAULT_POOL_THRESHOLD;
    }
    if (rawThreshold > POOL_THRESHOLD_LIMIT) {
        return POOL_THRESHOLD_LIMIT;
    }
    return rawThreshold;
}

bool FormCustConfigMgr::IsSupportSceneAnimation()
{
    return liveFormSupportType == Constants::SCENE_ANIMATION || liveFormSupportType == Constants::LIVE_FORM_BOTH;
}
 
bool FormCustConfigMgr::IsSupportFunInteraction()
{
    return liveFormSupportType == Constants::FUN_INTERACTION || liveFormSupportType == Constants::LIVE_FORM_BOTH;
}
 
bool FormCustConfigMgr::IsSupportGameCard()
{
    return gameCardSupportEnable == "true";
}
}  // namespace AppExecFwk
}  // namespace OHOS