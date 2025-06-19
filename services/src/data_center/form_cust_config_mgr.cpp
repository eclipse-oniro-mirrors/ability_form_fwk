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
FormCustConfigMgr::FormCustConfigMgr()
{
    HILOG_INFO("create");
    InitLiveFormParameters();
}
 
FormCustConfigMgr::~FormCustConfigMgr()
{
    HILOG_INFO("destroy");
}
 
void FormCustConfigMgr::InitLiveFormParameters()
{
    liveFormSupportType = OHOS::system::GetParameter(Constants::PARAM_LIVE_FORM_SUPPORT_KEY, Constants::LIVE_FORM_NONE);
    gameCardSupportEnable = OHOS::system::GetParameter(Constants::PARAM_GAME_CARD_SUPPORT_KEY, "false");
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