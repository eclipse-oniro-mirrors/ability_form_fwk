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

#include "form_refresh/strategy/refresh_control_mgr.h"

#include "fms_log_wrapper.h"
#include "common/util/form_trust_mgr.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#ifdef SUPPORT_POWER
#include "power_mgr_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr char HICAR_FORM [] = "phone_hicar";
}

RefreshControlMgr::RefreshControlMgr() {}
RefreshControlMgr::~RefreshControlMgr() {}

#ifdef RES_SCHEDULE_ENABLE
void RefreshControlMgr::SetSystemOverloadFlag(bool flag)
{
    if (isSystemOverload_ && !flag) {
        RefreshCacheMgr::GetInstance().ConsumeOverloadTaskQueue();
    }

    HILOG_INFO("isSystemOverload_:%{public}d, new flag:%{public}d", isSystemOverload_, flag);
    isSystemOverload_ = flag;
}
#endif

bool RefreshControlMgr::IsSystemOverload()
{
#ifdef RES_SCHEDULE_ENABLE
    if (isSystemOverload_) {
        HILOG_WARN("system overload");
    }
    return isSystemOverload_;
#endif
    return false;
}

bool RefreshControlMgr::IsFormInvisible(const FormRecord &record)
{
    if (record.formVisibleNotifyState != Constants::FORM_VISIBLE) {
        HILOG_WARN("invisible formId:%{public}" PRId64, record.formId);
        return true;
    }
    return false;
}

bool RefreshControlMgr::IsScreenOff(const FormRecord &record)
{
#ifdef SUPPORT_POWER
    bool screenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
    bool collaborationScreenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsCollaborationScreenOn();
    bool isHicar = (record.moduleName == HICAR_FORM);
    if (!screenOnFlag && !collaborationScreenOnFlag && !isHicar) {
        HILOG_WARN("screen off contorl, formId:%{public}" PRId64, record.formId);
        return true;
    }
#endif
    return false;
}

bool RefreshControlMgr::IsHealthyControl(const FormRecord &record)
{
    if (!record.enableForm) {
        HILOG_WARN("be healthy usage controlling, formId:%{public}" PRId64, record.formId);
        return true;
    }

    return false;
}

bool RefreshControlMgr::IsNeedToFresh(FormRecord &record, bool isVisibleToFresh)
{
    bool isEnableRefresh = FormDataMgr::GetInstance().IsEnableRefresh(record.formId);
    HILOG_INFO("isEnableRefresh is %{public}d", isEnableRefresh);
    if (isEnableRefresh) {
        return true;
    }
    HILOG_INFO("isVisibleToFresh is %{public}d, record.isVisible is %{public}d", isVisibleToFresh, record.isVisible);
    if (isVisibleToFresh) {
        if (!record.isVisible) {
            FormRecordReport::GetInstance().IncreaseUpdateTimes(record.formId,
                HiSysEventPointType::TYPE_INVISIBLE_INTERCEPT);
        }
        return record.isVisible;
    }
    bool isEnableUpdate = FormDataMgr::GetInstance().IsEnableUpdate(record.formId);
    HILOG_INFO("isEnableUpdate is %{public}d", isEnableUpdate);
    return isEnableUpdate;
}

} // namespace AppExecFwk
} // namespace OHOS