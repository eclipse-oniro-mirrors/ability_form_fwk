/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "bms_mgr/form_bundle_event_callback.h"

#include "feature/bundle_forbidden/form_bundle_forbid_mgr.h"
#include "form_mgr/form_mgr_queue.h"
#include "feature/bundle_distributed/form_distributed_mgr.h"
#include "common/util/form_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BMS_EVENT_ADDITIONAL_INFO_CHANGED = "bms.event.ADDITIONAL_INFO_CHANGED";
} // namespace

FormBundleEventCallback::FormBundleEventCallback()
{
    HILOG_INFO("create");
}

FormBundleEventCallback::~FormBundleEventCallback()
{
    HILOG_INFO("destroy");
}

void FormBundleEventCallback::OnReceiveEvent(const EventFwk::CommonEventData eventData)
{
    const AAFwk::Want& want = eventData.GetWant();
    // action contains the change type of haps.
    std::string action = want.GetAction();
    std::string bundleName = want.GetElement().GetBundleName();
    int userId = want.GetIntParam(KEY_USER_ID, 0);
    // verify data
    if (action.empty() || bundleName.empty()) {
        HILOG_ERROR("empty action/bundleName");
        return;
    }

    HILOG_INFO("action:%{public}s", action.c_str());

    wptr<FormBundleEventCallback> weakThis = this;
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        // install or update
        HILOG_WARN("bundleName:%{public}s changed", bundleName.c_str());
        HandleBundleChange(bundleName);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        // uninstall module/bundle
        int appIndex = want.GetIntParam("appIndex", 0);
        if (appIndex > 0) {
            HILOG_INFO("this application is a simulation. not support to remove the form.\
                appIndex: %{public}d", appIndex);
            return;
        }
        HILOG_WARN("package removed, bundleName:%{public}s, userId:%{public}d", bundleName.c_str(), userId);
        FormEventUtil::HandleBundleFormInfoRemoved(bundleName, userId);
        std::function<void()> taskFunc = [bundleName, userId]() {
            FormEventUtil::HandleProviderRemoved(bundleName, userId);
            // Ensure clear forbidden form db when bundle uninstall
            // Health contol will set again when reinstall
            FormBundleForbidMgr::GetInstance().SetBundleForbiddenStatus(bundleName, false);
            DistributedModule distributedModule;
            distributedModule.userId = userId;
            FormDistributedMgr::GetInstance().SetBundleDistributedStatus(bundleName, false, distributedModule);
        };
        FormMgrQueue::GetInstance().ScheduleTask(0, taskFunc);
    } else if (action == BMS_EVENT_ADDITIONAL_INFO_CHANGED) {
        // additional info changed
        HILOG_INFO("bundleName:%{public}s additional info changed", bundleName.c_str());
        std::function<void()> taskFunc = [bundleName]() {
            FormEventUtil::HandleAdditionalInfoChanged(bundleName);
        };
        FormMgrQueue::GetInstance().ScheduleTask(0, taskFunc);
    }
}

void FormBundleEventCallback::HandleBundleChange(const std::string &bundleName)
{
    std::vector<int32_t> activeList;
    FormUtil::GetActiveUsers(activeList);
    if (activeList.empty()) {
        HILOG_ERROR("can't not find active user, do not handle bundle change");
        return;
    }

    HILOG_INFO("active user list len:%{public}zu", activeList.size());
    for (const int32_t userId : activeList) {
        bool needReload = true;
        FormEventUtil::HandleBundleFormInfoChanged(bundleName, userId, needReload);
        std::function<void()> taskFunc = [bundleName, userId, needReload]() {
            FormEventUtil::HandleUpdateFormCloud(bundleName);
            FormEventUtil::HandleProviderUpdated(bundleName, userId, needReload);
        };
        FormMgrQueue::GetInstance().ScheduleTask(0, taskFunc);
    }
}
} // namespace AppExecFwk
} // namespace OHOS