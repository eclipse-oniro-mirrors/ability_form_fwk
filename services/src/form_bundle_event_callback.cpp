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

#include "form_bundle_event_callback.h"

#include "form_bundle_forbid_mgr.h"
#include "form_task_mgr.h"

#include "form_bms_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BMS_EVENT_ADDITIONAL_INFO_CHANGED = "bms.event.ADDITIONAL_INFO_CHANGED";
constexpr uint64_t CRYPTED_BUNDLE_DELAY_TIME = 1000;
const std::string BMS_EVENT_PKG_REMOVE_RESULT_CODE = "resultCode";
} // namespace

FormBundleEventCallback::FormBundleEventCallback()
{
    HILOG_INFO("create");
}

FormBundleEventCallback::~FormBundleEventCallback()
{
    HILOG_INFO("destroy");
}

bool FormBundleEventCallback::IsEncryptedBundle(std::string &bundleName, int32_t userId)
{
    ApplicationInfo appInfo;
    if (FormBmsHelper::GetInstance().GetApplicationInfo(bundleName, userId, appInfo) != ERR_OK) {
        HILOG_ERROR("get app info failed");
        return false;
    }
    return (appInfo.applicationReservedFlag &
        static_cast<uint32_t>(AppExecFwk::ApplicationReservedFlag::ENCRYPTED_APPLICATION)) != 0;
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
        HILOG_INFO("bundleName:%{public}s changed", bundleName.c_str());
        FormEventUtil::HandleBundleFormInfoChanged(bundleName, userId);
        std::function<void()> taskFunc = [bundleName, userId]() {
            FormEventUtil::HandleUpdateFormCloud(bundleName);
            FormEventUtil::HandleProviderUpdated(bundleName, userId);
        };
        uint64_t delayMs = 0;
        if (IsEncryptedBundle(bundleName, userId)) {
            delayMs = CRYPTED_BUNDLE_DELAY_TIME;
        }
        FormTaskMgr::GetInstance().PostTask(taskFunc, delayMs);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        // uninstall module/bundle
        int32_t pkgRemoveRet = want.GetIntParam(BMS_EVENT_PKG_REMOVE_RESULT_CODE, ERR_OK);
        HILOG_INFO("bundleName:%{public}s removed, result code:%{pulic}d", bundleName.c_str(), pkgRemoveRet);
        if (pkgRemoveRet != ERR_OK) {
            HILOG_WARN("bundleName:%{public}s removed, but failed", bundleName.c_str());
            return;
        }
        FormEventUtil::HandleBundleFormInfoRemoved(bundleName, userId);
        std::function<void()> taskFunc = [bundleName, userId]() {
            FormEventUtil::HandleProviderRemoved(bundleName, userId);
            // Ensure clear forbidden form db when bundle uninstall
            // Health contol will set again when reinstall
            FormBundleForbidMgr::GetInstance().SetBundleForbiddenStatus(bundleName, false);
        };
        FormTaskMgr::GetInstance().PostTask(taskFunc, 0);
    } else if (action == BMS_EVENT_ADDITIONAL_INFO_CHANGED) {
        // additional info changed
        HILOG_INFO("bundleName:%{public}s additional info changed", bundleName.c_str());
        std::function<void()> taskFunc = [bundleName]() {
            FormEventUtil::HandleAdditionalInfoChanged(bundleName);
        };
        FormTaskMgr::GetInstance().PostTask(taskFunc, 0);
    }
}

} // namespace AppExecFwk
} // namespace OHOS