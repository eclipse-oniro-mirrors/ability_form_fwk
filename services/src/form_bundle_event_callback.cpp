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

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BMS_EVENT_ADDITIONAL_INFO_CHANGED = "bms.event.ADDITIONAL_INFO_CHANGED";
} // namespace

void FormBundleEventCallback::OnReceiveEvent(const EventFwk::CommonEventData eventData)
{
    const AAFwk::Want& want = eventData.GetWant();
    // action contains the change type of haps.
    std::string action = want.GetAction();
    std::string bundleName = want.GetElement().GetBundleName();
    int userId = want.GetIntParam(KEY_USER_ID, 0);
    // verify data
    if (action.empty() || bundleName.empty()) {
        HILOG_ERROR("%{public}s failed, empty action/bundleName", __func__);
        return;
    }
    HILOG_INFO("%{public}s, action:%{public}s.", __func__, action.c_str());

    wptr<FormBundleEventCallback> weakThis = this;
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        // install or update
        HILOG_INFO("%{public}s, bundle changed, bundleName: %{public}s", __func__, bundleName.c_str());
        formEventHelper_.HandleBundleFormInfoChanged(bundleName, userId);
        formEventHelper_.HandleProviderUpdated(bundleName, userId);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        // uninstall module/bundle
        HILOG_INFO("%{public}s, bundle removed, bundleName: %{public}s", __func__, bundleName.c_str());
        formEventHelper_.HandleBundleFormInfoRemoved(bundleName, userId);
        formEventHelper_.HandleProviderRemoved(bundleName, userId);
    } else if (action == BMS_EVENT_ADDITIONAL_INFO_CHANGED) {
        // additional info changed
        HILOG_INFO("Additional info changed, bundleName: %{public}s", bundleName.c_str());
        formEventHelper_.HandleAdditionalInfoChanged(bundleName);
    }
}

} // namespace AppExecFwk
} // namespace OHOS