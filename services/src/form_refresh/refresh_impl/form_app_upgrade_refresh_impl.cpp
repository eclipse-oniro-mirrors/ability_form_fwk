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

#include "form_refresh/refresh_impl/form_app_upgrade_refresh_impl.h"

#include "data_center/form_cache_mgr.h"
#include "form_mgr/form_mgr_adapter.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// Configuration for form app upgrade refresh, check types and control checks
static RefreshConfig CreateConfig()
{
    RefreshConfig config;
    // Check types configuration
    config.checkTypes = { TYPE_UNTRUST_APP, TYPE_ACTIVE_USER, TYPE_ADD_FINISH };
    // Control checks configuration
    config.controlCheckFlags = CONTROL_CHECK_HEALTHY_CONTROL | CONTROL_CHECK_NEED_TO_FRESH;
    return config;
}
}

FormAppUpgradeRefreshImpl::FormAppUpgradeRefreshImpl() : BaseFormRefresh(CreateConfig()) {}
FormAppUpgradeRefreshImpl::~FormAppUpgradeRefreshImpl() {}

int FormAppUpgradeRefreshImpl::DoRefresh(RefreshData &data)
{
    if (!FormMgrAdapter::GetInstance().IsDeleteCacheInUpgradeScene(data.record)) {
        FormProviderData formProviderData;
        std::string cacheData;
        std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
        if (FormCacheMgr::GetInstance().GetData(data.formId, cacheData, imageDataMap)) {
            formProviderData.SetDataString(cacheData);
            formProviderData.SetImageDataMap(imageDataMap);
            FormMgrAdapter::GetInstance().UpdateForm(data.formId, data.record.uid, formProviderData);
        }
        HILOG_INFO("Upgrade APP data agent card update, imageDataState: %{public}d, cacheData: %{public}zu, "
            "formId: %{public}" PRId64, formProviderData.GetImageDataState(), cacheData.size(), data.formId);
    }
    return BaseFormRefresh::DoRefresh(data);
}
} // namespace AppExecFwk
} // namespace OHOS