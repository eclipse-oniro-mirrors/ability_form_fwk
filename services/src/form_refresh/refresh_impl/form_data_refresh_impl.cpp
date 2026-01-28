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

#include "form_refresh/refresh_impl/form_data_refresh_impl.h"
#include "form_provider/form_provider_mgr.h"
#include "form_refresh/strategy/refresh_exec_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// Configuration for form data refresh, check types and control checks
static RefreshConfig CreateConfig()
{
    RefreshConfig config;
    // Check types configuration
    config.checkTypes = { TYPE_UNTRUST_APP, TYPE_CALLING_USER, TYPE_MULTI_ACTIVE_USERS };
    // Control checks configuration
    config.controlCheckFlags = CONTROL_CHECK_NONE;
    return config;
}
}

FormDataRefreshImpl::FormDataRefreshImpl() : BaseFormRefresh(CreateConfig()) {}
FormDataRefreshImpl::~FormDataRefreshImpl() {}

int FormDataRefreshImpl::DoRefresh(RefreshData &data)
{
    int ret = ERR_OK;
    FormType formType = data.record.uiSyntax;
    if (formType == FormType::JS) {
        ret = FormProviderMgr::GetInstance().UpdateForm(data.formId, data.record, data.providerData);
        HILOG_INFO("update js form, ret:%{public}d, formId:%{public}" PRId64, ret, data.formId);
        return ret;
    }

    ret = RefreshExecMgr::UpdateByProviderData(data.formId, data.providerData, false);
    if (ret != ERR_OK) {
        HILOG_ERROR("update provider data failed, ret:%{public}d, formId:%{public}" PRId64, ret, data.formId);
        return ret;
    }

    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS