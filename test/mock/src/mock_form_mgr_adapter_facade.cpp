/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "mock_form_mgr_adapter_facade.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "form_mgr/form_mgr_adapter_facade.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormMgrAdapterFacade> MockFormMgrAdapterFacade::obj = nullptr;

bool FormMgrAdapterFacade::IsDeleteCacheInUpgradeScene(const FormRecord &record)
{
    GTEST_LOG_(INFO) << "IsDeleteCacheInUpgradeScene called";
    if (AppExecFwk::MockFormMgrAdapterFacade::obj) {
        return AppExecFwk::MockFormMgrAdapterFacade::obj->IsDeleteCacheInUpgradeScene(record);
    }
    return false;
}

int FormMgrAdapterFacade::UpdateForm(int64_t formId, int32_t callingUid,
    const FormProviderData &formProviderData, const std::vector<FormDataProxy> &formDataProxies)
{
    GTEST_LOG_(INFO) << "FormMgrAdapterFacade::UpdateForm called, formId:" << formId;
    if (AppExecFwk::MockFormMgrAdapterFacade::obj) {
        return AppExecFwk::MockFormMgrAdapterFacade::obj->UpdateForm(
            formId, callingUid, formProviderData, formDataProxies);
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
