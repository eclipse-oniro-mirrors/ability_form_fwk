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
#include "form_refresh/strategy/refresh_check_mgr.h"
#include "form_refresh/strategy/refresh_exec_mgr.h"

namespace OHOS {
namespace AppExecFwk {

FormDataRefreshImpl::FormDataRefreshImpl() {}
FormDataRefreshImpl::~FormDataRefreshImpl() {}

int FormDataRefreshImpl::RefreshFormRequest(RefreshData &data)
{
    const std::vector<int32_t> checkTypes = { TYPE_UNTRUST_APP, TYPE_CALLING_USER };
    CheckValidFactor factor;
    factor.formId = data.formId;
    factor.record = data.record;
    factor.callingUid = data.callingUid;
    int ret = RefreshCheckMgr::GetInstance().IsBaseValidPass(checkTypes, factor);
    if (ret != ERR_OK) {
        return ret;
    }

    FormType formType = data.record.uiSyntax;
    if (formType == FormType::JS) {
        ret = FormProviderMgr::GetInstance().UpdateForm(data.formId, data.record, data.providerData);
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