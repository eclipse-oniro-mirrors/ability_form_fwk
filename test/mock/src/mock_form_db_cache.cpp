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

#include "mock_form_db_cache.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "data_center/database/form_db_cache.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormDbCache> MockFormDbCache::obj = nullptr;

ErrCode FormDbCache::GetDBRecord(const int64_t formId, FormRecord &record) const
{
    GTEST_LOG_(INFO) << "GetDBRecord called";
    if (AppExecFwk::MockFormDbCache::obj) {
        return AppExecFwk::MockFormDbCache::obj->GetDBRecord(formId, record);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormDbCache::UpdateDBRecord(const int64_t formId, const FormRecord &record) const
{
    GTEST_LOG_(INFO) << "UpdateDBRecord called";
    if (AppExecFwk::MockFormDbCache::obj) {
        return AppExecFwk::MockFormDbCache::obj->UpdateDBRecord(formId, record);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

void FormDbCache::GetAllFormInfo(std::vector<FormDBInfo> &formDBInfos)
{
    GTEST_LOG_(INFO) << "GetAllFormInfo called";
    if (AppExecFwk::MockFormDbCache::obj) {
        AppExecFwk::MockFormDbCache::obj->GetAllFormInfo(formDBInfos);
    }
}

ErrCode FormDbCache::UpdateFormLocation(const int64_t formId, const int32_t formLocation)
{
    GTEST_LOG_(INFO) << "UpdateFormLocation called";
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
