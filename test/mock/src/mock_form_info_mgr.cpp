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

#include "mock_form_info_mgr.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "data_center/form_info/form_info_mgr.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormInfoMgr> MockFormInfoMgr::obj = nullptr;

FormInfoMgr::FormInfoMgr()
{}

FormInfoMgr::~FormInfoMgr()
{}

ErrCode FormInfoMgr::GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
    std::vector<FormInfo> &formInfos, int32_t userId)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByModule called";
    if (AppExecFwk::MockFormInfoMgr::obj) {
        return AppExecFwk::MockFormInfoMgr::obj->GetFormsInfoByModule(bundleName, moduleName, formInfos, userId);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

bool FormInfoMgr::IsMultiAppForm(const FormInfo &formInfo)
{
    GTEST_LOG_(INFO) << "IsMultiAppForm called";
    if (AppExecFwk::MockFormInfoMgr::obj) {
        return AppExecFwk::MockFormInfoMgr::obj->IsMultiAppForm(formInfo);
    }
    return false;
}

ErrCode FormInfoMgr::GetAllFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId)
{
    GTEST_LOG_(INFO) << "GetAllFormsInfo called";
    if (AppExecFwk::MockFormInfoMgr::obj) {
        return AppExecFwk::MockFormInfoMgr::obj->GetAllFormsInfo(formInfos, userId);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}
}  // namespace AppExecFwk
}  // namespace OHOS
