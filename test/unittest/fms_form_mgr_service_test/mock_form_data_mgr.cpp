/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "data_center/form_data_mgr.h"
#include "form_errors.h"

namespace {
    int32_t g_mockCheckInvalidFormRet = OHOS::ERR_OK;
}

void MockCheckInvalidForm(int32_t mockRet)
{
    g_mockCheckInvalidFormRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormDataMgr::FormDataMgr()
{}

FormDataMgr::~FormDataMgr()
{}

ErrCode FormDataMgr::CheckInvalidForm(const int64_t formId, const int32_t userId)
{
    return g_mockCheckInvalidFormRet;
}
}  // namespace AppExecFwk
}  // namespace OHOS