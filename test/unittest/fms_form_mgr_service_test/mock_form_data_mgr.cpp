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

using namespace OHOS::AppExecFwk;
namespace {
    int32_t g_mockCheckInvalidFormRet = OHOS::ERR_OK;
    int32_t g_mockGetPublishedFormInfoByIdRet = OHOS::ERR_OK;
    int32_t g_mockGetPublishedFormInfosRet = OHOS::ERR_OK;
    int32_t g_mockGetRunningFormInfosByFormIdRet = OHOS::ERR_OK;
    std::string g_mockBundleName;
    FormVisibilityType g_mockVisibilityType = FormVisibilityType::INVISIBLE;
}

void MockCheckInvalidForm(int32_t mockRet)
{
    g_mockCheckInvalidFormRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {

void MockFormDataMgrGetPublishedFormInfoById(int32_t mockRet)
{
    g_mockGetPublishedFormInfoByIdRet = mockRet;
}

void MockFormDataMgrGetPublishedFormInfos(int32_t mockRet)
{
    g_mockGetPublishedFormInfosRet = mockRet;
}

void MockFormDataMgrGetRunningFormInfosByFormId(int32_t mockRet, const std::string &bundleName,
    FormVisibilityType visibilityType)
{
    g_mockGetRunningFormInfosByFormIdRet = mockRet;
    g_mockBundleName = bundleName;
    g_mockVisibilityType = visibilityType;
}

FormDataMgr::FormDataMgr()
{}

FormDataMgr::~FormDataMgr()
{}

ErrCode FormDataMgr::CheckInvalidForm(const int64_t formId, const int32_t userId)
{
    return g_mockCheckInvalidFormRet;
}

ErrCode FormDataMgr::GetPublishedFormInfoById(const std::string &bundleName, RunningFormInfo &formInfo,
    const int64_t &formId, int32_t userId) const
{
    return g_mockGetPublishedFormInfoByIdRet;
}

ErrCode FormDataMgr::GetPublishedFormInfos(const std::string &bundleName, std::vector<RunningFormInfo> &formInfos,
    int32_t userId) const
{
    return g_mockGetPublishedFormInfosRet;
}

ErrCode FormDataMgr::GetRunningFormInfosByFormId(const int64_t formId, RunningFormInfo &runningFormInfo,
    const int32_t userId)
{
    runningFormInfo.bundleName = g_mockBundleName;
    runningFormInfo.formVisiblity = g_mockVisibilityType;
    return g_mockGetRunningFormInfosByFormIdRet;
}
}  // namespace AppExecFwk
}  // namespace OHOS