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

#include "form_data_mgr.h"

#include "form_mgr_errors.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"

namespace {
    bool g_mockGetFormRecordRet = true;
    bool g_mockSetFormTempFlagRet = true;
    bool g_mockGetReCreateFormRecordsByBundleNameRet = true;
    bool g_mockGetUpdatedFormRet = true;
    bool g_mockGetPackageFormRet = true;
    bool g_mockGetNoHostTempFormsOne = true;
    bool g_mockGetNoHostTempFormsTwo = true;
}

void MockGetFormRecord(bool mockRet)
{
    g_mockGetFormRecordRet = mockRet;
}

void MockSetFormTempFlag(bool mockRet)
{
    g_mockSetFormTempFlagRet = mockRet;
}

void MockGetReCreateFormRecordsByBundleName(bool mockRet)
{
    g_mockGetReCreateFormRecordsByBundleNameRet = mockRet;
}

void MockGetUpdatedForm(bool mockRet)
{
    g_mockGetUpdatedFormRet = mockRet;
}

void MockGetPackageForm(bool mockRet)
{
    g_mockGetPackageFormRet = mockRet;
}

void MockGetNoHostTempFormsOne(bool mockRet)
{
    g_mockGetNoHostTempFormsOne = mockRet;
}

void MockGetNoHostTempFormsTwo(bool mockRet)
{
    g_mockGetNoHostTempFormsTwo = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormDataMgr::FormDataMgr()
{
    HILOG_INFO("create form data manager instance");
}
FormDataMgr::~FormDataMgr()
{
    HILOG_INFO("destroy form data manager instance");
}

bool FormDataMgr::GetFormRecord(const std::string &bundleName, std::vector<FormRecord> &formInfos)
{
    FormRecord formRecord;
    formRecord.bundleName = "com.form.provider.service";
    formRecord.formId = 1;
    if (false == g_mockSetFormTempFlagRet) {
        formRecord.formTempFlag = false;
    } else {
        formRecord.formTempFlag = true;
    }
    formInfos.emplace_back(formRecord);
    return g_mockGetFormRecordRet;
}

void FormDataMgr::GetReCreateFormRecordsByBundleName(const std::string &bundleName, std::set<int64_t> &reCreateForms)
{
    if (true == g_mockGetReCreateFormRecordsByBundleNameRet) {
        int64_t formId = 1;
        reCreateForms.emplace(formId);
    }
}

bool FormDataMgr::GetUpdatedForm(const FormRecord &record, const std::vector<FormInfo> &targetForms,
    FormInfo &updatedForm)
{
    return g_mockGetUpdatedFormRet;
}

bool FormDataMgr::GetPackageForm(const FormRecord &record, const BundlePackInfo &bundlePackInfo,
    AbilityFormInfo &abilityFormInfo)
{
    return g_mockGetPackageFormRet;
}

void FormDataMgr::GetNoHostTempForms(
    const int uid, std::map<FormIdKey,
    std::set<int64_t>> &noHostTempFormsMap,
    std::map<int64_t, bool> &foundFormsMap)
{
    int64_t formId = 1;
    std::string bundleName = "com.form.start";
    std::string abilityName = "bbbbbb";
    if (false == g_mockGetNoHostTempFormsOne) {
        FormIdKey formIdKey(bundleName, abilityName);
        std::set<int64_t> formIdsSet;
        formIdsSet.emplace(formId);
        noHostTempFormsMap.emplace(formIdKey, formIdsSet);
    }
    if (false == g_mockGetNoHostTempFormsTwo) {
        foundFormsMap.emplace(formId, false);
    }                        
}
}  // namespace AppExecFwk
}  // namespace OHOS
