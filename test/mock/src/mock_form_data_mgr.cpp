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

#include "mock_form_data_mgr.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "data_center/form_data_mgr.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormDataMgr> MockFormDataMgr::obj = nullptr;

bool FormDataMgr::GetFormRecord(const int64_t formId, FormRecord &formRecord) const
{
    GTEST_LOG_(INFO) << "GetFormRecord called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetFormRecord(formId, formRecord);
    }
    formRecord = FormRecord();
    return false;
}

void FormDataMgr::CheckForms(const std::vector<int64_t> &formIds)
{
    GTEST_LOG_(INFO) << "CheckForms called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        AppExecFwk::MockFormDataMgr::obj->CheckForms(formIds);
    }
}

bool FormDataMgr::GetUpdatedForm(const FormRecord &record, const std::vector<FormInfo> &targetForms,
    FormInfo &updatedForm)
{
    GTEST_LOG_(INFO) << "GetUpdatedForm called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetUpdatedForm(record, targetForms, updatedForm);
    }
    updatedForm = FormInfo();
    return false;
}

void FormDataMgr::SetNeedRefresh(const int64_t formId, const bool needRefresh)
{
    GTEST_LOG_(INFO) << "SetNeedRefresh called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        AppExecFwk::MockFormDataMgr::obj->SetNeedRefresh(formId, needRefresh);
    }
}

bool FormDataMgr::SetRecordNeedFreeInstall(int64_t formId, bool isNeedFreeInstall)
{
    GTEST_LOG_(INFO) << "SetRecordNeedFreeInstall called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->SetRecordNeedFreeInstall(formId, isNeedFreeInstall);
    }
    return false;
}

bool FormDataMgr::UpdateFormRecord(const int64_t formId, const FormRecord &formRecord)
{
    GTEST_LOG_(INFO) << "UpdateFormRecord called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->UpdateFormRecord(formId, formRecord);
    }
    return false;
}

ErrCode FormDataMgr::HandleFormAddObserver(const std::string &hostBundleName,
    const int64_t formId, const int32_t userId)
{
    GTEST_LOG_(INFO) << "HandleFormAddObserver called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->HandleFormAddObserver(hostBundleName, formId, userId);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

bool FormDataMgr::HasFormCloudUpdateDuration(const std::string &bundleName) const
{
    GTEST_LOG_(INFO) << "HasFormCloudUpdateDuration called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->HasFormCloudUpdateDuration(bundleName);
    }
    return false;
}

int FormDataMgr::GetFormCloudUpdateDuration(const std::string &bundleName) const
{
    GTEST_LOG_(INFO) << "GetFormCloudUpdateDuration called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetFormCloudUpdateDuration(bundleName);
    }
    return 0;
}

void FormDataMgr::UpdateFormCloudUpdateDuration(const std::string &bundleName, int duration)
{
    GTEST_LOG_(INFO) << "UpdateFormCloudUpdateDuration called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        AppExecFwk::MockFormDataMgr::obj->UpdateFormCloudUpdateDuration(bundleName, duration);
    }
}

void FormDataMgr::RemoveFormCloudUpdateDuration(const std::string &bundleName)
{
    GTEST_LOG_(INFO) << "RemoveFormCloudUpdateDuration called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        AppExecFwk::MockFormDataMgr::obj->RemoveFormCloudUpdateDuration(bundleName);
    }
}

int64_t FormDataMgr::FindMatchedFormId(const int64_t formId)
{
    GTEST_LOG_(INFO) << "FindMatchedFormId called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->FindMatchedFormId(formId);
    }
    return formId;
}

bool FormDataMgr::GetTempFormRecord(std::vector<FormRecord> &formTempRecords)
{
    GTEST_LOG_(INFO) << "GetTempFormRecord called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetTempFormRecord(formTempRecords);
    }
    return false;
}

bool FormDataMgr::GetFormRecord(const std::string &bundleName,
    std::vector<FormRecord> &formInfos, int32_t userId) const
{
    GTEST_LOG_(INFO) << "GetFormRecord(bundleName) called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetFormRecordByBundleName(bundleName, formInfos);
    }
    return false;
}

void FormDataMgr::GetFormHostRecord(const int64_t formId,
    std::vector<FormHostRecord> &formHostRecords) const
{
    GTEST_LOG_(INFO) << "GetFormHostRecord called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        AppExecFwk::MockFormDataMgr::obj->GetFormHostRecord(formId, formHostRecords);
    }
}

ErrCode FormDataMgr::GetRunningFormInfos(bool isUnusedIncluded,
    std::vector<RunningFormInfo> &runningFormInfos, int32_t userId)
{
    GTEST_LOG_(INFO) << "GetRunningFormInfos called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetRunningFormInfos(
            isUnusedIncluded, runningFormInfos, userId);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}
}  // namespace AppExecFwk
}  // namespace OHOS