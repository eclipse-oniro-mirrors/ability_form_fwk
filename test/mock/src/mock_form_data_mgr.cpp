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

ErrCode FormDataMgr::GetFormInstanceById(const int64_t formId, FormInstance &formInstance)
{
    GTEST_LOG_(INFO) << "GetFormInstanceById(2) called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetFormInstanceById2(formId, formInstance);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormDataMgr::GetFormInstanceById(const int64_t formId, bool isUnusedIncluded,
    FormInstance &formInstance)
{
    GTEST_LOG_(INFO) << "GetFormInstanceById(3) called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetFormInstanceById3(formId, isUnusedIncluded, formInstance);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

int32_t FormDataMgr::GetTempFormsCount(int32_t &formCount)
{
    GTEST_LOG_(INFO) << "GetTempFormsCount called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetTempFormsCount(formCount);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

int32_t FormDataMgr::GetCastFormsCount(int32_t &formCount)
{
    GTEST_LOG_(INFO) << "GetCastFormsCount called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetCastFormsCount(formCount);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

int32_t FormDataMgr::GetHostFormsCount(const std::string &bundleName, int32_t &formCount)
{
    GTEST_LOG_(INFO) << "GetHostFormsCount called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetHostFormsCount(bundleName, formCount);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormDataMgr::GetRunningFormInfosByBundleName(const std::string &bundleName,
    bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos, int32_t userId)
{
    GTEST_LOG_(INFO) << "GetRunningFormInfosByBundleName called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetRunningFormInfosByBundleName(
            bundleName, isUnusedIncluded, runningFormInfos, userId);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormDataMgr::GetFormInstancesByFilter(const FormInstancesFilter &filter,
    std::vector<FormInstance> &formInstances)
{
    GTEST_LOG_(INFO) << "GetFormInstancesByFilter called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetFormInstancesByFilter(filter, formInstances);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

bool FormDataMgr::CreateFormStateRecord(std::string &provider, const FormItemInfo &info,
    const sptr<IRemoteObject> &callerToken, int32_t callingUid)
{
    GTEST_LOG_(INFO) << "CreateFormStateRecord called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->CreateFormStateRecord(provider, info, callerToken, callingUid);
    }
    return false;
}

bool FormDataMgr::CreateFormAcquireDataRecord(int64_t requestCode, const FormItemInfo &info,
    const sptr<IRemoteObject> &callerToken, int32_t callingUid)
{
    GTEST_LOG_(INFO) << "CreateFormAcquireDataRecord called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->CreateFormAcquireDataRecord(requestCode, info,
            callerToken, callingUid);
    }
    return false;
}

bool FormDataMgr::GetMatchedHostClient(const sptr<IRemoteObject> &callerToken,
    FormHostRecord &formHostRecord) const
{
    GTEST_LOG_(INFO) << "GetMatchedHostClient called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GetMatchedHostClient(callerToken, formHostRecord);
    }
    return false;
}

ErrCode FormDataMgr::UpdateHostFormFlag(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, bool flag, bool isOnlyEnableUpdate,
    std::vector<int64_t> &refreshForms)
{
    GTEST_LOG_(INFO) << "UpdateHostFormFlag called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->UpdateHostFormFlag(
            formIds, callerToken, flag, isOnlyEnableUpdate, refreshForms);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

bool FormDataMgr::UpdateFormRecord(const int64_t formId, std::function<void(FormRecord &)> updateFunc)
{
    GTEST_LOG_(INFO) << "UpdateFormRecord(func) called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->UpdateFormRecordFunc(formId, updateFunc);
    }
    return false;
}

void FormDataMgr::SetFormVisible(int64_t formId, bool isVisible)
{
    GTEST_LOG_(INFO) << "SetFormVisible called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        AppExecFwk::MockFormDataMgr::obj->SetFormVisible(formId, isVisible);
    }
}

void FormDataMgr::SetExpectRecycledStatus(int64_t formId, bool isExpectRecycled)
{
    GTEST_LOG_(INFO) << "SetExpectRecycledStatus(int64_t) called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        AppExecFwk::MockFormDataMgr::obj->SetExpectRecycledStatus(formId, isExpectRecycled);
    }
}

void FormDataMgr::SetExpectRecycledStatus(const std::vector<int64_t> &formIds, bool isExpectRecycled)
{
    GTEST_LOG_(INFO) << "SetExpectRecycledStatus(vector) called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        AppExecFwk::MockFormDataMgr::obj->SetExpectRecycledStatusVec(formIds, isExpectRecycled);
    }
}

bool FormDataMgr::ExistFormRecord(const int64_t formId) const
{
    GTEST_LOG_(INFO) << "ExistFormRecord called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->ExistFormRecord(formId);
    }
    return false;
}

ErrCode FormDataMgr::NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
    const sptr<IRemoteObject> &callerToken, int32_t userId)
{
    GTEST_LOG_(INFO) << "NotifyFormsVisible called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->NotifyFormsVisible(formIds, isVisible, callerToken, userId);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormDataMgr::SetFormProtect(const int64_t formId, const bool protect)
{
    GTEST_LOG_(INFO) << "SetFormProtect called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->SetFormProtect(formId, protect);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

void FormDataMgr::LockForms(const std::vector<FormRecord> &&formRecords, const bool protect)
{
    GTEST_LOG_(INFO) << "LockForms called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        AppExecFwk::MockFormDataMgr::obj->LockForms(std::move(formRecords), protect);
    }
}

int64_t FormDataMgr::GenerateFormId()
{
    GTEST_LOG_(INFO) << "GenerateFormId called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->GenerateFormId();
    }
    return 0;
}

ErrCode FormDataMgr::AddRequestPublishFormInfo(int64_t formId, const Want &want,
    std::unique_ptr<FormProviderData> &formProviderData)
{
    GTEST_LOG_(INFO) << "AddRequestPublishFormInfo called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->AddRequestPublishFormInfo(formId, want, formProviderData);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormDataMgr::RemoveRequestPublishFormInfo(int64_t formId)
{
    GTEST_LOG_(INFO) << "RemoveRequestPublishFormInfo called";
    if (AppExecFwk::MockFormDataMgr::obj) {
        return AppExecFwk::MockFormDataMgr::obj->RemoveRequestPublishFormInfo(formId);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

void FormDataMgr::UpdateFormHostParams(const int64_t formId, const Want &want)
{
    GTEST_LOG_(INFO) << "UpdateFormHostParams called";
}

bool FormDataMgr::GetFormUpgradeInfo(const int64_t formId, FormUpgradeInfo &formUpgradeInfo) const
{
    GTEST_LOG_(INFO) << "GetFormUpgradeInfo called";
    return false;
}

bool FormDataMgr::UpdateFormUpgradeInfo(const int64_t formId, const FormUpgradeInfo &formUpgradeInfo)
{
    GTEST_LOG_(INFO) << "UpdateFormUpgradeInfo called";
    return false;
}

ErrCode FormDataMgr::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation)
{
    GTEST_LOG_(INFO) << "UpdateFormLocation called";
    return ERR_OK;
}

ErrCode FormDataMgr::SetSpecification(const int64_t formId, const int32_t specification)
{
    GTEST_LOG_(INFO) << "SetSpecification called";
    return ERR_OK;
}

ErrCode FormDataMgr::GetRecordsByFormType(const int32_t formRefreshType,
    std::vector<FormRecord> &visibleFormRecords, std::vector<FormRecord> &invisibleFormRecords)
{
    GTEST_LOG_(INFO) << "GetRecordsByFormType called";
    return ERR_OK;
}

bool FormDataMgr::GetFormRecordByCondition(int32_t conditionType, std::vector<FormRecord> &formInfos) const
{
    GTEST_LOG_(INFO) << "GetFormRecordByCondition called";
    return false;
}

ErrCode FormDataMgr::SetRefreshDuringDisableForm(const int64_t formId, const bool enable)
{
    GTEST_LOG_(INFO) << "SetRefreshDuringDisableForm called";
    return ERR_OK;
}

void FormDataMgr::SetHostTransparentFormColor(const int64_t formId, const std::string &transparencyColor)
{
    GTEST_LOG_(INFO) << "SetHostTransparentFormColor called";
}

void FormDataMgr::DelHostTransparentFormColor(const int64_t formId)
{
    GTEST_LOG_(INFO) << "DelHostTransparentFormColor called";
}
}  // namespace AppExecFwk
}  // namespace OHOS