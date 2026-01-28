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

#include "inner/mock_form_data_mgr.h"

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#define private public
#include "data_center/form_data_mgr.h"
#include "form_mgr_errors.h"
#include "common/util/form_util.h"
#undef private
#include "ipc_skeleton.h"

namespace {
    bool g_mockExistTempFormRet = true;
    bool g_mockExistFormRecordRet = true;
    bool g_mockGetMatchedHostClientRet = true;
    bool g_mockGetMatchedHostClientParams = false;
    int32_t g_mockCheckInvalidFormRet = OHOS::ERR_OK;
    int64_t g_mockGetMatchedHostClientParamsMatchedId = 0;
    bool g_mockGetFormRecordRet = true;
    bool g_mockGetFormRecordParams = false;
    bool g_mockGetFormRecordParamsUid = true;
    bool g_mockGetFormRecordParamsSysUid = true;
    bool g_mockGetFormRecordParamsTemp = true;
    bool g_mockDeleteFormRecordRet = true;
    bool g_mockAllotFormHostRecordRet = true;
    bool g_mockGenerateFormIdRet = true;
    bool g_mockGetRequestPublishFormInfoRet = true;
    bool g_mockCheckTempEnoughFormRet = true;
    bool g_mockDeleteFormUserUidRet = true;
    bool g_mockIsRequestPublishForm = true;
    bool g_mockDeleteHostRecord = true;
    bool g_mockHasFormUserUids = true;
    bool g_mockUpdateFormRecord = true;
    bool g_mockUpdateFormRecordParams = false;
    bool g_mockCheckEnoughForm = true;
    bool g_mockDeleteTempForm = true;
    bool g_mockModifyFormTempFlag = true;
    bool g_mockAddFormUserUid = true;
    bool g_mockGetFormHostRecord = false;
    bool g_mockGetRunningFormInfosByFormIdRet = true;
    bool g_mockGetRunningFormInfosRet = true;
    bool g_mockIsDynamic = false;
    bool g_mockIsExistRecycleTask = false;
    OHOS::AAFwk::Want g_mockGetRequestPublishFormInfoWant = {};
    constexpr int32_t UPDATE_DURATION  = 2;
}

void MockExistTempForm(bool mockRet)
{
    g_mockExistTempFormRet = mockRet;
}

void MockExistFormRecord(bool mockRet)
{
    g_mockExistFormRecordRet = mockRet;
}

void MockGetMatchedHostClient(bool mockRet)
{
    g_mockGetMatchedHostClientRet = mockRet;
}

void MockGetMatchedHostClientParams(bool mockRet)
{
    g_mockGetMatchedHostClientParams = mockRet;
}

void MockGetMatchedHostClientParamsMatchedId(int64_t mockRet)
{
    g_mockGetMatchedHostClientParamsMatchedId = mockRet;
}

void MockGetFormRecord(bool mockRet)
{
    g_mockGetFormRecordRet = mockRet;
}

void MockGetFormRecordParams(bool mockRet)
{
    g_mockGetFormRecordParams = mockRet;
}

void MockGetFormRecordParamsUid(bool mockRet)
{
    g_mockGetFormRecordParamsUid = mockRet;
}

void MockGetFormRecordParamsSysUid(bool mockRet)
{
    g_mockGetFormRecordParamsSysUid = mockRet;
}

void MockGetFormRecordParamsTemp(bool mockRet)
{
    g_mockGetFormRecordParamsTemp = mockRet;
}

void MockDeleteFormRecord(bool mockRet)
{
    g_mockDeleteFormRecordRet = mockRet;
}

void MockAllotFormHostRecord(bool mockRet)
{
    g_mockAllotFormHostRecordRet = mockRet;
}

void MockGenerateFormId(bool mockRet)
{
    g_mockGenerateFormIdRet = mockRet;
}

void MockGetRequestPublishFormInfo(bool mockRet)
{
    g_mockGetRequestPublishFormInfoRet = mockRet;
}

void MockGetRequestPublishFormInfoWant(OHOS::AAFwk::Want mockWant)
{
    g_mockGetRequestPublishFormInfoWant = mockWant;
}

void MockCheckTempEnoughForm(bool mockRet)
{
    g_mockCheckTempEnoughFormRet = mockRet;
}

void MockDeleteFormUserUid(bool mockRet)
{
    g_mockDeleteFormUserUidRet = mockRet;
}

void MockIsRequestPublishForm(bool mockRet)
{
    g_mockIsRequestPublishForm = mockRet;
}

void MockDeleteHostRecord(bool mockRet)
{
    g_mockDeleteHostRecord = mockRet;
}

void MockHasFormUserUids(bool mockRet)
{
    g_mockHasFormUserUids = mockRet;
}

void MockUpdateFormRecord(bool mockRet)
{
    g_mockUpdateFormRecord = mockRet;
}

void MockUpdateFormRecordParams(bool mockRet)
{
    g_mockUpdateFormRecordParams = mockRet;
}

void MockCheckEnoughForm(bool mockRet)
{
    g_mockCheckEnoughForm = mockRet;
}

void MockDeleteTempForm(bool mockRet)
{
    g_mockDeleteTempForm = mockRet;
}

void MockModifyFormTempFlag(bool mockRet)
{
    g_mockModifyFormTempFlag = mockRet;
}

void MockAddFormUserUid(bool mockRet)
{
    g_mockAddFormUserUid = mockRet;
}

void MockGetFormHostRecord(bool mockRet)
{
    g_mockGetFormHostRecord = mockRet;
}

void MockCheckInvalidForm(int32_t mockRet)
{
    g_mockCheckInvalidFormRet = mockRet;
}

void MockGetRunningFormInfosByFormId(int32_t mockRet)
{
    g_mockGetRunningFormInfosByFormIdRet = mockRet;
}

void MockGetRunningFormInfos(int32_t mockRet)
{
    g_mockGetRunningFormInfosRet = mockRet;
}

void MockFormRecordIsDynamic(bool mockRet)
{
    g_mockIsDynamic = mockRet;
}

void MockIsExistRecycleTask(bool mockRet)
{
    g_mockIsExistRecycleTask = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormDataMgr::FormDataMgr()
{}

FormDataMgr::~FormDataMgr()
{}

bool FormDataMgr::ExistTempForm(const int64_t formId) const
{
    return g_mockExistTempFormRet;
}

bool FormDataMgr::ExistFormRecord(const int64_t formId) const
{
    return g_mockExistFormRecordRet;
}

bool FormDataMgr::GetMatchedHostClient(const sptr<IRemoteObject> &callerToken, FormHostRecord &formHostRecord) const
{
    if (g_mockGetMatchedHostClientRet && g_mockGetMatchedHostClientParams) {
        int64_t formId = 0x000000007FFFFFFFL;
        if (g_mockGetMatchedHostClientParamsMatchedId > 0) {
            formId = FormDataMgr::GetInstance().FindMatchedFormId(g_mockGetMatchedHostClientParamsMatchedId);
        }
        formHostRecord.forms_[formId] = true;
    }
    return g_mockGetMatchedHostClientRet;
}

bool FormDataMgr::GetFormRecord(const int64_t formId, FormRecord &formRecord) const
{
    if (g_mockGetFormRecordRet && g_mockGetFormRecordParams) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        constexpr int32_t CALLING_UID_TRANSFORM_DIVISOR = 200000;
        constexpr int32_t SYSTEM_UID = 1000;
        if (g_mockGetFormRecordParamsUid) {
            formRecord.userId = callingUid / CALLING_UID_TRANSFORM_DIVISOR;
        } else {
            formRecord.userId = 0;
        }
        formRecord.formUserUids.push_back(callingUid);
        if (g_mockGetFormRecordParamsSysUid) {
            formRecord.formUserUids.push_back(SYSTEM_UID);
        }
        formRecord.providerUserId = FormUtil::GetCurrentAccountId();
        formRecord.formTempFlag = g_mockGetFormRecordParamsTemp;
        formRecord.bundleName = "bundleName";
        formRecord.moduleName = "moduleName";
        formRecord.abilityName = "abilityName";
        formRecord.formName = "formName";
        formRecord.specification = 0;
        formRecord.formVisibleNotify = true;
        formRecord.uid = 0;
        formRecord.updateDuration = UPDATE_DURATION * Constants::TIME_CONVERSION;
        formRecord.isDynamic = g_mockIsDynamic;
        formRecord.isExistRecycleTask = g_mockIsExistRecycleTask;
    }
    return g_mockGetFormRecordRet;
}

bool FormDataMgr::DeleteFormRecord(const int64_t formId)
{
    return g_mockDeleteFormRecordRet;
}

bool FormDataMgr::AllotFormHostRecord(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
    const int64_t formId, const int callingUid)
{
    return g_mockAllotFormHostRecordRet;
}

int64_t FormDataMgr::GenerateFormId()
{
    if (true == g_mockGenerateFormIdRet) {
        return -1;
    }
    return 1;
}

ErrCode FormDataMgr::GetRequestPublishFormInfo(int64_t formId, Want &want,
                                               std::unique_ptr<FormProviderData> &formProviderData)
{
    if (true == g_mockGetRequestPublishFormInfoRet) {
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    want = g_mockGetRequestPublishFormInfoWant;
    return ERR_OK;
}

int FormDataMgr::CheckTempEnoughForm() const
{
    if (true == g_mockCheckTempEnoughFormRet) {
        return ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS;
    }
    return ERR_OK;
}

bool FormDataMgr::DeleteFormUserUid(const int64_t formId, const int uid)
{
    if (true == g_mockDeleteFormUserUidRet) {
        return false;
    }
    return true;
}

bool FormDataMgr::IsRequestPublishForm(int64_t formId)
{
    return g_mockIsRequestPublishForm;
}

bool FormDataMgr::DeleteHostRecord(const sptr<IRemoteObject> &callerToken, const int64_t formId)
{
    return g_mockDeleteHostRecord;
}

bool FormDataMgr::HasFormUserUids(const int64_t formId) const
{
    return g_mockHasFormUserUids;
}

bool FormDataMgr::UpdateFormRecord(const int64_t formId, const FormRecord &formRecord)
{
    return g_mockUpdateFormRecord;
}

int FormDataMgr::CheckEnoughForm(const int callingUid, const int32_t currentUserId) const
{
    if (!g_mockCheckEnoughForm) {
        return ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS;
    }
    return ERR_OK;
}

bool FormDataMgr::DeleteTempForm(const int64_t formId)
{
    return g_mockDeleteTempForm;
}

bool FormDataMgr::ModifyFormTempFlag(const int64_t formId, const bool formTempFlag)
{
    return g_mockModifyFormTempFlag;
}

bool FormDataMgr::AddFormUserUid(const int64_t formId, const int formUserUid)
{
    return g_mockAddFormUserUid;
}

void FormDataMgr::GetFormHostRecord(const int64_t formId, std::vector<FormHostRecord> &formHostRecords) const
{
    if (g_mockGetFormHostRecord) {
        FormHostRecord formRecord = {};
        formHostRecords.push_back(formRecord);
    }
}

ErrCode FormDataMgr::CheckInvalidForm(const int64_t formId, const int32_t userId)
{
    return g_mockCheckInvalidFormRet;
}

ErrCode FormDataMgr::GetRunningFormInfosByFormId(const int64_t formId, RunningFormInfo &runningFormInfo,
    const int32_t userId)
{
    return g_mockGetRunningFormInfosByFormIdRet;
}

ErrCode FormDataMgr::GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos,
    const int32_t userId)
{
    return g_mockGetRunningFormInfosRet;
}

}  // namespace AppExecFwk
}  // namespace OHOS
