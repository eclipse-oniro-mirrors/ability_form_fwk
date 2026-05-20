/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_MOCK_FORM_DATA_MGR_H
#define OHOS_FORM_FWK_MOCK_FORM_DATA_MGR_H

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>
#include "gmock/gmock.h"
#include "data_center/form_record/form_record.h"
#include "data_center/form_info/form_item_info.h"
#include "form_host/form_host_record.h"
#include "form_info.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "running_form_info.h"
#include "want.h"
#include "form_provider_data.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormDataMgr {
public:
    virtual ~AbstractMockFormDataMgr() = default;
    virtual bool GetFormRecord(const int64_t formId, FormRecord &formRecord) = 0;
    virtual void CheckForms(const std::vector<int64_t> &formIds) = 0;
    // MergeFormWant removed - FormWant::MergeFrom is used directly now
    virtual void SetNeedRefresh(const int64_t formId, const bool needRefresh) = 0;
    virtual bool GetUpdatedForm(const FormRecord &record, const std::vector<FormInfo> &targetForms,
        FormInfo &updatedForm) = 0;
    virtual bool SetRecordNeedFreeInstall(int64_t formId, bool isNeedFreeInstall) = 0;
    virtual bool UpdateFormRecord(const int64_t formId, const FormRecord &formRecord) = 0;
    virtual bool UpdateFormRecordFunc(const int64_t formId,
        std::function<void(FormRecord &)> updateFunc) = 0;
    virtual ErrCode HandleFormAddObserver(const std::string &hostBundleName,
        const int64_t formId, const int32_t userId) = 0;
    virtual bool HasFormCloudUpdateDuration(const std::string &bundleName) = 0;
    virtual int GetFormCloudUpdateDuration(const std::string &bundleName) = 0;
    virtual void UpdateFormCloudUpdateDuration(const std::string &bundleName, int duration) = 0;
    virtual void RemoveFormCloudUpdateDuration(const std::string &bundleName) = 0;
    virtual int64_t FindMatchedFormId(const int64_t formId) = 0;
    virtual bool GetTempFormRecord(std::vector<FormRecord> &formTempRecords) = 0;
    virtual bool GetFormRecordByBundleName(const std::string &bundleName,
        std::vector<FormRecord> &formInfos) const = 0;
    virtual void GetFormHostRecord(const int64_t formId,
        std::vector<FormHostRecord> &formHostRecords) const = 0;
    virtual ErrCode GetRunningFormInfos(bool isUnusedIncluded,
        std::vector<RunningFormInfo> &runningFormInfos, int32_t userId) = 0;
    virtual ErrCode GetFormInstanceById2(const int64_t formId, FormInstance &formInstance) = 0;
    virtual ErrCode GetFormInstanceById3(const int64_t formId, bool isUnusedIncluded,
        FormInstance &formInstance) = 0;
    virtual int32_t GetTempFormsCount(int32_t &formCount) = 0;
    virtual int32_t GetCastFormsCount(int32_t &formCount) = 0;
    virtual int32_t GetHostFormsCount(const std::string &bundleName, int32_t &formCount) = 0;
    virtual ErrCode GetRunningFormInfosByBundleName(const std::string &bundleName,
        bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos, int32_t userId) = 0;
    virtual ErrCode GetFormInstancesByFilter(const FormInstancesFilter &filter,
        std::vector<FormInstance> &formInstances) = 0;
    virtual bool CreateFormStateRecord(std::string &provider, const FormItemInfo &info,
        const sptr<IRemoteObject> &callerToken, int32_t callingUid) = 0;
    virtual bool CreateFormAcquireDataRecord(int64_t requestCode, const FormItemInfo &info,
        const sptr<IRemoteObject> &callerToken, int32_t callingUid) = 0;
    virtual bool GetMatchedHostClient(const sptr<IRemoteObject> &callerToken,
        FormHostRecord &formHostRecord) const = 0;
    virtual ErrCode UpdateHostFormFlag(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, bool flag, bool isOnlyEnableUpdate,
        std::vector<int64_t> &refreshForms) = 0;
    virtual void SetFormVisible(int64_t formId, bool isVisible) = 0;
    virtual void SetExpectRecycledStatus(int64_t formId, bool isExpectRecycled) = 0;
    virtual void SetExpectRecycledStatusVec(const std::vector<int64_t> &formIds, bool isExpectRecycled) = 0;
    virtual bool ExistFormRecord(const int64_t formId) const = 0;
    virtual ErrCode NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
        const sptr<IRemoteObject> &callerToken, int32_t userId) = 0;
    virtual ErrCode SetFormProtect(const int64_t formId, const bool protect) = 0;
    virtual void LockForms(const std::vector<FormRecord> &&formRecords, const bool protect) = 0;
    virtual int64_t GenerateFormId() = 0;
    virtual ErrCode AddRequestPublishFormInfo(int64_t formId, const Want &want,
        std::unique_ptr<FormProviderData> &formProviderData) = 0;
    virtual ErrCode RemoveRequestPublishFormInfo(int64_t formId) = 0;
};

class MockFormDataMgr : public AbstractMockFormDataMgr {
public:
    static std::shared_ptr<MockFormDataMgr> obj;
    MockFormDataMgr() = default;
    ~MockFormDataMgr() override = default;
    MOCK_METHOD4(AllotFormHostRecord, bool(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
        const int64_t formId, const int callingUid));
    MOCK_METHOD2(GetFormRecord, bool(const int64_t formId, FormRecord &formRecord));
    MOCK_METHOD1(CheckForms, void(const std::vector<int64_t> &formIds));
    MOCK_METHOD2(SetNeedRefresh, void(const int64_t formId, const bool needRefresh));
    MOCK_METHOD3(GetUpdatedForm, bool(const FormRecord &record, const std::vector<FormInfo> &targetForms,
        FormInfo &updatedForm));
    MOCK_METHOD2(SetRecordNeedFreeInstall, bool(int64_t formId, bool isNeedFreeInstall));
    MOCK_METHOD2(UpdateFormRecord, bool(const int64_t formId, const FormRecord &formRecord));
    MOCK_METHOD2(UpdateFormRecordFunc, bool(const int64_t formId,
        std::function<void(FormRecord &)> updateFunc));
    MOCK_METHOD3(HandleFormAddObserver, ErrCode(const std::string &hostBundleName,
        const int64_t formId, const int32_t userId));
    MOCK_METHOD1(HasFormCloudUpdateDuration, bool(const std::string &bundleName));
    MOCK_METHOD1(GetFormCloudUpdateDuration, int(const std::string &bundleName));
    MOCK_METHOD2(UpdateFormCloudUpdateDuration, void(const std::string &bundleName, int duration));
    MOCK_METHOD1(RemoveFormCloudUpdateDuration, void(const std::string &bundleName));
    MOCK_METHOD1(FindMatchedFormId, int64_t(const int64_t formId));
    MOCK_METHOD1(GetTempFormRecord, bool(std::vector<FormRecord> &formTempRecords));
    MOCK_CONST_METHOD2(GetFormRecordByBundleName, bool(const std::string &bundleName,
        std::vector<FormRecord> &formInfos));
    MOCK_CONST_METHOD2(GetFormRecordByCondition, bool(int32_t conditionType,
        std::vector<FormRecord> &formInfos));
    MOCK_CONST_METHOD2(GetFormHostRecord, void(const int64_t formId,
        std::vector<FormHostRecord> &formHostRecords));
    MOCK_METHOD3(GetRunningFormInfos, ErrCode(bool isUnusedIncluded,
        std::vector<RunningFormInfo> &runningFormInfos, int32_t userId));
    MOCK_METHOD2(GetFormInstanceById2, ErrCode(const int64_t formId, FormInstance &formInstance));
    MOCK_METHOD3(GetFormInstanceById3, ErrCode(const int64_t formId, bool isUnusedIncluded,
        FormInstance &formInstance));
    MOCK_METHOD1(GetTempFormsCount, int32_t(int32_t &formCount));
    MOCK_METHOD1(GetCastFormsCount, int32_t(int32_t &formCount));
    MOCK_METHOD2(GetHostFormsCount, int32_t(const std::string &bundleName, int32_t &formCount));
    MOCK_METHOD4(GetRunningFormInfosByBundleName, ErrCode(const std::string &bundleName,
        bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos, int32_t userId));
    MOCK_METHOD2(GetFormInstancesByFilter, ErrCode(const FormInstancesFilter &filter,
        std::vector<FormInstance> &formInstances));
    MOCK_METHOD4(CreateFormStateRecord, bool(std::string &provider, const FormItemInfo &info,
        const sptr<IRemoteObject> &callerToken, int32_t callingUid));
    MOCK_METHOD4(CreateFormAcquireDataRecord, bool(int64_t requestCode, const FormItemInfo &info,
        const sptr<IRemoteObject> &callerToken, int32_t callingUid));
    MOCK_CONST_METHOD2(GetMatchedHostClient, bool(const sptr<IRemoteObject> &callerToken,
        FormHostRecord &formHostRecord));
    MOCK_METHOD5(UpdateHostFormFlag, ErrCode(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, bool flag, bool isOnlyEnableUpdate,
        std::vector<int64_t> &refreshForms));
    MOCK_METHOD2(SetFormVisible, void(int64_t formId, bool isVisible));
    MOCK_METHOD2(SetExpectRecycledStatus, void(int64_t formId, bool isExpectRecycled));
    MOCK_METHOD2(SetExpectRecycledStatusVec, void(const std::vector<int64_t> &formIds, bool isExpectRecycled));
    MOCK_CONST_METHOD1(ExistFormRecord, bool(const int64_t formId));
    MOCK_METHOD4(NotifyFormsVisible, ErrCode(const std::vector<int64_t> &formIds, bool isVisible,
        const sptr<IRemoteObject> &callerToken, int32_t userId));
    MOCK_METHOD2(SetFormProtect, ErrCode(const int64_t formId, const bool protect));
    MOCK_METHOD2(LockForms, void(const std::vector<FormRecord> &&formRecords, const bool protect));
    MOCK_METHOD0(GenerateFormId, int64_t());
    MOCK_METHOD3(AddRequestPublishFormInfo, ErrCode(int64_t formId, const Want &want,
        std::unique_ptr<FormProviderData> &formProviderData));
    MOCK_METHOD1(RemoveRequestPublishFormInfo, ErrCode(int64_t formId));
    MOCK_METHOD2(HandleFormRemoveObserver, void(const std::string &, const RunningFormInfo &));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_DATA_MGR_H
