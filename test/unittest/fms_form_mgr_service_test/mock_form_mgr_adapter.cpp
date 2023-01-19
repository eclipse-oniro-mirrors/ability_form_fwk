/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "form_mgr_adapter.h"
#include "form_mgr_errors.h"
#include "hilog_wrapper.h"

namespace {
    int enableUpdateForm = OHOS::ERR_OK;
    int disableUpdateForm = OHOS::ERR_OK;
    int addForm = OHOS::ERR_OK;
    int deleteForm = OHOS::ERR_OK;
    int releaseForm = OHOS::ERR_OK;
    int requestForm = OHOS::ERR_OK;
    int notifyWhetherVisibleForms = OHOS::ERR_OK;
    int castTempForm = OHOS::ERR_OK;
    int messageEvent = OHOS::ERR_OK;
    int routerEvent = OHOS::ERR_OK;
    int deleteInvalidForms = OHOS::ERR_OK;
    int acquireFormState = OHOS::ERR_OK;
    int notifyFormsVisible = OHOS::ERR_OK;
    int notifyFormsEnableUpdate = OHOS::ERR_OK;
    int getFormsInfoByApp = OHOS::ERR_OK;
    int getFormsInfoByModule = OHOS::ERR_OK;
    int updateForm = OHOS::ERR_OK;
    bool isRequestPublishFormSupported = true;
}

void MockEnableUpdateForm(int mockRet)
{
    enableUpdateForm = mockRet;
}

void MockDisableUpdateForm(int mockRet)
{
    disableUpdateForm = mockRet;
}

void MockAddForm(int mockRet)
{
    addForm = mockRet;
}

void MockDeleteForm(int mockRet)
{
    deleteForm = mockRet;
}

void MockReleaseForm(int mockRet)
{
    releaseForm = mockRet;
}

void MockRequestForm(int mockRet)
{
    requestForm = mockRet;
}

void MockNotifyWhetherVisibleForms(int mockRet)
{
    notifyWhetherVisibleForms = mockRet;
}

void MockCastTempForm(int mockRet)
{
    castTempForm = mockRet;
}

void MockMessageEvent(int mockRet)
{
    messageEvent = mockRet;
}

void MockRouterEvent(int mockRet)
{
    routerEvent = mockRet;
}

void MockAcquireFormState(int mockRet)
{
    acquireFormState = mockRet;
}

void MockNotifyFormsVisible(int mockRet)
{
    notifyFormsVisible = mockRet;
}

void MockNotifyFormsEnableUpdate(int mockRet)
{
    notifyFormsEnableUpdate = mockRet;
}

void MockGetFormsInfoByApp(int mockRet)
{
    getFormsInfoByApp = mockRet;
}

void MockGetFormsInfoByModule(int mockRet)
{
    getFormsInfoByModule = mockRet;
}

void MockIsRequestPublishFormSupported(bool mockRet)
{
    isRequestPublishFormSupported = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
int FormMgrAdapter::EnableUpdateForm(const std::vector<int64_t> formIDs, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "EnableUpdateForm called " << enableUpdateForm;
    return enableUpdateForm;
}

int FormMgrAdapter::DisableUpdateForm(const std::vector<int64_t> formIDs, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "DisableUpdateForm called " << disableUpdateForm;
    return disableUpdateForm;
}

int FormMgrAdapter::AddForm(
    const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken, FormJsInfo &formInfo)
{
    GTEST_LOG_(INFO) << "AddForm called " << addForm;
    return addForm;
}

int FormMgrAdapter::DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "DeleteForm called " << deleteForm;
    return deleteForm;
}

int FormMgrAdapter::ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache)
{
    GTEST_LOG_(INFO) << "ReleaseForm called " << releaseForm;
    return releaseForm;
}

int FormMgrAdapter::RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want)
{
    GTEST_LOG_(INFO) << "RequestForm called " << requestForm;
    return requestForm;
}

ErrCode FormMgrAdapter::NotifyWhetherVisibleForms(
    const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType)
{
    GTEST_LOG_(INFO) << "NotifyWhetherVisibleForms called " << notifyWhetherVisibleForms;
    return notifyWhetherVisibleForms;
}

int FormMgrAdapter::CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "CastTempForm called " << castTempForm;
    return castTempForm;
}

int FormMgrAdapter::MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "MessageEvent called " << messageEvent;
    return messageEvent;
}

int FormMgrAdapter::RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "RouterEvent called " << routerEvent;
    return routerEvent;
}

int FormMgrAdapter::DeleteInvalidForms(
    const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken, int32_t &numFormsDeleted)
{
    GTEST_LOG_(INFO) << "DeleteInvalidForms called " << deleteInvalidForms;
    return deleteInvalidForms;
}

int FormMgrAdapter::AcquireFormState(
    const Want &want, const sptr<IRemoteObject> &callerToken, FormStateInfo &stateInfo)
{
    GTEST_LOG_(INFO) << "AcquireFormState called " << acquireFormState;
    return acquireFormState;
}

int FormMgrAdapter::NotifyFormsVisible(
    const std::vector<int64_t> &formIds, bool isVisible, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "NotifyFormsVisible called " << notifyFormsVisible;
    return notifyFormsVisible;
}

int FormMgrAdapter::NotifyFormsEnableUpdate(
    const std::vector<int64_t> &formIds, bool isEnableUpdate, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "NotifyFormsEnableUpdate called " << notifyFormsEnableUpdate;
    return notifyFormsEnableUpdate;
}

int FormMgrAdapter::GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByApp called " << getFormsInfoByApp;
    return getFormsInfoByApp;
}

int FormMgrAdapter::GetFormsInfoByModule(
    const std::string &bundleName, const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByModule called " << getFormsInfoByModule;
    return getFormsInfoByModule;
}

bool FormMgrAdapter::IsRequestPublishFormSupported()
{
    return isRequestPublishFormSupported;
}

int FormMgrAdapter::UpdateForm(
    const int64_t formId, const std::string &bundleName, const FormProviderData &formProviderData)
{
    return updateForm;
}
} // namespace AppExecFwk
} // namespace OHOS