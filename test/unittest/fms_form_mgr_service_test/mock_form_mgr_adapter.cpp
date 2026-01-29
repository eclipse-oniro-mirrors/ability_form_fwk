/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "form_mgr/form_mgr_adapter.h"
#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"

namespace {
    int g_enableUpdateForm = OHOS::ERR_OK;
    int g_disableUpdateForm = OHOS::ERR_OK;
    int g_addForm = OHOS::ERR_OK;
    int g_deleteForm = OHOS::ERR_OK;
    int g_releaseForm = OHOS::ERR_OK;
    int g_requestForm = OHOS::ERR_OK;
    int g_notifyWhetherVisibleForms = OHOS::ERR_OK;
    int g_castTempForm = OHOS::ERR_OK;
    int g_messageEvent = OHOS::ERR_OK;
    int g_routerEvent = OHOS::ERR_OK;
    int g_deleteInvalidForms = OHOS::ERR_OK;
    int g_acquireFormState = OHOS::ERR_OK;
    int g_notifyFormsVisible = OHOS::ERR_OK;
    int g_notifyFormsEnableUpdate = OHOS::ERR_OK;
    int g_getFormsInfoByApp = OHOS::ERR_OK;
    int g_getFormsInfoByModule = OHOS::ERR_OK;
    int g_updateForm = OHOS::ERR_OK;
    int g_updateFormLocation = OHOS::ERR_OK;
    int g_setPublishFormResult = OHOS::ERR_OK;
    int g_acquireAddFormResult = OHOS::ERR_OK;
    bool g_isRequestPublishFormSupported = true;
    int32_t g_requestPublishForm = OHOS::ERR_OK;
    int g_stopRenderingForm = OHOS::ERR_OK;
    int g_releaseRenderer = OHOS::ERR_OK;
    int g_dumpStorageFormInfos = OHOS::ERR_OK;
    int g_dumpFormInfoByBundleName = OHOS::ERR_OK;
    int g_dumpFormInfoByFormId = OHOS::ERR_OK;
    int g_dumpFormTimerByFormId = OHOS::ERR_OK;
    int g_backgroundEvent = OHOS::ERR_OK;
    int g_registerFormRouterProxy = OHOS::ERR_OK;
    int g_unregisterFormRouterProxy = OHOS::ERR_OK;
    int g_getFormsCount = OHOS::ERR_OK;
    int g_getHostFormsCount = OHOS::ERR_OK;
    int g_getRunningFormInfos = OHOS::ERR_OK;
    int g_getRunningFormInfosByBundleName = OHOS::ERR_OK;
    int g_getFormInstanceById = OHOS::ERR_OK;
    int g_handleFormAddObserver = OHOS::ERR_OK;
    int g_registerAddObserver = OHOS::ERR_OK;
    int g_registerRemoveObserver = OHOS::ERR_OK;
    int g_registerClickEventObserver = OHOS::ERR_OK;
    int g_unregisterClickEventObserver = OHOS::ERR_OK;
    int g_requestoverflow = OHOS::ERR_OK;
    int g_changesceneanimationstate = OHOS::ERR_OK;
    int g_getformrect = OHOS::ERR_OK;
}

void MockEnableUpdateForm(int mockRet)
{
    g_enableUpdateForm = mockRet;
}

void MockDisableUpdateForm(int mockRet)
{
    g_disableUpdateForm = mockRet;
}

void MockAddForm(int mockRet)
{
    g_addForm = mockRet;
}

void MockDeleteForm(int mockRet)
{
    g_deleteForm = mockRet;
}

void MockReleaseForm(int mockRet)
{
    g_releaseForm = mockRet;
}

void MockRequestForm(int mockRet)
{
    g_requestForm = mockRet;
}

void MockNotifyWhetherVisibleForms(int mockRet)
{
    g_notifyWhetherVisibleForms = mockRet;
}

void MockCastTempForm(int mockRet)
{
    g_castTempForm = mockRet;
}

void MockMessageEvent(int mockRet)
{
    g_messageEvent = mockRet;
}

void MockRouterEvent(int mockRet)
{
    g_routerEvent = mockRet;
}

void MockAcquireFormState(int mockRet)
{
    g_acquireFormState = mockRet;
}

void MockNotifyFormsVisible(int mockRet)
{
    g_notifyFormsVisible = mockRet;
}

void MockNotifyFormsEnableUpdate(int mockRet)
{
    g_notifyFormsEnableUpdate = mockRet;
}

void MockGetFormsInfoByApp(int mockRet)
{
    g_getFormsInfoByApp = mockRet;
}

void MockGetFormsInfoByModule(int mockRet)
{
    g_getFormsInfoByModule = mockRet;
}

void MockIsRequestPublishFormSupported(bool mockRet)
{
    g_isRequestPublishFormSupported = mockRet;
}

void MockRrequestPublishForm(int32_t mockRet)
{
    g_requestPublishForm = mockRet;
}

void MockStopRenderingForm(int mockRet)
{
    g_stopRenderingForm = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
int FormMgrAdapter::EnableUpdateForm(const std::vector<int64_t> formIDs, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "EnableUpdateForm called " << g_enableUpdateForm;
    return g_enableUpdateForm;
}

int FormMgrAdapter::DisableUpdateForm(const std::vector<int64_t> formIDs, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "DisableUpdateForm called " << g_disableUpdateForm;
    return g_disableUpdateForm;
}

int FormMgrAdapter::AddForm(
    const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken, FormJsInfo &formInfo)
{
    GTEST_LOG_(INFO) << "AddForm called " << g_addForm;
    return g_addForm;
}

int FormMgrAdapter::DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "DeleteForm called " << g_deleteForm;
    return g_deleteForm;
}

int FormMgrAdapter::ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache)
{
    GTEST_LOG_(INFO) << "ReleaseForm called " << g_releaseForm;
    return g_releaseForm;
}

int FormMgrAdapter::RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want)
{
    GTEST_LOG_(INFO) << "RequestForm called " << g_requestForm;
    return g_requestForm;
}

ErrCode FormMgrAdapter::NotifyWhetherVisibleForms(
    const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType)
{
    GTEST_LOG_(INFO) << "NotifyWhetherVisibleForms called " << g_notifyWhetherVisibleForms;
    return g_notifyWhetherVisibleForms;
}

int FormMgrAdapter::CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "CastTempForm called " << g_castTempForm;
    return g_castTempForm;
}

int FormMgrAdapter::MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "MessageEvent called " << g_messageEvent;
    return g_messageEvent;
}

int FormMgrAdapter::RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "RouterEvent called " << g_routerEvent;
    return g_routerEvent;
}

int FormMgrAdapter::DeleteInvalidForms(
    const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken, int32_t &numFormsDeleted)
{
    GTEST_LOG_(INFO) << "DeleteInvalidForms called " << g_deleteInvalidForms;
    return g_deleteInvalidForms;
}

int FormMgrAdapter::AcquireFormState(
    const Want &want, const sptr<IRemoteObject> &callerToken, FormStateInfo &stateInfo)
{
    GTEST_LOG_(INFO) << "AcquireFormState called " << g_acquireFormState;
    return g_acquireFormState;
}

int FormMgrAdapter::NotifyFormsVisible(
    const std::vector<int64_t> &formIds, bool isVisible, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "NotifyFormsVisible called " << g_notifyFormsVisible;
    return g_notifyFormsVisible;
}

int FormMgrAdapter::NotifyFormsEnableUpdate(
    const std::vector<int64_t> &formIds, bool isEnableUpdate, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "NotifyFormsEnableUpdate called " << g_notifyFormsEnableUpdate;
    return g_notifyFormsEnableUpdate;
}

int FormMgrAdapter::GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByApp called " << g_getFormsInfoByApp;
    return g_getFormsInfoByApp;
}

int FormMgrAdapter::GetFormsInfoByModule(
    const std::string &bundleName, const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByModule called " << g_getFormsInfoByModule;
    return g_getFormsInfoByModule;
}

bool FormMgrAdapter::IsRequestPublishFormSupported()
{
    return g_isRequestPublishFormSupported;
}

ErrCode FormMgrAdapter::RequestPublishForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies, bool needCheckFormPermission)
{
    return g_requestPublishForm;
}

int FormMgrAdapter::UpdateForm(const int64_t formId, const int32_t uid,
    const FormProviderData &formProviderData, const std::vector<FormDataProxy> &formDataProxies)
{
    return g_updateForm;
}

int FormMgrAdapter::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation,
    const bool isRequestPublishFormWithSnapshot)
{
    return g_updateFormLocation;
}

int FormMgrAdapter::SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo)
{
    return g_setPublishFormResult;
}

int FormMgrAdapter::AcquireAddFormResult(const int64_t formId)
{
    return g_acquireAddFormResult;
}

int FormMgrAdapter::StopRenderingForm(const int64_t formId, const std::string &compId)
{
    return g_stopRenderingForm;
}

int FormMgrAdapter::ReleaseRenderer(int64_t formId, const std::string &compId)
{
    return g_releaseRenderer;
}

int FormMgrAdapter::DumpStorageFormInfos(std::string &formInfos) const
{
    return g_dumpStorageFormInfos;
}

int FormMgrAdapter::DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) const
{
    return g_dumpFormInfoByBundleName;
}

int FormMgrAdapter::DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) const
{
    return g_dumpFormInfoByFormId;
}

int FormMgrAdapter::DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) const
{
    return g_dumpFormTimerByFormId;
}

int FormMgrAdapter::BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    return g_backgroundEvent;
}

ErrCode FormMgrAdapter::RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
    return g_registerFormRouterProxy;
}

ErrCode FormMgrAdapter::UnregisterFormRouterProxy(const std::vector<int64_t> &formIds)
{
    return g_unregisterFormRouterProxy;
}

int32_t FormMgrAdapter::GetFormsCount(bool isTempFormFlag, int32_t &formCount)
{
    return g_getFormsCount;
}

int32_t FormMgrAdapter::GetHostFormsCount(std::string &bundleName, int32_t &formCount)
{
    return g_getHostFormsCount;
}

ErrCode FormMgrAdapter::GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos,
    const int32_t userId)
{
    return g_getRunningFormInfos;
}

ErrCode FormMgrAdapter::GetRunningFormInfosByBundleName(
    const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    return g_getRunningFormInfosByBundleName;
}

ErrCode FormMgrAdapter::GetFormInstanceById(const int64_t formId, bool isUnusedIncluded, FormInstance &formInstance)
{
    return g_getFormInstanceById;
}

ErrCode FormMgrAdapter::RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    return g_registerAddObserver;
}

ErrCode FormMgrAdapter::RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    return g_registerRemoveObserver;
}

ErrCode FormMgrAdapter::RegisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    return g_registerClickEventObserver;
}

ErrCode FormMgrAdapter::UnregisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    return g_unregisterClickEventObserver;
}

ErrCode FormMgrAdapter::RequestOverflow(const int64_t formId, const int32_t callingUid,
    const OverflowInfo &overflowInfo, bool isOverflow)
{
    return g_requestoverflow;
}

ErrCode FormMgrAdapter::ChangeSceneAnimationState(const int64_t formId, const int32_t callingUid, int32_t state)
{
    return g_changesceneanimationstate;
}

ErrCode FormMgrAdapter::GetFormRect(const int64_t formId, const int32_t callingUid, Rect &rect)
{
    return g_getformrect;
}
} // namespace AppExecFwk
} // namespace OHOS