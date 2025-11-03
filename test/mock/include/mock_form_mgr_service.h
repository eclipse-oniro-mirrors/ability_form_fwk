/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_FORM_FWK_MOCK_FORM_MGR_SERVICE_H
#define OHOS_FORM_FWK_MOCK_FORM_MGR_SERVICE_H

#include <gtest/gtest.h>
#include "gmock/gmock.h"
#include "form_mgr_stub.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "message_parcel.h"
namespace OHOS {
namespace AppExecFwk {
class MockFormMgrService : public FormMgrStub {
public:
    MOCK_METHOD4(AddForm, int(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &callerToken, FormJsInfo &formInfo));
    MOCK_METHOD2(DeleteForm, int(const int64_t formId, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD3(ReleaseForm, int(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache));
    MOCK_METHOD2(UpdateForm, int(const int64_t formId, const FormProviderData &formProviderData));
    MOCK_METHOD2(SetNextRefreshTime, int(const int64_t formId, const int64_t nextTime));
    MOCK_METHOD4(RequestPublishForm, ErrCode(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId));
    MOCK_METHOD3(LifecycleUpdate, int(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
        bool updateType));
    MOCK_METHOD3(RequestForm, int(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want));
    MOCK_METHOD3(NotifyWhetherVisibleForms, int(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType));
    MOCK_METHOD1(HasFormVisible, bool(const uint32_t tokenId));
    MOCK_METHOD2(CreateForm, int(const Want &want, RunningFormInfo &runningFormInfo));
    MOCK_METHOD2(CastTempForm, int(const int64_t formId, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD1(DumpStorageFormInfos, int(std::string &formInfos));
    MOCK_METHOD2(DumpFormInfoByBundleName, int(const std::string &bundleName, std::string &formInfos));
    MOCK_METHOD2(DumpFormInfoByFormId, int(const std::int64_t formId, std::string &formInfo));
    MOCK_METHOD2(DumpFormTimerByFormId, int(const std::int64_t formId, std::string &isTimingService));
    MOCK_METHOD3(MessageEvent, int(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD3(RouterEvent, int(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD3(BackgroundEvent, int(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD3(DeleteInvalidForms, int(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
        int32_t &numFormsDeleted));
    MOCK_METHOD3(AcquireFormState, int(const Want &want, const sptr<IRemoteObject> &callerToken,
        FormStateInfo &stateInfo));

    MOCK_METHOD3(NotifyFormsVisible, int(const std::vector<int64_t> &formIds, bool isVisible,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD3(NotifyFormsPrivacyProtected, int(const std::vector<int64_t> &formIds, bool isProtected,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD3(NotifyFormsEnableUpdate, int(const std::vector<int64_t> &formIds, bool isEnableUpdate,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD1(GetAllFormsInfo, int(std::vector<FormInfo> &formInfos));
    MOCK_METHOD2(GetFormsInfoByApp, int(std::string &bundleName, std::vector<FormInfo> &formInfos));
    MOCK_METHOD3(GetFormsInfoByModule, int(std::string &bundleName, std::string &moduleName,
        std::vector<FormInfo> &formInfos));
    MOCK_METHOD2(GetFormsInfoByFilter, int(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos));
    MOCK_METHOD2(GetFormsInfo, int(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos));
    MOCK_METHOD2(GetPublishedFormInfoById, int32_t(const int64_t formId, RunningFormInfo &formInfo));
    MOCK_METHOD1(GetPublishedFormInfos, int32_t(std::vector<RunningFormInfo> &formInfos));
    MOCK_METHOD0(IsRequestPublishFormSupported, bool());
    MOCK_METHOD2(StartAbility, int32_t(const Want &want, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD4(ShareForm, int32_t(int64_t, const std::string&, const sptr<IRemoteObject>&, int64_t));
    MOCK_METHOD1(RecvFormShareInfoFromRemote, int32_t(const FormShareInfo&));
    MOCK_METHOD0(CheckFMSReady, int32_t());
    MOCK_METHOD2(StopRenderingForm, int32_t(const int64_t formId, const std::string &compId));
    MOCK_METHOD2(SetBackgroundFunction, int32_t(const std::string funcName, const std::string params));
    MOCK_METHOD4(AcquireFormData, int32_t(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
        AAFwk::WantParams &formData));
    MOCK_METHOD2(GetFormsCount, int32_t(bool isTempFormFlag, int32_t &formCount));
    MOCK_METHOD2(GetHostFormsCount, int32_t(std::string &bundleName, int32_t &formCount));
    MOCK_METHOD2(GetRunningFormInfos, ErrCode(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos));
    MOCK_METHOD3(GetRunningFormInfosByBundleName,
        ErrCode(const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos));
    MOCK_METHOD2(GetFormInstancesByFilter, int32_t(const FormInstancesFilter &formInstancesFilter,
        std::vector<FormInstance> &formInstances));
    MOCK_METHOD2(GetFormInstanceById, int32_t(const int64_t formId, FormInstance &formInstances));
    MOCK_METHOD2(RegisterFormAddObserverByBundle, ErrCode(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD2(RegisterFormRemoveObserverByBundle, ErrCode(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD2(RegisterAddObserver, ErrCode(const std::string &bundleName, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD2(RegisterRemoveObserver, ErrCode(const std::string &bundleName,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD3(UpdateProxyForm, ErrCode(const int64_t formId, const FormProviderData &formProviderData,
        const std::vector<FormDataProxy> &formDataProxies));
    MOCK_METHOD5(RequestPublishProxyForm, ErrCode(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
        const std::vector<FormDataProxy> &formDataProxies));
    MOCK_METHOD3(GetFormInstanceById, int32_t(int64_t formId, bool isUnusedIncluded, FormInstance &formInstances));
    MOCK_METHOD1(RegisterPublishFormInterceptor, int32_t(const sptr<IRemoteObject> &interceptorCallback));
    MOCK_METHOD1(UnregisterPublishFormInterceptor, int32_t(const sptr<IRemoteObject> &interceptorCallback));
    MOCK_METHOD3(RegisterClickEventObserver, ErrCode(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer));
    MOCK_METHOD3(UnregisterClickEventObserver, ErrCode(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer));
    MOCK_METHOD2(RegisterFormRouterProxy, ErrCode(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD1(UnregisterFormRouterProxy, ErrCode(const std::vector<int64_t> &formIds));
    MOCK_METHOD1(SetFormsRecyclable, int32_t(const std::vector<int64_t> &formIds));
    MOCK_METHOD2(RecycleForms, int32_t(const std::vector<int64_t> &formIds, const Want &want));
    MOCK_METHOD2(RecoverForms, int32_t(const std::vector<int64_t> &formIds, const Want &want));
    MOCK_METHOD2(UpdateFormLocation, ErrCode(const int64_t &formId, const int32_t &formLocation));
    MOCK_METHOD2(SetPublishFormResult, ErrCode(const int64_t formId, Constants::PublishFormResult &errorCodeInfo));
    MOCK_METHOD1(AcquireAddFormResult, ErrCode(const int64_t formId));
    MOCK_METHOD4(RequestPublishFormWithSnapshot, ErrCode(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId));
    MOCK_METHOD1(BatchRefreshForms, ErrCode(const int32_t formRefreshType));
    MOCK_METHOD3(EnableForms, ErrCode(const std::string bundleName, const int32_t userId, const bool enable));
    MOCK_METHOD2(ReleaseRenderer, ErrCode(int64_t formId, const std::string &compId));
    MOCK_METHOD1(IsSystemAppForm, bool(const std::string &bundleName));
    MOCK_METHOD1(StartAbilityByFms, int32_t(const Want &want));
    MOCK_METHOD2(IsFormBundleProtected, bool(const std::string &bundleName, int64_t formId));
    MOCK_METHOD1(IsFormBundleExempt, bool(int64_t formId));
    MOCK_METHOD2(NotifyFormLocked, int32_t(const int64_t &formId, bool isLocked));
    MOCK_METHOD4(UpdateFormSize, ErrCode(const int64_t &formId, float width, float height, float borderWidth));
    MOCK_METHOD2(LockForms, int32_t(const std::vector<FormLockInfo> &formLockInfos, LockChangeType type));
    MOCK_METHOD3(OpenFormEditAbility, ErrCode(const std::string &abilityName, const int64_t &formId, bool isMainPage));
    MOCK_METHOD3(RequestOverflow, ErrCode(const int64_t formId, const OverflowInfo &overflowInfo, bool isOverflow));
    MOCK_METHOD2(ChangeSceneAnimationState, ErrCode(const int64_t formId, int32_t state));
    MOCK_METHOD2(GetFormRect, ErrCode(const int64_t formId, Rect &rect));
    MOCK_METHOD1(RegisterGetFormRectProxy, bool(const sptr<IRemoteObject> &observer));
    MOCK_METHOD0(UnregisterGetFormRectProxy, bool());
    MOCK_METHOD1(RegisterGetLiveFormStatusProxy, bool(const sptr<IRemoteObject> &observer));
    MOCK_METHOD0(UnregisterGetLiveFormStatusProxy, bool());
    MOCK_METHOD4(ReloadForms, ErrCode(int32_t &reloadNum, const std::string &moduleName,
        const std::string &abilityName, const std::string &formName));
    MOCK_METHOD1(ReloadAllForms, ErrCode(int32_t &reloadNum));
    MOCK_METHOD2(IsFormDueControl, bool(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy));
};
}
}
#endif // OHOS_FORM_FWK_MOCK_FORM_MGR_SERVICE_H
