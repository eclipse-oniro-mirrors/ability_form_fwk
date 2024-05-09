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
#ifndef OHOS_FORM_FWK_MOCK_FORM_MGR_PROXY_H
#define OHOS_FORM_FWK_MOCK_FORM_MGR_PROXY_H

#include <gtest/gtest.h>
#include "gmock/gmock.h"
#include "form_mgr_proxy.h"
#include "form_provider_data.h"

namespace OHOS {
namespace AppExecFwk {
class MockFormMgrProxy : public FormMgrProxy {
public:
    MockFormMgrProxy(const sptr<IRemoteObject> &impl) : FormMgrProxy(impl) {};
    MOCK_METHOD2(GetFormsInfo, int(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos));
    MOCK_METHOD0(IsRequestPublishFormSupported, bool());
    MOCK_METHOD2(StartAbility, int32_t(const Want &want, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD2(UpdateForm, int32_t(int64_t formId, const FormProviderData &formBindingData));
    MOCK_METHOD3(RequestForm, int32_t(int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want));
    MOCK_METHOD3(MessageEvent, int32_t(int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD3(NotifyFormsPrivacyProtected, int(const std::vector<int64_t> &formIds, bool isProtected,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD1(HasFormVisible, bool(const uint32_t tokenId));
    MOCK_METHOD2(CreateForm, int(const Want &want, RunningFormInfo &runningFormInfo));
    MOCK_METHOD1(DumpStorageFormInfos, int(std::string &formInfos));
    MOCK_METHOD2(DumpFormInfoByFormId, int(int64_t formId, std::string &formInfos));
    MOCK_METHOD2(DumpFormTimerByFormId, int(int64_t formId, std::string &isTimingService));
    MOCK_METHOD3(RouterEvent, int(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD3(NotifyFormsVisible, int(const std::vector<int64_t> &formIds, bool isProtected,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD3(DeleteInvalidForms, int(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
        int32_t &numFormsDeleted));
    MOCK_METHOD3(NotifyFormsEnableUpdate, int(const std::vector<int64_t> &formIds, bool isProtected,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD1(GetAllFormsInfo, int(std::vector<FormInfo> &formInfos));
    MOCK_METHOD2(GetFormsInfoByApp, int(std::string &bundleName, std::vector<FormInfo> &formInfos));
    MOCK_METHOD3(GetFormsInfoByModule, int(std::string &bundleName, std::string &moduleName,
        std::vector<FormInfo> &formInfos));
    MOCK_METHOD2(GetFormsInfoByFilter, int(const FormInfoFilter &filter,
        std::vector<FormInfo> &formInfos));
    MOCK_METHOD2(DumpFormInfoByBundleName, int(const std::string &bundleName, std::string &formInfos));
    MOCK_METHOD3(AcquireFormState, int(const Want &want, const sptr<IRemoteObject> &callerToken,
        FormStateInfo &stateInfo));
    MOCK_METHOD0(CheckFMSReady, bool());
    MOCK_METHOD3(NotifyWhetherVisibleForms, int(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType));
    MOCK_METHOD2(CastTempForm, int(const int64_t formId, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD0(Reconnect, bool());
    MOCK_METHOD4(ShareForm, int(int64_t formId, const std::string &remoteDeviceId,
        const sptr<IRemoteObject> &callerToken, int64_t requestCode));
    MOCK_METHOD2(DeleteForm, int(const int64_t formId, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD3(ReleaseForm, int(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache));
    MOCK_METHOD2(SetBackgroundFunction, int32_t(const std::string funcName, const std::string params));
    MOCK_METHOD4(AcquireFormData, int32_t(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
         AAFwk::WantParams &formData));
    MOCK_METHOD2(GetFormsCount, int32_t(bool isTempFormFlag, int32_t &formCount));
    MOCK_METHOD2(GetHostFormsCount, int32_t(std::string &bundleName, int32_t &formCount));
    MOCK_METHOD2(GetRunningFormInfos, ErrCode(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos));
    MOCK_METHOD3(GetRunningFormInfosByBundleName,
        ErrCode(const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos));
    MOCK_METHOD2(RegisterFormAddObserverByBundle, ErrCode(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD2(RegisterFormRemoveObserverByBundle, ErrCode(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD3(UpdateProxyForm, ErrCode(const int64_t formId, const FormProviderData &formProviderData,
        const std::vector<FormDataProxy> &formDataProxies));
    MOCK_METHOD5(RequestPublishProxyForm, ErrCode(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
        const std::vector<FormDataProxy> &formDataProxies));
    MOCK_METHOD3(BackgroundEvent, int(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD1(RegisterPublishFormInterceptor, int32_t(const sptr<IRemoteObject> &interceptorCallback));
    MOCK_METHOD1(UnregisterPublishFormInterceptor, int32_t(const sptr<IRemoteObject> &interceptorCallback));
    MOCK_METHOD2(RegisterAddObserver, ErrCode(const std::string &bundleName, const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD2(RegisterRemoveObserver, ErrCode(const std::string &bundleName,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD2(RegisterFormRouterProxy, ErrCode(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken));
    MOCK_METHOD1(UnregisterFormRouterProxy, ErrCode(const std::vector<int64_t> &formIds));
    MOCK_METHOD2(UpdateFormLocation, ErrCode(const int64_t &formId, const int32_t &formLocation));
    MOCK_METHOD3(RegisterClickEventObserver,
        ErrCode(const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observe));
    MOCK_METHOD3(UnregisterClickEventObserver,
        ErrCode(const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observe));
    MOCK_METHOD1(SetFormsRecyclable, int32_t(const std::vector<int64_t> &formIds));
    MOCK_METHOD2(RecycleForms, int32_t(const std::vector<int64_t> &formIds, const Want &want));
    MOCK_METHOD2(RecoverForms, int32_t(const std::vector<int64_t> &formIds, const Want &want));
    MOCK_METHOD2(SetPublishFormResult, ErrCode(const int64_t formId, Constants::PublishFormResult &errorCodeInfo));
    MOCK_METHOD1(AcquireAddFormResult, ErrCode(const int64_t formId));
};
}
}
#endif // OHOS_FORM_FWK_MOCK_FORM_MGR_PROXY_H
