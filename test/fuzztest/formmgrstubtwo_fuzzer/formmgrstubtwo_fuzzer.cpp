/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "formmgrstubtwo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_mgr_stub.h"
#undef private
#undef protected
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr uint32_t MESSAGE_BASE = 3001;
constexpr uint32_t MESSAGE_LAST = 3091;
constexpr uint32_t MESSAGE_RANGE = MESSAGE_LAST - MESSAGE_BASE;
constexpr int32_t MAX_LENGTH = 256;

constexpr int32_t ZERO_NUM = 0;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.appexecfwk.FormMgr";

class FormMgrStubFuzzTestTwo : public FormMgrStub {
public:
    FormMgrStubFuzzTestTwo() = default;
    virtual ~FormMgrStubFuzzTestTwo() = default;

    int AddForm(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &callerToken, FormJsInfo &formInfo) override
    {
        return ZERO_NUM;
    }
    int DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) override
    {
        return ZERO_NUM;
    }
    int ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache) override
    {
        return ZERO_NUM;
    }
    int UpdateForm(const int64_t formId, const FormProviderData &formProviderData) override
    {
        return ZERO_NUM;
    }
    int UpdateFormCrossBundle(const int64_t formId, const FormProviderData &formProviderData) override
    {
        return ZERO_NUM;
    }
    int SetNextRefreshTime(const int64_t formId, const int64_t nextTime) override
    {
        return ZERO_NUM;
    }
    ErrCode RequestPublishFormCrossUser(Want &want, int32_t userId, int64_t &formId) override
    {
        return ZERO_NUM;
    }
    ErrCode RequestPublishForm(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId) override
    {
        return ZERO_NUM;
    }
    int LifecycleUpdate(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, bool updateType) override
    {
        return ZERO_NUM;
    }
    int RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want) override
    {
        return ZERO_NUM;
    }
    int NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType) override
    {
        return ZERO_NUM;
    }
    bool HasFormVisible(const uint32_t tokenId) override
    {
        return false;
    }
    int CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) override
    {
        return ZERO_NUM;
    }
    int DumpStorageFormInfos(std::string &formInfos) override
    {
        return ZERO_NUM;
    }
    int DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) override
    {
        return ZERO_NUM;
    }
    int DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) override
    {
        return ZERO_NUM;
    }
    int DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) override
    {
        return ZERO_NUM;
    }
    int MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return ZERO_NUM;
    }
    int RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return ZERO_NUM;
    }
    int BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return ZERO_NUM;
    }
    int DeleteInvalidForms(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, int32_t &numFormsDeleted) override
    {
        return ZERO_NUM;
    }
    int AcquireFormState(const Want &want,
        const sptr<IRemoteObject> &callerToken, FormStateInfo &stateInfo) override
    {
        return ZERO_NUM;
    }
    int NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
        const sptr<IRemoteObject> &callerToken) override
    {
        return ZERO_NUM;
    }
    int NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds,
        bool isProtected, const sptr<IRemoteObject> &callerToken) override
    {
        return ZERO_NUM;
    }
    int NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds, bool isEnableUpdate,
        const sptr<IRemoteObject> &callerToken) override
    {
        return ZERO_NUM;
    }
    int GetAllFormsInfo(std::vector<FormInfo> &formInfos) override
    {
        return ZERO_NUM;
    }
    int GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos) override
    {
        return ZERO_NUM;
    }
    int GetFormsInfoByModule(std::string &bundleName,
        std::string &moduleName, std::vector<FormInfo> &formInfos) override
    {
        return ZERO_NUM;
    }
    int32_t GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos) override
    {
        return ZERO_NUM;
    }
    bool IsRequestPublishFormSupported() override
    {
        return false;
    }
    int32_t StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return ZERO_NUM;
    }
    int32_t ShareForm(int64_t formId, const std::string &deviceId,
        const sptr<IRemoteObject> &callerToken, int64_t requestCode) override
    {
        return ZERO_NUM;
    }
    int32_t AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
         AAFwk::WantParams &formData) override
    {
        return ZERO_NUM;
    }
    int32_t RecvFormShareInfoFromRemote(const FormShareInfo &info) override
    {
        return ZERO_NUM;
    }
    int32_t CheckFMSReady() override
    {
        return ZERO_NUM;
    }
    int32_t SetBackgroundFunction(const std::string funcName, const std::string params) override
    {
        return ZERO_NUM;
    }
    int32_t GetFormsCount(bool isTempFormFlag, int32_t &formCount) override
    {
        return ZERO_NUM;
    }
    int32_t GetHostFormsCount(std::string &bundleName, int32_t &formCount) override
    {
        return ZERO_NUM;
    }
    ErrCode GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos) override
    {
        return ZERO_NUM;
    }
    ErrCode GetRunningFormInfosByBundleName(
        const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos) override
    {
        return ZERO_NUM;
    }
    int32_t GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
        std::vector<FormInstance> &formInstances) override
    {
        return ZERO_NUM;
    }
    ErrCode GetFormInstanceById(const int64_t formId, FormInstance &formInstances) override
    {
        return ZERO_NUM;
    }
    ErrCode RegisterFormAddObserverByBundle(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode RegisterFormRemoveObserverByBundle(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode RegisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer) override
    {
        return ERR_OK;
    }
    ErrCode UnregisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer) override
    {
        return ERR_OK;
    }
    ErrCode RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode UnregisterFormRouterProxy(const std::vector<int64_t> &formIds) override
    {
        return ERR_OK;
    }
    ErrCode RequestPublishFormWithSnapshot(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId) override
    {
        return ZERO_NUM;
    }
    ErrCode SendNonTransparencyRatio(int64_t formId, int32_t ratio) override
    {
        return ERR_OK;
    }

    int CreateForm(const Want &want, RunningFormInfo &runningFormInfo) override
    {
        return ERR_OK;
    }
    int StopRenderingForm(const int64_t formId, const std::string &compId) override
    {
        return ERR_OK;
    }
    int ReleaseRenderer(int64_t formId, const std::string &compId) override
    {
        return ERR_OK;
    }
    ErrCode SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo) override
    {
        return ERR_OK;
    }
    ErrCode AcquireAddFormResult(const int64_t formId) override
    {
        return ERR_OK;
    }
    int GetAllTemplateFormsInfo(std::vector<FormInfo> &formInfos) override
    {
        return ERR_OK;
    }
    int GetTemplateFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos) override
    {
        return ERR_OK;
    }
    int GetTemplateFormsInfoByModule(const std::string &bundleName,
        const std::string &moduleName, std::vector<FormInfo> &formInfos) override
    {
        return ERR_OK;
    }
    int GetFormsInfoByFilter(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos) override
    {
        return ERR_OK;
    }
    int32_t GetPublishedFormInfoById(const int64_t formId, RunningFormInfo &formInfo) override
    {
        return ZERO_NUM;
    }
    int32_t GetPublishedFormInfos(std::vector<RunningFormInfo> &formInfos) override
    {
        return ZERO_NUM;
    }
    bool IsSystemAppForm(const std::string &bundleName) override
    {
        return false;
    }
    int32_t RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback) override
    {
        return ZERO_NUM;
    }
    int32_t UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback) override
    {
        return ZERO_NUM;
    }
    ErrCode UpdateProxyForm(int64_t formId, const FormProviderData &FormProviderData,
        const std::vector<FormDataProxy> &formDataProxies) override
    {
        return ERR_OK;
    }
    ErrCode RequestPublishProxyForm(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
        const std::vector<FormDataProxy> &formDataProxies) override
    {
        return ERR_OK;
    }
    int32_t SetFormsRecyclable(const std::vector<int64_t> &formIds) override
    {
        return ZERO_NUM;
    }
    int32_t RecycleForms(const std::vector<int64_t> &formIds, const Want &want) override
    {
        return ZERO_NUM;
    }
    int32_t RecoverForms(const std::vector<int64_t> &formIds, const Want &want) override
    {
        return ZERO_NUM;
    }
    ErrCode UpdateFormLocation(const int64_t &formId, const int32_t &formLocation) override
    {
        return ERR_OK;
    }
    int32_t BatchRefreshForms(const int32_t formRefreshType) override
    {
        return ZERO_NUM;
    }
    int32_t EnableForms(const std::string bundleName, const int32_t userId, const bool enable) override
    {
        return ZERO_NUM;
    }
    bool IsFormBundleForbidden(const std::string &bundleName) override
    {
        return false;
    }
    int32_t LockForms(const std::vector<FormLockInfo> &formLockInfos,
        OHOS::AppExecFwk::LockChangeType type) override
    {
        return ZERO_NUM;
    }
    bool IsFormBundleProtected(const std::string &bundleName, int64_t formId) override
    {
        return false;
    }
    bool IsFormBundleDebugSignature(const std::string &bundleName) override
    {
        return false;
    }
    bool IsFormBundleExempt(int64_t formId) override
    {
        return false;
    }
    int32_t NotifyFormLocked(const int64_t &formId, bool isLocked) override
    {
        return ZERO_NUM;
    }
    ErrCode UpdateFormSize(const int64_t &formId, float width, float height,
        float borderWidth, float formViewScale) override
    {
        return ERR_OK;
    }
    ErrCode OpenFormEditAbility(const std::string &abilityName,
        const int64_t &formId, bool isMainPage) override
    {
        return ERR_OK;
    }
    ErrCode CloseFormEditAbility(bool isMainPage) override
    {
        return ERR_OK;
    }
    ErrCode RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode UnregisterOverflowProxy() override
    {
        return ERR_OK;
    }
    ErrCode RequestOverflow(const int64_t formId, const OverflowInfo &overflowInfo, bool isOverflow) override
    {
        return ERR_OK;
    }
    ErrCode RegisterChangeSceneAnimationStateProxy(const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode UnregisterChangeSceneAnimationStateProxy() override
    {
        return ERR_OK;
    }
    ErrCode ChangeSceneAnimationState(const int64_t formId, int32_t state) override
    {
        return ERR_OK;
    }
    ErrCode RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode UnregisterGetFormRectProxy() override
    {
        return ERR_OK;
    }
    ErrCode GetFormRect(const int64_t formId, Rect &rect) override
    {
        return ERR_OK;
    }
    ErrCode UpdateFormSize(const int64_t formId, const int32_t newDimension, const Rect &newRect) override
    {
        return ERR_OK;
    }
    ErrCode RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode UnregisterGetLiveFormStatusProxy() override
    {
        return ERR_OK;
    }
    ErrCode ReloadForms(int32_t &reloadNum, const std::string &moduleName,
        const std::string &abilityName, const std::string &formName) override
    {
        return ERR_OK;
    }
    ErrCode ReloadAllForms(int32_t &reloadNum) override
    {
        return ERR_OK;
    }
    bool IsFormDueControl(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy) override
    {
        return false;
    }
    ErrCode RegisterPublishFormCrossBundleControl(const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode UnregisterPublishFormCrossBundleControl() override
    {
        return ERR_OK;
    }
    ErrCode RegisterTemplateFormDetailInfoChange(const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode UnregisterTemplateFormDetailInfoChange() override
    {
        return ERR_OK;
    }
    ErrCode RegisterFormWantCallback(const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode UnregisterFormWantCallback() override
    {
        return ERR_OK;
    }
    ErrCode UpdateTemplateFormDetailInfo(
        const std::vector<TemplateFormDetailInfo> &templateFormInfo) override
    {
        return ERR_OK;
    }
    ErrCode GetFormIdsByFormLocation(int32_t formLocation, std::vector<std::string> &formIds) override
    {
        return ERR_OK;
    }
    ErrCode RegisterUpdateFormsConfigCallback(const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode UnregisterUpdateFormsConfigCallback() override
    {
        return ERR_OK;
    }
    ErrCode UpdateFormsConfig(const std::vector<FormCustomConfig> &configs) override
    {
        return ERR_OK;
    }
    ErrCode RegisterDeleteFormsCallback(const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode UnregisterDeleteFormsCallback() override
    {
        return ERR_OK;
    }
    ErrCode DeleteForms(const std::vector<FormRecordFilter> &filters) override
    {
        return ERR_OK;
    }

    int32_t StartAbilityByFms(const Want &want) override
    {
        return ZERO_NUM;
    }
    ErrCode StartUIAbilityByFms(const Want &want) override
    {
        return ZERO_NUM;
    }
    int32_t StartAbilityByCrossBundle(const Want &want) override
    {
        return ZERO_NUM;
    }
    ErrCode GetFormInstanceById(const int64_t formId, bool isUnusedIncluded,
        FormInstance &formInstance) override
    {
        return ZERO_NUM;
    }
};

void HandleFormMessageTwo(std::shared_ptr<FormMgrStub> formMgrStub, MessageParcel &data, MessageParcel &reply)
{
    if (formMgrStub == nullptr) {
        return;
    }
    formMgrStub->HandleRequestPublishFormCrossUser(data, reply);
    formMgrStub->HandleRegisterFormWantCallback(data, reply);
    formMgrStub->HandleUnregisterFormWantCallback(data, reply);
    formMgrStub->HandleGetPublishedFormInfoById(data, reply);
    formMgrStub->HandleGetPublishedFormInfos(data, reply);
    formMgrStub->HandleStartAbilityByFms(data, reply);
    formMgrStub->HandleStartUIAbilityByFms(data, reply);
    formMgrStub->HandleStartAbilityByCrossBundle(data, reply);
    formMgrStub->HandleRegisterPublishFormInterceptor(data, reply);
    formMgrStub->HandleLockForms(data, reply);
    formMgrStub->HandleIsFormExempt(data, reply);
    formMgrStub->HandleIsFormProtected(data, reply);
    formMgrStub->HandleIsFormDebugSignature(data, reply);
    formMgrStub->HandleNotifyFormLocked(data, reply);
    formMgrStub->HandleUpdateFormSize(data, reply);
    formMgrStub->HandleOpenFormEditAbility(data, reply);
    formMgrStub->HandleCloseFormEditAbility(data, reply);
    formMgrStub->HandleRegisterOverflowProxy(data, reply);
    formMgrStub->HandleUnregisterOverflowProxy(data, reply);
    formMgrStub->HandleRequestOverflow(data, reply);
    formMgrStub->HandleRegisterChangeSceneAnimationStateProxy(data, reply);
    formMgrStub->HandleUnregisterChangeSceneAnimationStateProxy(data, reply);
    formMgrStub->HandleChangeSceneAnimationState(data, reply);
    formMgrStub->HandleRegisterGetFormRectProxy(data, reply);
    formMgrStub->HandleUnregisterGetFormRectProxy(data, reply);
    formMgrStub->HandleGetFormRect(data, reply);
    formMgrStub->HandleNotifyUpdateFormSize(data, reply);
    formMgrStub->HandleRegisterGetLiveFormStatusProxy(data, reply);
    formMgrStub->HandleUnregisterGetLiveFormStatusProxy(data, reply);
    formMgrStub->HandleReloadForms(data, reply);
    formMgrStub->HandleReloadAllForms(data, reply);
    formMgrStub->HandleIsFormDueControl(data, reply);
    formMgrStub->HandleSendNonTransparencyRatio(data, reply);
    formMgrStub->HandleRegisterPublishFormCrossBundleControl(data, reply);
    formMgrStub->HandleUnregisterPublishFormCrossBundleControl(data, reply);
    formMgrStub->HandleRegisterTemplateFormDetailInfoChange(data, reply);
    formMgrStub->HandleUnregisterTemplateFormDetailInfoChange(data, reply);
    formMgrStub->HandleUpdateTemplateFormDetailInfo(data, reply);
    formMgrStub->HandleGetFormIdsByFormLocation(data, reply);
    formMgrStub->HandleRegisterUpdateFormsConfigCallback(data, reply);
    formMgrStub->HandleUnregisterUpdateFormsConfigCallback(data, reply);
    formMgrStub->HandleUpdateFormsConfig(data, reply);
    formMgrStub->HandleRegisterDeleteFormsCallback(data, reply);
    formMgrStub->HandleUnregisterDeleteFormsCallback(data, reply);
    formMgrStub->HandleDeleteForms(data, reply);
    formMgrStub->HandleRecycleForms(data, reply);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    std::string fuzzData = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    uint32_t code = fdp->ConsumeIntegralInRange<uint32_t>(MESSAGE_BASE, MESSAGE_LAST);

    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteBuffer(fuzzData.c_str(), fuzzData.length());
    datas.RewindRead(ZERO_NUM);
    MessageParcel reply;
    MessageOption option;

    std::shared_ptr<FormMgrStub> formMgrStub = std::make_shared<FormMgrStubFuzzTestTwo>();

    formMgrStub->OnRemoteRequest(code, datas, reply, option);

    uint32_t mappedCode = MESSAGE_BASE + code % MESSAGE_RANGE;
    MessageParcel datas2;
    datas2.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas2.WriteBuffer(fuzzData.c_str(), fuzzData.length());
    datas2.RewindRead(ZERO_NUM);
    MessageParcel reply2;
    formMgrStub->OnRemoteRequest(mappedCode, datas2, reply2, option);

    for (uint32_t iterCode = MESSAGE_BASE; iterCode <= MESSAGE_LAST; ++iterCode) {
        MessageParcel parcel;
        parcel.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
        parcel.WriteBuffer(fuzzData.c_str(), fuzzData.length());
        parcel.RewindRead(ZERO_NUM);
        MessageParcel iterReply;
        MessageOption iterOption;
        std::shared_ptr<FormMgrStub> iterStub = std::make_shared<FormMgrStubFuzzTestTwo>();
        iterStub->OnRemoteRequest(iterCode, parcel, iterReply, iterOption);
    }

    HandleFormMessageTwo(formMgrStub, datas, reply);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
