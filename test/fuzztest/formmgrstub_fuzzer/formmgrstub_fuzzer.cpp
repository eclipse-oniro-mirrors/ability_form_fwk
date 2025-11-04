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

#include "formmgrstub_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_mgr_stub.h"
#undef private
#undef protected
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MESSAGE_BASE = 3001;
constexpr size_t MESSAGE_MAX = 3077;
constexpr size_t MESSAGE_RANGE = 77;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.appexecfwk.FormMgr";

class FormMgrStubFuzzTest : public FormMgrStub {
public:
    FormMgrStubFuzzTest() = default;
    virtual ~FormMgrStubFuzzTest() = default;
    int AddForm(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &callerToken, FormJsInfo &formInfo) override
    {
        return 0;
    }
    int DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache) override
    {
        return 0;
    }
    int UpdateForm(const int64_t formId, const FormProviderData &formProviderData) override
    {
        return 0;
    }
    int SetNextRefreshTime(const int64_t formId, const int64_t nextTime) override
    {
        return 0;
    }
    ErrCode RequestPublishForm(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId) override
    {
        return 0;
    }
    int LifecycleUpdate(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, bool updateType) override
    {
        return 0;
    }
    int RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want) override
    {
        return 0;
    }
    int NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType) override
    {
        return 0;
    }
    bool HasFormVisible(const uint32_t tokenId) override
    {
        return false;
    }
    int CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int DumpStorageFormInfos(std::string &formInfos) override
    {
        return 0;
    }
    int DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) override
    {
        return 0;
    }
    int DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) override
    {
        return 0;
    }
    int DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) override
    {
        return 0;
    }
    int MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int DeleteInvalidForms(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, int32_t &numFormsDeleted) override
    {
        return 0;
    }
    int AcquireFormState(const Want &want,
        const sptr<IRemoteObject> &callerToken, FormStateInfo &stateInfo) override
    {
        return 0;
    }
    int NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
        const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds,
        bool isProtected, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds, bool isEnableUpdate,
        const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int GetAllFormsInfo(std::vector<FormInfo> &formInfos) override
    {
        return 0;
    }
    int GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos) override
    {
        return 0;
    }
    int GetFormsInfoByModule(std::string &bundleName,
        std::string &moduleName, std::vector<FormInfo> &formInfos) override
    {
        return 0;
    }
    int32_t GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos) override
    {
        return 0;
    }
    bool IsRequestPublishFormSupported() override
    {
        return 0;
    }
    int32_t StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int32_t ShareForm(int64_t formId, const std::string &deviceId,
        const sptr<IRemoteObject> &callerToken, int64_t requestCode) override
    {
        return 0;
    }
    int32_t AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
         AAFwk::WantParams &formData) override
    {
        return 0;
    }
    int32_t RecvFormShareInfoFromRemote(const FormShareInfo &info) override
    {
        return 0;
    }
    int32_t CheckFMSReady() override
    {
        return 0;
    }
    int32_t SetBackgroundFunction(const std::string funcName, const std::string params) override
    {
        return 0;
    }
    int32_t GetFormsCount(bool isTempFormFlag, int32_t &formCount) override
    {
        return 0;
    }
    int32_t GetHostFormsCount(std::string &bundleName, int32_t &formCount) override
    {
        return 0;
    }
    ErrCode GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos) override
    {
        return 0;
    }
    ErrCode GetRunningFormInfosByBundleName(
        const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos) override
    {
        return 0;
    }

    int32_t GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
        std::vector<FormInstance> &formInstances) override
    {
        return 0;
    }
    int32_t GetFormInstanceById(const int64_t formId, FormInstance &formInstances) override
    {
        return 0;
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
    
    ErrCode RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }

    ErrCode UnregisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer) override
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
        return 0;
    }
};

void HandleFormMessage(std::shared_ptr<FormMgrStub> formMgrStub, MessageParcel &data, MessageParcel &reply)
{
    if (formMgrStub == nullptr) {
        return;
    }
    formMgrStub->HandleRegisterFormRemoveObserverByBundle(data, reply);
    formMgrStub->HandleGetFormsCount(data, reply);
    formMgrStub->HandleGetHostFormsCount(data, reply);
    formMgrStub->HandleGetRunningFormInfos(data, reply);
    formMgrStub->HandleGetRunningFormInfosByBundleName(data, reply);
    formMgrStub->HandleGetFormInstanceById(data, reply);
    formMgrStub->HandleGetAllFormsInfo(data, reply);
    formMgrStub->HandleGetFormsInfoByApp(data, reply);
    formMgrStub->HandleGetFormsInfoByModule(data, reply);
    formMgrStub->HandleIsRequestPublishFormSupported(data, reply);
    formMgrStub->HandleShareForm(data, reply);
    formMgrStub->HandleCheckFMSReady(data, reply);
    formMgrStub->HandleDeleteForm(data, reply);
    formMgrStub->HandleStopRenderingForm(data, reply);
    formMgrStub->HandleReleaseForm(data, reply);
    formMgrStub->HandleSetNextRefreshTime(data, reply);
    formMgrStub->HandleLifecycleUpdate(data, reply);
    formMgrStub->HandleRequestForm(data, reply);
    formMgrStub->HandleNotifyWhetherVisibleForms(data, reply);
    formMgrStub->HandleCastTempForm(data, reply);
    formMgrStub->HandleDumpFormInfoByBundleName(data, reply);
    formMgrStub->HandleDumpFormInfoByFormId(data, reply);
    formMgrStub->HandleDumpFormTimerByFormId(data, reply);
    formMgrStub->HandleDeleteInvalidForms(data, reply);
    formMgrStub->HandleNotifyFormsVisible(data, reply);
    formMgrStub->HandleNotifyFormsPrivacyProtected(data, reply);
    formMgrStub->HandleNotifyFormsEnableUpdate(data, reply);
    formMgrStub->HandleRegisterFormAddObserverByBundle(data, reply);
    formMgrStub->HandleAddForm(data, reply);
    formMgrStub->HandleUpdateForm(data, reply);
    formMgrStub->HandleRequestPublishForm(data, reply);
    formMgrStub->HandleMessageEvent(data, reply);
    formMgrStub->HandleBackgroundEvent(data, reply);
    formMgrStub->HandleRouterEvent(data, reply);
    formMgrStub->HandleAcquireFormState(data, reply);
    formMgrStub->HandleGetFormsInfo(data, reply);
    formMgrStub->HandleStartAbility(data, reply);
    formMgrStub->HandleRecvFormShareInfoFromRemote(data, reply);
    formMgrStub->HandleAcquireFormData(data, reply);
    formMgrStub->HandleGetFormInstancesByFilter(data, reply);
}

void HandleFormRequest(std::shared_ptr<FormMgrStub> formMgrStub, MessageParcel &data, MessageParcel &reply)
{
    if (formMgrStub == nullptr) {
        return;
    }
    formMgrStub->HandleCreateForm(data, reply);
    formMgrStub->HandleReleaseRenderer(data, reply);
    formMgrStub->HandleSetPublishFormResult(data, reply);
    formMgrStub->HandleAcquireAddFormResult(data, reply);
    formMgrStub->HandleHasFormVisible(data, reply);
    formMgrStub->HandleDumpStorageFormInfos(data, reply);
    formMgrStub->HandleGetFormsInfoByFilter(data, reply);
    formMgrStub->HandleIsSystemAppForm(data, reply);
    formMgrStub->HandleRegisterAddObserver(data, reply);
    formMgrStub->HandleRegisterRemoveObserver(data, reply);
    formMgrStub->HandleRegisterFormRouterProxy(data, reply);
    formMgrStub->HandleUnregisterFormRouterProxy(data, reply);
    formMgrStub->HandleUpdateProxyForm(data, reply);
    formMgrStub->HandleRequestPublishProxyForm(data, reply);
    formMgrStub->HandleUnregisterPublishFormInterceptor(data, reply);
    formMgrStub->HandleRegisterClickCallbackEventObserver(data, reply);
    formMgrStub->HandleUnregisterClickCallbackEventObserver(data, reply);
    std::vector<FormDataProxy> formDataProxies;
    formMgrStub->ReadFormDataProxies(data, formDataProxies);
    formMgrStub->HandleSetFormsRecyclable(data, reply);
    formMgrStub->HandleRecoverForms(data, reply);
    formMgrStub->HandleUpdateFormLocation(data, reply);
    formMgrStub->HandleRequestPublishFormWithSnapshot(data, reply);
    formMgrStub->HandleBatchRefreshForms(data, reply);
    formMgrStub->HandleEnableForms(data, reply);
    formMgrStub->HandleIsFormBundleForbidden(data, reply);
}

uint32_t GetU32Data(const char* ptr)
{
    // 将第0个数字左移24位，将第1个数字左移16位，将第2个数字左移8位，第3个数字不左移
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    uint32_t code = GetU32Data(data);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<FormMgrStub> formmgrstub = std::make_shared<FormMgrStubFuzzTest>();
    formmgrstub->OnRemoteRequest(code, datas, reply, option);
    code = MESSAGE_BASE + code % MESSAGE_RANGE;
    formmgrstub->OnRemoteRequest(code, datas, reply, option);
    for (uint32_t code = MESSAGE_BASE; code < MESSAGE_MAX; code++) {
        MessageParcel parcel;
        parcel.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
        parcel.WriteBuffer(data, size);
        parcel.RewindRead(0);
        MessageParcel reply;
        MessageOption option;
        std::shared_ptr<FormMgrStub> formMgrStub = std::make_shared<FormMgrStubFuzzTest>();
        formMgrStub->OnRemoteRequest(code, parcel, reply, option);
    }
    HandleFormMessage(formmgrstub, datas, reply);
    HandleFormRequest(formmgrstub, datas, reply);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

