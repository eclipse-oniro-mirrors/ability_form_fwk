/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include <cstdlib>
#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_ipc_handlers.h"
#include "form_mgr_stub.h"
#undef private
#undef protected
#include "form_ipc_dispatch_table.h"
#include "form_stub_access_checker.h"
#include "message_parcel.h"
#include "securec.h"
#include "ffrt.h"

extern "C" void* ffrt_alloc_auto_managed_function_storage_base(ffrt_function_kind_t kind)
{
    return malloc(ffrt_auto_managed_function_storage_size);
}

extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    if (f != nullptr) {
        if (f->destroy != nullptr) {
            f->destroy(f);
        }
        free(f);
    }
    return nullptr;
}

extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MESSAGE_BASE = 3001;
constexpr size_t MESSAGE_RANGE = 80;
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
    int UpdateForm(const int64_t formId, const FormProviderInfo &formProviderInfo) override
    {
        return 0;
    }
    int SetNextRefreshTime(const int64_t formId, const int64_t nextTime) override
    {
        return 0;
    }
    ErrCode RequestPublishFormCrossUser(Want &want, int32_t userId, int64_t &formId) override
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
    int InsightIntentEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) override
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
    int GetAllTemplateFormsInfo(std::vector<FormInfo> &formInfos) override
    {
        return 0;
    }
    int GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos) override
    {
        return 0;
    }
    int GetTemplateFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos) override
    {
        return 0;
    }
    int GetFormsInfoByModule(std::string &bundleName,
        std::string &moduleName, std::vector<FormInfo> &formInfos) override
    {
        return 0;
    }
    int GetTemplateFormsInfoByModule(const std::string &bundleName,
        const std::string &moduleName, std::vector<FormInfo> &formInfos) override
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

    ErrCode SendNonTransparencyRatio(int64_t formId, int32_t ratio) override
    {
        return ERR_OK;
    }

    // GetVisibleFormRect family (newly added virtual methods)
    ErrCode GetVisibleFormRect(int64_t formId, Rect &rect) override
    {
        return 0;
    }
    ErrCode RegisterGetVisibleFormRectProxy(const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    ErrCode UnregisterGetVisibleFormRectProxy() override
    {
        return 0;
    }
};

using FormHandlerFunc = int32_t (*)(IFormMgr &, MessageParcel &, MessageParcel &);

// Each handler parses a distinct IPC command from the parcel. They are grouped
// so a single fuzz execution exercises only a handful of handlers: the selector
// (first 4 bytes) picks one switch-case branch, and the remaining bytes are
// split into one disjoint slice per handler of that branch.
const FormHandlerFunc FORM_MGR_FUZZ_HANDLERS[] = {
    &FormIpcHandlers::HandleRegisterFormRemoveObserverByBundle,
    &FormIpcHandlers::HandleGetFormsCount,
    &FormIpcHandlers::HandleGetHostFormsCount,
    &FormIpcHandlers::HandleGetRunningFormInfos,
    &FormIpcHandlers::HandleGetRunningFormInfosByBundleName,
    &FormIpcHandlers::HandleGetFormInstanceById,
    &FormIpcHandlers::HandleGetAllFormsInfo,
    &FormIpcHandlers::HandleGetFormsInfoByApp,
    &FormIpcHandlers::HandleGetFormsInfoByModule,
    &FormIpcHandlers::HandleIsRequestPublishFormSupported,
    &FormIpcHandlers::HandleShareForm,
    &FormIpcHandlers::HandleCheckFMSReady,
    &FormIpcHandlers::HandleDeleteForm,
    &FormIpcHandlers::HandleStopRenderingForm,
    &FormIpcHandlers::HandleReleaseForm,
    &FormIpcHandlers::HandleSetNextRefreshTime,
    &FormIpcHandlers::HandleLifecycleUpdate,
    &FormIpcHandlers::HandleRequestForm,
    &FormIpcHandlers::HandleNotifyWhetherVisibleForms,
    &FormIpcHandlers::HandleCastTempForm,
    &FormIpcHandlers::HandleDumpFormInfoByBundleName,
    &FormIpcHandlers::HandleDumpFormInfoByFormId,
    &FormIpcHandlers::HandleDumpFormTimerByFormId,
    &FormIpcHandlers::HandleDeleteInvalidForms,
    &FormIpcHandlers::HandleNotifyFormsVisible,
    &FormIpcHandlers::HandleNotifyFormsPrivacyProtected,
    &FormIpcHandlers::HandleNotifyFormsEnableUpdate,
    &FormIpcHandlers::HandleRegisterFormAddObserverByBundle,
    &FormIpcHandlers::HandleAddForm,
    &FormIpcHandlers::HandleUpdateForm,
    &FormIpcHandlers::HandleRequestPublishForm,
    &FormIpcHandlers::HandleMessageEvent,
    &FormIpcHandlers::HandleBackgroundEvent,
    &FormIpcHandlers::HandleRouterEvent,
    &FormIpcHandlers::HandleInsightIntentEvent,
    &FormIpcHandlers::HandleAcquireFormState,
    &FormIpcHandlers::HandleGetFormsInfo,
    &FormIpcHandlers::HandleStartAbility,
    &FormIpcHandlers::HandleRecvFormShareInfoFromRemote,
    &FormIpcHandlers::HandleAcquireFormData,
    &FormIpcHandlers::HandleGetFormInstancesByFilter,
    &FormIpcHandlers::HandleGetAllTemplateFormsInfo,
    &FormIpcHandlers::HandleGetTemplateFormsInfoByApp,
    &FormIpcHandlers::HandleGetTemplateFormsInfoByModule,
    &FormIpcHandlers::HandleCreateForm,
    &FormIpcHandlers::HandleReleaseRenderer,
    &FormIpcHandlers::HandleSetPublishFormResult,
    &FormIpcHandlers::HandleAcquireAddFormResult,
    &FormIpcHandlers::HandleHasFormVisible,
    &FormIpcHandlers::HandleDumpStorageFormInfos,
    &FormIpcHandlers::HandleGetFormsInfoByFilter,
    &FormIpcHandlers::HandleIsSystemAppForm,
    &FormIpcHandlers::HandleRegisterAddObserver,
    &FormIpcHandlers::HandleRegisterRemoveObserver,
    &FormIpcHandlers::HandleRegisterFormRouterProxy,
    &FormIpcHandlers::HandleUnregisterFormRouterProxy,
    &FormIpcHandlers::HandleUpdateProxyForm,
    &FormIpcHandlers::HandleRequestPublishProxyForm,
    &FormIpcHandlers::HandleUnregisterPublishFormInterceptor,
    &FormIpcHandlers::HandleRegisterClickCallbackEventObserver,
    &FormIpcHandlers::HandleUnregisterClickCallbackEventObserver,
    &FormIpcHandlers::HandleSetFormsRecyclable,
    &FormIpcHandlers::HandleRecoverForms,
    &FormIpcHandlers::HandleUpdateFormLocation,
    &FormIpcHandlers::HandleRequestPublishFormWithSnapshot,
    &FormIpcHandlers::HandleBatchRefreshForms,
    &FormIpcHandlers::HandleEnableForms,
    &FormIpcHandlers::HandleIsFormBundleForbidden,
};

constexpr size_t FUZZ_HANDLER_COUNT = sizeof(FORM_MGR_FUZZ_HANDLERS) / sizeof(FORM_MGR_FUZZ_HANDLERS[0]);
constexpr size_t FUZZ_HANDLER_GROUP_SIZE = 5;
constexpr size_t FUZZ_HANDLER_GROUP_COUNT =
    (FUZZ_HANDLER_COUNT + FUZZ_HANDLER_GROUP_SIZE - 1) / FUZZ_HANDLER_GROUP_SIZE;
// case 0/1: OnRemoteRequest with raw/mapped code; case 2: ReadFormDataProxies;
// case 3..: one group of FUZZ_HANDLER_GROUP_SIZE handlers per branch.
constexpr uint32_t FUZZ_CASE_COUNT = 3 + FUZZ_HANDLER_GROUP_COUNT;

// Direct handler invocation: handlers parse business params directly without
// ReadInterfaceToken (only OnRemoteRequest consumes the token), so seed the
// parcel with fuzz bytes only to keep handler reads aligned with the mutated
// data. Each handler gets its own fresh parcel and reply.
void InvokeFormHandler(FormHandlerFunc handler, FormMgrStub &formMgrStub, const char* data, size_t size)
{
    if (handler == nullptr) {
        return;
    }
    MessageParcel datas;
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    handler(formMgrStub, datas, reply);
}

// Split the branch payload into one disjoint slice per handler so each command
// parses its own bytes instead of replaying the same mutation.
void InvokeFormHandlerGroup(const FormHandlerFunc *handlers, size_t count, FormMgrStub &formMgrStub,
    const char *payload, size_t payloadSize)
{
    for (size_t i = 0; i < count; ++i) {
        size_t begin = payloadSize * i / count;
        size_t end = payloadSize * (i + 1) / count;
        InvokeFormHandler(handlers[i], formMgrStub, payload + begin, end - begin);
    }
}

// OnRemoteRequest consumes the interface token itself, so the token is written
// only on this path.
void FuzzOnRemoteRequest(FormMgrStub &formMgrStub, uint32_t code, const char* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    formMgrStub.OnRemoteRequest(code, datas, reply, option);
}

uint32_t GetU32Data(const char* ptr)
{
    // 将第0个数字左移24位，将第1个数字左移16位，将第2个数字左移8位，第3个数字不左移
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    std::shared_ptr<FormMgrStub> formmgrstub = std::make_shared<FormMgrStubFuzzTest>();
    uint32_t selector = GetU32Data(data);
    // Bytes after the selector feed the payload of the chosen branch only.
    const char* payload = data + U32_AT_SIZE;
    size_t payloadSize = size - U32_AT_SIZE;
    switch (selector % FUZZ_CASE_COUNT) {
        case 0:
            FuzzOnRemoteRequest(*formmgrstub, selector, data, size);
            break;
        case 1:
            FuzzOnRemoteRequest(*formmgrstub, MESSAGE_BASE + selector % MESSAGE_RANGE, data, size);
            break;
        case 2: {
            MessageParcel datas;
            datas.WriteBuffer(payload, payloadSize);
            std::vector<FormDataProxy> formDataProxies;
            ReadFormDataProxies(datas, formDataProxies);
            break;
        }
        default: {
            uint32_t group = (selector % FUZZ_CASE_COUNT) - 3;
            size_t begin = static_cast<size_t>(group) * FUZZ_HANDLER_GROUP_SIZE;
            size_t end = begin + FUZZ_HANDLER_GROUP_SIZE;
            if (end > FUZZ_HANDLER_COUNT) {
                end = FUZZ_HANDLER_COUNT;
            }
            InvokeFormHandlerGroup(FORM_MGR_FUZZ_HANDLERS + begin, end - begin,
                *formmgrstub, payload, payloadSize);
            break;
        }
    }
    return true;
}
}

// The fuzz process has no system-caller identity, so the table's default
// FailClosedChecker would deny every registered command before deserialization.
// Install an allow-all checker to let the OnRemoteRequest path reach the
// dispatch table, the handlers and their business-parameter parsing.
class AllowAllChecker : public IStubAccessChecker {
public:
    OHOS::ErrCode Check(const FormPermissionPolicy &, const FormIpcContext &) override
    {
        return OHOS::ERR_OK;
    }
};

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    FormIpcDispatchTable::GetInstance().SetAccessChecker(std::make_shared<AllowAllChecker>());
    return 0;
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

