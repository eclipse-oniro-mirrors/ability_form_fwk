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

#include "formmgrproxy_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_mgr_proxy.h"
#undef private
#undef protected                                                                
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    sptr<IRemoteObject> impl = nullptr;
    FormMgrProxy formMgrProxy(impl);
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formInfo;
    formMgrProxy.AddForm(formId, want, callerToken, formInfo);
    formMgrProxy.DeleteForm(formId, callerToken);
    bool delCache = *data % ENABLE;
    formMgrProxy.ReleaseForm(formId, callerToken, delCache);
    formMgrProxy.RequestForm(formId, callerToken, want);
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    int32_t formVisibleType = static_cast<int32_t>(GetU32Data(data));
    formMgrProxy.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType);
    formMgrProxy.CastTempForm(formId, callerToken);
    std::string stringData(data);
    formMgrProxy.DumpStorageFormInfos(stringData);
    std::string bundleName(data);
    formMgrProxy.DumpFormInfoByBundleName(bundleName, stringData);
    formMgrProxy.DumpFormInfoByFormId(formId, stringData);
    std::string isTimingService(data);
    formMgrProxy.DumpFormTimerByFormId(formId, isTimingService);
    formMgrProxy.MessageEvent(formId, want, callerToken);
    MessageParcel datas;
    formMgrProxy.WriteInterfaceToken(datas);
    std::string stringInfo(data);
    formMgrProxy.GetStringInfo(IFormMgr::Message::FORM_MGR_ADD_FORM, datas, stringInfo);
    FormInfo formInfoes;
    std::vector<FormInfo> formInfos;
    formInfos.emplace_back(formInfoes);
    formMgrProxy.GetFormsInfo(IFormMgr::Message::FORM_MGR_ADD_FORM, datas, formInfos);
    formMgrProxy.SendTransactCmd(IFormMgr::Message::FORM_MGR_ADD_FORM, datas, datas);
    int32_t numFormsDeleted = static_cast<int32_t>(GetU32Data(data));
    formMgrProxy.DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
    FormStateInfo stateInfo;
    formMgrProxy.AcquireFormState(want, callerToken, stateInfo);
    bool isVisible = *data % ENABLE;
    formMgrProxy.NotifyFormsVisible(formIds, isVisible, callerToken);
    bool isEnableUpdate = *data % ENABLE;
    formMgrProxy.NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken);
    formMgrProxy.GetAllFormsInfo(formInfos);
    formMgrProxy.GetFormsInfoByApp(bundleName, formInfos);
    std::string moduleName(data);
    formMgrProxy.GetFormsInfoByModule(bundleName, moduleName, formInfos);
    FormInfoFilter filter;
    formMgrProxy.GetFormsInfo(filter, formInfos);
    formMgrProxy.StartAbility(want, callerToken);
    std::string deviceId(data);
    int64_t requestCode = static_cast<int64_t>(GetU32Data(data));
    return formMgrProxy.ShareForm(formId, deviceId, callerToken, requestCode);
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

    /* Validate the length of size */
    if (size == 0 || size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = (char *)malloc(size + 1);
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

