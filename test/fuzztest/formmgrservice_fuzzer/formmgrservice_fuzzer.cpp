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

#include "formmgrservice_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_mgr_service.h"
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
    FormMgrService formMgrService;
    formMgrService.IsReady();
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formInfo;
    formMgrService.AddForm(formId, want, callerToken, formInfo);
    formMgrService.DeleteForm(formId, callerToken);
    bool delCache = *data % ENABLE;
    formMgrService.ReleaseForm(formId, callerToken, delCache);
    formMgrService.RequestForm(formId, callerToken, want);
    int64_t nextTime = static_cast<int64_t>(GetU32Data(data));
    formMgrService.SetNextRefreshTime(formId, nextTime);
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    int32_t formVisibleType = static_cast<int32_t>(GetU32Data(data));
    formMgrService.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType);
    formMgrService.CastTempForm(formId, callerToken);
    bool updateType = *data % ENABLE;
    formMgrService.LifecycleUpdate(formIds, callerToken, updateType);
    std::string bundleName(data, size);
    std::string formInfos(data, size);
    formMgrService.DumpFormInfoByBundleName(bundleName, formInfos); 
    formMgrService.DumpFormInfoByFormId(formId, formInfos);
    std::string isTimingService(data, size);
    formMgrService.DumpFormTimerByFormId(formId, isTimingService);
    formMgrService.OnStop();
    formMgrService.CheckFormPermission();
    int32_t numFormsDeleted = static_cast<int32_t>(GetU32Data(data));
    formMgrService.DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
    FormStateInfo stateInfo;
    formMgrService.AcquireFormState(want, callerToken, stateInfo);
    bool isVisible = *data % ENABLE;
    formMgrService.NotifyFormsVisible(formIds, isVisible, callerToken);
    bool isEnableUpdate = *data % ENABLE;
    formMgrService.NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken);
    FormInfo aa;
    std::vector<FormInfo> formInfoes;
    formInfoes.emplace_back(aa);
    formMgrService.GetAllFormsInfo(formInfoes);
    formMgrService.StartAbility(want, callerToken);
    formMgrService.InitFormShareMgrEventHandler();
    FormShareInfo info;
    formMgrService.RecvFormShareInfoFromRemote(info);
    int fd = static_cast<int>(GetU32Data(data));
    std::vector<std::u16string> args = {u"-h"};
    formMgrService.Dump(fd, args);
    std::string result(data, size);
    formMgrService.Dump(args, result);
    std::string value(data, size);
    formMgrService.HiDumpFormInfoByBundleName(value, result);
    formMgrService.HiDumpFormInfoByFormId(value, result);
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

