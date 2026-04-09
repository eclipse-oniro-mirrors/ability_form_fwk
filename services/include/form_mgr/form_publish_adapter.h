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

#ifndef OHOS_FORM_FWK_FORM_PUBLISH_ADAPTER_H
#define OHOS_FORM_FWK_FORM_PUBLISH_ADAPTER_H

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "app_mgr_interface.h"
#include "form_constants.h"
#include "form_info.h"
#include "form_provider_data.h"
#include "form_publish_interceptor_interface.h"
#include "iremote_object.h"
#include "ipc_skeleton.h"
#include "system_ability_definition.h"
#include "want.h"

#include "fms_log_wrapper.h"
#include "form_event_report.h"
#include "form_mgr_errors.h"
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "common/util/form_serial_queue.h"
#include "common/util/form_util.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_data_proxy_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_record/form_record.h"
#include "form_mgr/form_common_adapter.h"
#include "form_refresh/form_refresh_mgr.h"
#include "form_provider/form_provider_mgr.h"

namespace OHOS {
namespace AppExecFwk {
// Forward declaration
class FormCallbackAdapter;
class FormCommonAdapter;

class FormPublishAdapter {
public:
    FormPublishAdapter(
        FormDataMgr* formDataMgr,
        FormInfoMgr* formInfoMgr,
        FormCommonAdapter* commonAdapter,
        FormCallbackAdapter* callbackAdapter);

    virtual ~FormPublishAdapter() = default;

    ErrCode RequestPublishForm(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
        const std::vector<FormDataProxy> &formDataProxies = {}, bool needCheckFormPermission = true);

    ErrCode QueryPublishFormToHost(Want &wantToHost);

    ErrCode CheckPublishForm(Want &want, bool needCheckFormPermission);

    ErrCode SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo);

    ErrCode AcquireAddFormResult(const int64_t formId);

    bool IsRequestPublishFormSupported();

    // Functions moved from FormLifecycleAdapter
    ErrCode CheckAddFormTaskTimeoutOrFailed(const int64_t formId, AddFormResultErrorCodes &formStates);
    void RemoveFormIdMapElement(const int64_t formId);
    void CancelAddFormRequestTimeOutTask(const int64_t formId, const int result);

private:
    ErrCode CheckFormBundleName(Want &want, std::string &bundleName, bool needCheckFormPermission);
    bool IsValidPublishEvent(const sptr<IBundleMgr> &iBundleMgr, const std::string &bundleName, const Want &want,
        bool needCheckFormPermission = true);
    bool IsActionAllowToPublish(const std::string &action);
    bool CheckIsSystemAppByBundleName(const sptr<IBundleMgr> &iBundleMgr,
        const int32_t &userId, const std::string &bundleName);
    bool IsErmsSupportPublishForm(std::string bundleName, std::vector<Want> wants);
    bool CheckSnapshotWant(const Want &want);
    void IncreaseAddFormRequestTimeOutTask(const int64_t formId);
    ErrCode RequestPublishFormToHost(Want &want);
    int32_t GetCallerType(std::string bundleName);
    bool GetBundleName(std::string &bundleName, bool needCheckFormPermission = true);

    FormDataMgr* formDataMgr_;
    FormInfoMgr* formInfoMgr_;
    FormCommonAdapter* commonAdapter_;
    std::unique_ptr<FormSerialQueue> serialQueue_;
    std::map<int64_t, AddFormResultErrorCodes> formIdMap_;
    mutable std::mutex formResultMutex_;
    std::condition_variable condition_;
    FormCallbackAdapter* callbackAdapter_;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_PUBLISH_ADAPTER_H
