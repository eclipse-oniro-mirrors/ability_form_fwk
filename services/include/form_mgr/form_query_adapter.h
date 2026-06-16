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

#ifndef OHOS_FORM_FWK_FORM_QUERY_ADAPTER_H
#define OHOS_FORM_FWK_FORM_QUERY_ADAPTER_H

#include <memory>

#include "singleton.h"

#include "form_info.h"
#include "form_info_filter.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "form_state_info.h"
#include "ipc_skeleton.h"
#include "running_form_info.h"

#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"
#include "common/util/form_util.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_info/form_info_mgr.h"

namespace OHOS {
namespace AppExecFwk {

class FormCommonAdapter;

class FormQueryAdapter final : public DelayedRefSingleton<FormQueryAdapter> {
    DECLARE_DELAYED_REF_SINGLETON(FormQueryAdapter)
public:

    int GetAllFormsInfo(std::vector<FormInfo> &formInfos);

    int GetFormsInfoByApp(const std::string &bundleName,
        std::vector<FormInfo> &formInfos);

    int GetFormsInfoByModule(const std::string &bundleName,
        const std::string &moduleName, std::vector<FormInfo> &formInfos);

    int GetFormsInfoByFilter(const FormInfoFilter &filter,
        std::vector<FormInfo> &formInfos);

    ErrCode GetFormInstanceById(const int64_t formId, FormInstance &formInstance);

    ErrCode GetFormInstanceById(const int64_t formId, bool isUnusedIncluded, FormInstance &formInstance);

    ErrCode GetRunningFormInfos(bool isUnusedIncluded,
        std::vector<RunningFormInfo> &runningFormInfos, const int32_t userId);

    int GetAllTemplateFormsInfo(std::vector<FormInfo> &formInfos);

    int GetTemplateFormsInfoByApp(const std::string &bundleName,
        std::vector<FormInfo> &formInfos);

    int GetTemplateFormsInfoByModule(const std::string &bundleName,
        const std::string &moduleName, std::vector<FormInfo> &formInfos);

    int32_t GetFormsCount(bool isTempFormFlag, int32_t &formCount);

    int32_t GetHostFormsCount(const std::string &bundleName, int32_t &formCount);

    ErrCode GetRunningFormInfosByBundleName(const std::string &bundleName,
        bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos);

    ErrCode GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
        std::vector<FormInstance> &formInstances);

    /**
     * @brief Acquire form state info by passing a set of parameters (using Want) to the form provider.
     * @param want Indicates a set of parameters to be transparently passed to the form provider.
     * @param callerToken Caller ability token.
     * @param stateInfo Returns the form's state info of the specify.
     * @return Returns ERR_OK on success, others on failure.
     */
    int AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken, FormStateInfo &stateInfo);

    /**
     * @brief Acquire form data by formId.
     * @param formId The Id of the form to acquire data.
     * @param requestCode The request code of this acquire form.
     * @param callerToken Indicates the host client.
     * @param formData Return the form information of customization
     * @return Returns ERR_OK on success, others on failure.
     */
    int AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
        AAFwk::WantParams &formData);

private:
    /**
     * @brief Check acquire form state parameters
     * @param bundleName Bundle name
     * @param abilityName Ability name
     * @param want The want of the request
     * @param provider Provider string
     * @return Returns ERR_OK on success, others on failure
     */
    ErrCode AcquireFormStateCheck(const std::string &bundleName,
        const std::string &abilityName, const Want &want, std::string &provider);
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_QUERY_ADAPTER_H
