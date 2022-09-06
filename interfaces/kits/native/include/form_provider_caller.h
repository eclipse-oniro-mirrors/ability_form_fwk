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

#ifndef OHOS_FORM_FWK_FORM_PROVIDER_CALLER_H
#define OHOS_FORM_FWK_FORM_PROVIDER_CALLER_H

#include <iremote_object.h>

#include "form_js_info.h"
#include "form_provider_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormProviderCaller
 * The caller of the form provider.
 */
class FormProviderCaller {
public:
    explicit FormProviderCaller(const sptr<IRemoteObject> &callerToken) : callerToken_(callerToken) {}
    ~FormProviderCaller() = default;

    /**
     * @brief Get form host caller token.
     * @return Returns callerToken_.
     */
    sptr<IRemoteObject> GetCallerToken() const;

    /**
     * @brief Add form js info to formJsInfoMap_.
     * @param formJsInfo The form js info.
     */
    void AddForm(const FormJsInfo &formJsInfo);

    /**
     * @brief Delete form js info form formJsInfoMap_.
     * @param formJsInfo The form js info.
     */
    void DeleteFormJsInfo(const FormJsInfo &formJsInfo);

    /**
     * @brief Whether has the specific form.
     * @param formId The form ID.
     * @return Returns true if has the specific form; returns false otherwise.
     */
    bool HasForm(int64_t formId);

    /**
     * @brief Delete the Specific form.
     * @param formId The form ID.
     */
    void DeleteForm(int64_t formId);

    /**
     * @brief Whether the form is empty.
     * @return Returns true if the form is empty; returns false otherwise.
     */
    bool IsFormEmpty();

    /**
     * @brief Callback acquire.
     * @param providerFormInfo Form binding data.
     * @param want Indicates the Want structure containing form info.
     * @param token Indicates the provider client token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t OnAcquire(const FormProviderInfo &formProviderInfo, const AAFwk::Want &want,
        const sptr<IRemoteObject> &token);
private:
    bool GetFormJsInfo(int64_t formId, FormJsInfo &formJsInfo);
    int32_t OnAcquired(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> &token);

    mutable std::recursive_mutex formJsInfoMutex_;
    std::map<int64_t, FormJsInfo> formJsInfoMap_;
    std::vector<FormJsInfo> formJsInfos_;
    sptr<IRemoteObject> callerToken_ = nullptr;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_PROVIDER_CALLER_H