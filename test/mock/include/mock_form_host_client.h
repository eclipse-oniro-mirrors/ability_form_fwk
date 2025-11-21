/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_HOST_CLIENT_H
#define OHOS_FORM_FWK_FORM_HOST_CLIENT_H

#include <map>
#include "form_host_stub.h"
#include "iremote_object.h"
#include "iremote_stub.h"
#include "semaphore_ex.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class MockFormHostClient
 * MockFormHostClient.
 */
class MockFormHostClient : public FormHostStub {
public:
    MockFormHostClient() = default;
    virtual ~MockFormHostClient() = default;

    void Wait()
    {
        sem_.Wait();
    }

    int Post()
    {
        sem_.Post();
        return 0;
    }

    void PostVoid()
    {
        sem_.Post();
    }

    /**
     * Request to give back a Form.
     *
     * @param formId, The Id of the forms to create.
     * @param formInfo, Form info.
     * @return none.
     */
    void OnAcquired(const FormJsInfo &formInfo, const sptr<IRemoteObject> &token) override;

     /**
     * Form is updated.
     *
     * @param formId, The Id of the form to update.
     * @param formInfo, Form info.
     * @return none.
     */
    void OnUpdate(const FormJsInfo &formInfo) override;

    /**
     * Form provider is uninstalled.
     *
     * @param formIds, The Id list of the forms.
     * @return none.
     */
    void OnUninstall(const std::vector<int64_t> &formIds) override;

    /**
     * @brief Form provider is acquire state
     * @param state The form state.
     * @param want The form want.
     */
    void OnAcquireState(AppExecFwk::FormState state, const AAFwk::Want &want) override;

    /**
     * @brief Responsive form sharing.
     * @param requestCode The request code of this share form.
     * @param result Share form result.
     */
    void OnShareFormResponse(int64_t requestCode, int32_t result) override;

    /**
     * @brief Return error to host.
     * @param errorCode Indicates error-code of the form.
     * @param errorMsg Indicates error-message of the form.
     */
    void OnError(int32_t errorCode, const std::string &errorMsg) override;
    
     /**
     * @brief Return error to host for forms.
     *
     * @param errorCode Indicates error-code of the form.
     * @param errorMsg Indicates error-message of the form.
     * @param formIds Indicates ids of the form.
     */
    void OnError(int32_t errorCode, const std::string &errorMsg, std::vector<int64_t> &formIds) override;

    /**
     * @brief Form provider is acquire data
     * @param wantParams Indicates the data information acquired by the form.
     * @param requestCode Indicates the requested id.
     */
    void OnAcquireDataResponse(const AAFwk::WantParams &wantParams, int64_t requestCode) override;

    /**
     * @brief enable form style
     * @param formIds The Id list of the forms.
     * @param enable True is enableform, false is disableform.
     */
    void OnEnableForm(const std::vector<int64_t> &formIds, const bool enable) override;

    /**
     * @brief check if the form is abnormal
     * @param formIds The Id list of the forms.
     */
    void OnCheckForm(const std::vector<int64_t> &formIds) override;

private:
    Semaphore sem_;
    DISALLOW_COPY_AND_MOVE(MockFormHostClient);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_HOST_CLIENT_H
