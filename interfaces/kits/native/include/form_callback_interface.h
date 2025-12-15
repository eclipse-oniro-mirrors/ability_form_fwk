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
#ifndef OHOS_FORM_FWK_FORM_CALLBACK_INTERFACE_H
#define OHOS_FORM_FWK_FORM_CALLBACK_INTERFACE_H

#include "form_js_info.h"
#include "form_state_info.h"

namespace OHOS {
namespace AppExecFwk {
class FormCallbackInterface {
public:
    /**
     * @brief Update form.
     *
     * @param formJsInfo Indicates the obtained {@code FormJsInfo} instance.
     */
    virtual void ProcessFormUpdate(const FormJsInfo &formJsInfo) = 0;

    /**
     * @brief Uninstall form.
     *
     * @param formId Indicates the ID of the form to uninstall.
     */
    virtual void ProcessFormUninstall(const int64_t formId) = 0;

    /**
     * @brief Form service death event.
     *
     */
    virtual void OnDeathReceived() = 0;

    /**
     * @brief Return error.
     *
     * @param errorCode Indicates error-code of the form.
     * @param errorMsg Indicates error-message of the form.
     */
    virtual void OnError(const int32_t errorCode, const std::string &errorMsg) = 0;

    /**
     * @brief Recycle form.
     */
    virtual void ProcessRecycleForm() {}

    /**
     * @brief Enable form.
     * @param enable True is enable form, false is disable form.
     */
    virtual void ProcessEnableForm(bool enable) {}

    /**
     * @brief Lock form.
     * @param enable True is lock form, false is unlock form.
     */
    virtual void ProcessLockForm(bool lock) {}

    /**
    * @brief due control form.
    * @param isDisablePolicy True is disable form, false is remove form.
    * @param isControl True is control form, false is not control form.
    */
    virtual void ProcessDueControlForm(bool isDisablePolicy, bool isControl) {}

    /**
     * @brief check if form is abnormal.
     */
    virtual void ProcessCheckForm() {}
};

class FormStateCallbackInterface {
public:
/**
 * @brief acquire form state.
 *
 * @param state Indicates the form state.
 */
virtual void ProcessAcquireState(FormState state) = 0;
};

class FormDataCallbackInterface {
public:
/**
 * @brief acquire form data.
 *
 * @param state Indicates the form data.
 */
virtual void ProcessAcquireFormData(AAFwk::WantParams data) = 0;
};

class ShareFormCallBack {
public:
    /**
     * @brief share form callback.
     *
     * @param result Indicates the result for ShareForm.
     */
    virtual void ProcessShareFormResponse(int32_t result) = 0;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_CALLBACK_INTERFACE_H
