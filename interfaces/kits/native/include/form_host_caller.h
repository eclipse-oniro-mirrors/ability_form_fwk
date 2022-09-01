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

#ifndef OHOS_FORM_FWK_FORM_HOST_CALLER_H
#define OHOS_FORM_FWK_FORM_HOST_CALLER_H

#include <iremote_object.h>

#include "form_js_info.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormHostCaller
 * The caller of the form host.
 */
class FormHostCaller {
public:
    FormHostCaller(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> &callerToken) :
        formJsInfo_(formJsInfo), callerToken_(callerToken) {}
    ~FormHostCaller() = default;

    /**
     * @brief Update form with formId.
     * @param formId Indicates the Id of the form to update.
     * @param formProviderData Indicates the form provider data.
     */
    void UpdateForm(int64_t formId, const FormProviderData &formProviderData);
private:
    FormJsInfo formJsInfo_;
    sptr<IRemoteObject> callerToken_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_HOST_CALLER_H
