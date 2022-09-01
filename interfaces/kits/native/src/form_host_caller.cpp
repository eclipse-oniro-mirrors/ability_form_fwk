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

#include "form_host_caller.h"

#include "form_host_client.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
void FormHostCaller::UpdateForm(int64_t formId, const FormProviderData &formProviderData)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    FormJsInfo formJsInfo;
    formJsInfo = formJsInfo_;
    formJsInfo.formData = formProviderData.GetDataString();
    formJsInfo.formProviderData = formProviderData;
    if (!formJsInfo.ConvertRawImageData()) {
        HILOG_ERROR("convert raw image data failed.");
    }
    FormHostClient::GetInstance()->UpdateForm(formJsInfo);
}
} // namespace AppExecFwk
} // namespace OHOS
