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

#ifndef INNER_MOCK_FORM_DATA_MGR_H
#define INNER_MOCK_FORM_DATA_MGR_H

#include <string>
#include "form_instance.h"
#include "running_form_info.h"

namespace OHOS {
namespace AppExecFwk {

void MockFormDataMgrGetPublishedFormInfoById(int32_t mockRet);
void MockFormDataMgrGetPublishedFormInfos(int32_t mockRet);
void MockFormDataMgrGetRunningFormInfosByFormId(int32_t mockRet, const std::string &bundleName = "",
    FormVisibilityType visibilityType = FormVisibilityType::INVISIBLE);

}  // namespace AppExecFwk
}  // namespace OHOS

#endif // INNER_MOCK_FORM_DATA_MGR_H
