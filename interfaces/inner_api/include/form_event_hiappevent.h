/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_EVENT_HIAPPEVENT_H
#define OHOS_FORM_FWK_FORM_EVENT_HIAPPEVENT_H

#include <cstdint>
#include <string>

#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
struct PublishFormData {
    std::string bundleName;
    std::string abilityName;
    int formDimension;
    std::string moduleName;
    std::string formName;
};

class FormEventHiAppEvent {
public:
    static int64_t AddProcessor();
    static void WriteAppFormEndEvent(const int errCode, const time_t beginTime, const std::string &apiName,
        const PublishFormData &publishFormData, const int64_t processorId);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif //OHOS_FORM_FWK_FORM_EVENT_HIAPPEVENT_H