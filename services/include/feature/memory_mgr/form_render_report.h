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

#ifndef OHOS_FORM_FWK_FORM_RENDER_REPORT_H 
#define OHOS_FORM_FWK_FORM_RENDER_REPORT_H

#include <singleton.h>

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormRenderReport
 * FormRenderReport is used to call frs ready.
 */

 struct FormRenderStatusRecord {
    bool isLowMemory;
    int8_t status;
    int32_t formCount;
    int64_t occurrenceTime;
};

class FormRenderReport final : public DelayedRefSingleton<FormRenderReport> {
    DECLARE_DELAYED_REF_SINGLETON(FormRenderReport)
public:
    DISALLOW_COPY_AND_MOVE(FormRenderReport);

    void RecordFRSStart();

    void ReportFRSDead();

    void ReportFRSStatus();

private:
    int32_t GetAllFormsCount();
    void RecordFRSStatus(uint8_t status);

private:
    std::vector<FormRenderStatusRecord> frsStatusRecords_;
    std::mutex frsStatusRecordsMutex_;
    std::atomic_bool isFRSFirstLoaded_ = true;
};
}
}
#endif
