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

#ifndef OHOS_FORM_FWK_MOCK_FORM_EVENT_REPORT_H
#define OHOS_FORM_FWK_MOCK_FORM_EVENT_REPORT_H

#include <cstdint>
#include <memory>
#include "gmock/gmock.h"
#include "form_event_report_define.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormEventReport {
public:
    virtual ~AbstractMockFormEventReport() = default;
    virtual void SendFormAbnormalEvent(const FormAbnormalReportParams &params) = 0;
};

class MockFormEventReport : public AbstractMockFormEventReport {
public:
    static std::shared_ptr<MockFormEventReport> obj;
    MockFormEventReport() = default;
    ~MockFormEventReport() override = default;
    MOCK_METHOD1(SendFormAbnormalEvent, void(const FormAbnormalReportParams &params));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_EVENT_REPORT_H
