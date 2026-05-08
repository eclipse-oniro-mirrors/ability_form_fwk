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

#include "mock_form_event_report.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "form_event_report.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormEventReport> MockFormEventReport::obj = nullptr;

void FormEventReport::SendFormAbnormalEvent(const FormAbnormalReportParams &params)
{
    GTEST_LOG_(INFO) << "SendFormAbnormalEvent called";
    if (AppExecFwk::MockFormEventReport::obj) {
        return AppExecFwk::MockFormEventReport::obj->SendFormAbnormalEvent(params);
    }
}

void FormEventReport::SendFormFailedEvent(const FormEventName &eventName, int64_t formId,
    const std::string &bundleName, const std::string &abilityName, int32_t errorCode, int errCode)
{
    GTEST_LOG_(INFO) << "SendFormFailedEvent called";
}

void FormEventReport::SendConditonUpdateFormEvent(const FormEventName &eventName,
    HiSysEventType type, const NewFormEventInfo &eventInfo)
{
    GTEST_LOG_(INFO) << "SendConditonUpdateFormEvent called";
}

void FormEventReport::SendFourthFormEvent(const FormEventName &eventName,
    HiSysEventType type, const NewFormEventInfo &eventInfo, const Want &want)
{
    GTEST_LOG_(INFO) << "SendFourthFormEvent called";
}

void FormEventReport::SendRequestPublicFormEvent(const std::string &bundleName,
    const std::string &abilityName, RequestFormType requestFormType)
{
    GTEST_LOG_(INFO) << "SendRequestPublicFormEvent called";
}
}  // namespace AppExecFwk
}  // namespace OHOS