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

#ifndef OHOS_FORM_FWK_FORM_TIMER_OPTION_H
#define OHOS_FORM_FWK_FORM_TIMER_OPTION_H

#include "itimer_info.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormTimerOption
 * form timer option.
 */
class FormTimerOption : public OHOS::MiscServices::ITimerInfo {
public:
    FormTimerOption();
    virtual ~FormTimerOption();
    virtual void OnTrigger() override;
    virtual void SetType(const int &type) override;
    virtual void SetRepeat(bool repeat) override;
    virtual void SetInterval(const uint64_t &interval) override;
    virtual void SetWantAgent(std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent) override;
    void SetCallbackInfo(std::function<void()> callBack);

private:
    std::function<void()> callBack_;
};

FormTimerOption::FormTimerOption()
{
}

FormTimerOption::~FormTimerOption()
{
}

void FormTimerOption::OnTrigger()
{
    if (callBack_) {
        callBack_();
    }
}

void FormTimerOption::SetCallbackInfo(std::function<void()> callBack)
{
    callBack_ = callBack;
}

void FormTimerOption::SetType(const int &type)
{
    this->type = type;
}

void FormTimerOption::SetRepeat(bool repeat)
{
    this->repeat = repeat;
}

void FormTimerOption::SetInterval(const uint64_t &interval)
{
    this->interval = interval;
}

void FormTimerOption::SetWantAgent(std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent)
{
    this->wantAgent = wantAgent;
}
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_TIMER_OPTION_H
