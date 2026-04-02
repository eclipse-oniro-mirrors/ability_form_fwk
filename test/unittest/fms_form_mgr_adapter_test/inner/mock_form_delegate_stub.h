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

#ifndef MOCK_FORM_DELEGATE_STUB_H
#define MOCK_FORM_DELEGATE_STUB_H

#include "form_host_delegate_stub.h"
#include "form_provider_delegate_stub.h"

namespace OHOS {
namespace AppExecFwk {

class MockFormHostDelegateStub : public FormHostDelegateStub {
public:
    MockFormHostDelegateStub() = default;
    ~MockFormHostDelegateStub() override = default;
    ErrCode RouterEvent(int64_t formId, const Want &want) override { return ERR_OK; }
    ErrCode RequestOverflow(int64_t formId, const OverflowInfo &overflowInfo, bool isOverflow) override
    {
        return requestOverflowResult_;
    }
    ErrCode ChangeSceneAnimationState(int64_t formId, int32_t state) override
    {
        return changeSceneResult_;
    }
    ErrCode GetFormRect(int64_t formId, Rect &rect) override
    {
        return getFormRectResult_;
    }
    ErrCode GetLiveFormStatus(std::unordered_map<std::string, std::string> &liveFormStatusMap) override
    {
        liveFormStatusMap["key"] = "value";
        return getLiveFormStatusResult_;
    }
    ErrCode TemplateFormDetailInfoChange(const std::vector<TemplateFormDetailInfo> &info) override
    {
        return templateFormResult_;
    }
    ErrCode requestOverflowResult_ = ERR_OK;
    ErrCode changeSceneResult_ = ERR_OK;
    ErrCode getFormRectResult_ = ERR_OK;
    ErrCode getLiveFormStatusResult_ = ERR_OK;
    ErrCode templateFormResult_ = ERR_OK;
};

class MockFormProviderDelegateStub : public FormProviderDelegateStub {
public:
    MockFormProviderDelegateStub() = default;
    ~MockFormProviderDelegateStub() override = default;
    ErrCode PublishFormCrossBundleControl(const PublishFormCrossBundleInfo &bundleInfo, bool &isCanOpen) override
    {
        isCanOpen = isCanOpenResult_;
        return publishResult_;
    }
    ErrCode publishResult_ = ERR_OK;
    bool isCanOpenResult_ = true;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // MOCK_FORM_DELEGATE_STUB_H
