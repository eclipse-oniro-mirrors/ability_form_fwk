/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_RENDER_MGR_H
#define OHOS_FORM_FWK_FORM_RENDER_MGR_H

#include <singleton.h>

#include "form_record.h"
#include "form_ability_connection.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;
/**
 * @class FormRenderService
 * FormRenderService provides a facility for managing form render life cycle.
 */
class FormRenderMgr final : public DelayedRefSingleton<FormRenderMgr> {
DECLARE_DELAYED_REF_SINGLETON(FormRenderMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormRenderMgr);

    ErrCode RenderForm(const FormRecord &formRecord, const WantParams &wantParams);

    ErrCode RenderForm(int64_t formId, const FormProviderInfo &formProviderInfo,
        const WantParams &wantParams);

    ErrCode StopRenderingForm(int64_t formId, const FormRecord &formRecord);

    ErrCode RenderFormCallback(int64_t &formId, const Want &want);

    ErrCode StopRenderingFormCallback(int64_t &formId, const Want &want);

    ErrCode AddConnection(sptr<FormAbilityConnection> connection);

    void HandleHostDied(int64_t formId);

    bool IsNeedRender(int64_t formId);
private:
    bool IsRemoveConnection(int64_t formId);
private:
    mutable std::mutex conMutex_;
    std::map<int32_t, sptr<FormAbilityConnection>> renderFormConnections_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_RENDER_MGR_H
