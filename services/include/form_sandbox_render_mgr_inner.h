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

#ifndef OHOS_FORM_FWK_FORM_SANDBOX_RENDER_MGR_INNER_H
#define OHOS_FORM_FWK_FORM_SANDBOX_RENDER_MGR_INNER_H

#include "form_record.h"
#include "form_render_connection.h"
#include "form_render_interface.h"
#include "form_render_mgr_inner.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;
/**
 * @class FormSandboxRenderMgrInner
 * FormSandboxRenderMgrInner provides a facility for managing sandbox form render life cycle.
 */
class FormSandboxRenderMgrInner : public FormRenderMgrInner {
public:
    FormSandboxRenderMgrInner();
    virtual ~FormSandboxRenderMgrInner();

    ErrCode RenderForm(
        const FormRecord &formRecord, Want &want, const sptr<IRemoteObject> &hostToken = nullptr) override;

private:
    ErrCode InstallSandboxFRS(int32_t &appIndex) const;
    ErrCode IsSandboxFRSInstalled() const;
    std::mutex sandboxMutex_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_SANDBOX_RENDER_MGR_INNER_H
