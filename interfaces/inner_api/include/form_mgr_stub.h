/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_MGR_STUB_H
#define OHOS_FORM_FWK_FORM_MGR_STUB_H

#include "form_mgr_interface.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormMgrStub
 * Form manager service stub. IPC handlers live in form_ipc_handlers.h as
 * free functions over IFormMgr; this class only validates the interface
 * token, checks policy and dispatches (see form_ipc_dispatch_table.h).
 */
class FormMgrStub : public IRemoteStub<IFormMgr> {
public:
    FormMgrStub();
    virtual ~FormMgrStub();
    /**
     * @brief Handle remote request.
     * @param data input param.
     * @param reply output param.
     * @param option message option.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

private:
    DISALLOW_COPY_AND_MOVE(FormMgrStub);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_MGR_STUB_H
