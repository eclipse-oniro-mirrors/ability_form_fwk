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

#ifndef OHOS_FORM_FWK_FORM_PUBLISH_INTERCEPTOR_STUB_H
#define OHOS_FORM_FWK_FORM_PUBLISH_INTERCEPTOR_STUB_H

#include "form_publish_interceptor_interface.h"
#include "iremote_object.h"
#include "iremote_stub.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using OHOS::AAFwk::Want;
/**
 * @class FormPublishInterceptorStub
 * FormPublishInterceptorStub is used to process the publish form request.
 */
class FormPublishInterceptorStub : public IRemoteStub<IFormPublishInterceptor> {
public:
    FormPublishInterceptorStub();
    virtual ~FormPublishInterceptorStub();

    /**
     * @brief handle remote request.
     * @param data input param.
     * @param reply output param.
     * @param option message option.
     * @return Returns ERR_OK on success, others on failure.
     */
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    /**
     * @brief Handle process publish form info message.
     *
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t HandleProcessPublishForm(MessageParcel &data, MessageParcel &reply);

private:
    using FormPublishInterceptorFunc =
        int32_t (FormPublishInterceptorStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, FormPublishInterceptorFunc> memberFuncMap_;

    DISALLOW_COPY_AND_MOVE(FormPublishInterceptorStub);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_PUBLISH_INTERCEPTOR_STUB_H
