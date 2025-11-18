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

#ifndef OHOS_FORM_FWK_FORM_RENDER_STUB_H
#define OHOS_FORM_FWK_FORM_RENDER_STUB_H

#include <unordered_map>

#include "form_render_interface.h"
#include "iremote_object.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormRenderStub
 * form render service stub.
 */
class FormRenderStub : public IRemoteStub<IFormRender> {
public:
    FormRenderStub();
    virtual ~FormRenderStub();
    /**
     * @brief handle remote request.
     * @param data input param.
     * @param reply output param.
     * @param option message option.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

private:
    /**
     * @brief handle render form message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleRenderForm(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief Stop rendering form. This is sync API.
     * @param formJsInfo The form js info.
     * @param want Indicates the {@link Want} structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleStopRenderingForm(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief When host is died, clean resources. This is async API.
     * @param hostToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleCleanFormHost(MessageParcel &data, MessageParcel &reply);

    int32_t HandleReleaseRenderer(MessageParcel &data, MessageParcel &reply);

    int32_t HandleReloadForm(MessageParcel &data, MessageParcel &reply);

    int32_t HandleOnUnlock(MessageParcel &data, MessageParcel &reply);

    int32_t HandleSetRenderGroupEnableFlag(MessageParcel &data, MessageParcel &reply);

    int32_t HandleSetVisibleChange(MessageParcel &data, MessageParcel &reply);

    int32_t HandleRecycleForm(MessageParcel &data, MessageParcel &reply);

    int32_t HandleRecoverForm(MessageParcel &data, MessageParcel &reply);

    int32_t HandleUpdateFormSize(MessageParcel &data, MessageParcel &reply);
	
protected:
    virtual int32_t CheckPermission() = 0;

private:
    template<typename T>
    int32_t GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos);

    DISALLOW_COPY_AND_MOVE(FormRenderStub);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_RENDER_STUB_H
