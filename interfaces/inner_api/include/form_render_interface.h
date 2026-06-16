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

#ifndef OHOS_FORM_FWK_FORM_RENDER_INTERFACE_H
#define OHOS_FORM_FWK_FORM_RENDER_INTERFACE_H

#include <vector>

#include "form_js_info.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "want.h"
#include "form_surface_info.h"

namespace OHOS {
namespace AppExecFwk {
using OHOS::AAFwk::Want;
/**
 * @class IFormProvider
 * IFormProvider interface is used to access form render service.
 */
class IFormRender : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.FormRender");

    /**
     * @brief Render form. This is a sync API.
     * @param formJsInfo The form js info.
     * @param want Indicates the {@link Want} structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RenderForm(const FormJsInfo &formJsInfo, const Want &want,
        sptr<IRemoteObject> callerToken) = 0;

    /**
     * @brief Stop rendering form. This is sync API.
     * @param formId Indicates The Id of the form to stop rendering.
     * @param want Indicates the {@link Want} structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t StopRenderingForm(const FormJsInfo &formJsInfo, const Want &want,
        const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief When host is died, clean resources. This is async API.
     * @param hostToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t CleanFormHost(const sptr<IRemoteObject> &hostToken) = 0;

    virtual int32_t ReloadForm(const std::vector<FormJsInfo> &&formJsInfos, const Want &want) { return ERR_OK; }

    virtual int32_t ReleaseRenderer(
        int64_t formId, const std::string &compId, const std::string &uid, const Want &want) { return ERR_OK; }

    virtual int32_t OnUnlock() { return ERR_OK; }

    virtual int32_t SetRenderGroupEnableFlag(const int64_t formId, bool isEnable, const Want &want) { return ERR_OK; }

    virtual int32_t SetVisibleChange(const int64_t &formId, bool isVisible, const Want &want) { return ERR_OK; }

    virtual int32_t RecycleForm(const int64_t &formId, const Want &want) { return ERR_OK; }

    virtual int32_t RecoverForm(const FormJsInfo &formJsInfo, const Want &want) { return ERR_OK; }

    virtual int32_t UpdateFormSize(const int64_t formId, const FormSurfaceInfo &formSurfaceInfo,
        const std::string &uid, const FormJsInfo &formJsInfo) { return ERR_OK; }

    virtual void RunCachedConfigurationUpdated() {}

    virtual int32_t SetRenderGroupParams(const int64_t formId, const Want &want) { return ERR_OK; }

    enum class Message {
        // ipc id 1-1000 for kit
        // ipc id 1001-2000 for DMS
        // ipc id 2001-3000 for tools
        // ipc id for form mgr (3001)
        // ipc id for form provider (3051)
        // ipc id for form render (3101)
        // ipc id for form supply (3201)
        // ipc id for form host (3681)

        FORM_RENDER_RENDER_FORM = 3101,
        FORM_RENDER_STOP_RENDERING_FORM = 3102,
        FORM_RENDER_FORM_HOST_DIED = 3103,
        FORM_RENDER_RELOAD_FORM = 3104,
        FORM_RENDER_RELEASE_RENDERER = 3105,
        FORM_RENDER_UNLOCKED = 3106,
        FORM_RECYCLE_FORM = 3107,
        FORM_RECOVER_FORM = 3108,
        FORM_RUN_CACHED_CONFIG = 3109,
        FORM_SET_VISIBLE_CHANGE = 3110,
        FORM_UPDATE_FORM_SIZE = 3111,
        FORM_SET_RENDER_GROUP_ENABLE_FLAG = 3112,
        FORM_SET_RENDER_GROUP_PARAMS = 3113,
    };
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_RENDER_INTERFACE_H
