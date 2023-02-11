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

#ifndef OHOS_FORM_FWK_FORM_RENDER_RECORD_H
#define OHOS_FORM_FWK_FORM_RENDER_RECORD_H

#include <memory>
#include <unordered_map>
#include <unordered_set>

#include "context_impl.h"
#include "event_handler.h"
#include "form_js_info.h"
#include "form_mgr_errors.h"
#include "form_renderer_group.h"
#include "js_runtime.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
using Want = AAFwk::Want;
class FormRenderRecord : public std::enable_shared_from_this<FormRenderRecord> {
public:
    /**
     * @brief Create a FormRenderRecord.
     * @param bundleName The bundleName of form bundle.
     * @param uid The uid of form bundle.
     * @return Returns FormRenderRecord instance.
     */
    static std::shared_ptr<FormRenderRecord> Create(const std::string &bundleName, int32_t uid);

    FormRenderRecord(const std::string &bundleName, int32_t uid);

    /**
     * @brief When the host exits, clean up related resources.
     * @param hostRemoteObj host token.
     * @return Returns TRUE: FormRenderRecord is empty, FALSE: FormRenderRecord is not empty.
     */
    bool HandleHostDied(const sptr<IRemoteObject> hostRemoteObj);

    /**
     * @brief When add a new form, the corresponding FormRenderRecord needs to be updated.
     * @param formJsInfo formJsInfo.
     * @param want want.
     * @param hostRemoteObj host token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t UpdateRenderRecord(const FormJsInfo &formJsInfo, const Want &want, const sptr<IRemoteObject> hostRemoteObj);

    /**
     * @brief When all forms of an bundle are deleted, the corresponding FormRenderRecord-record needs to be removed
     * @param formId formId.
     * @param want want.
     * @param hostRemoteObj host token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t DeleteRenderRecord(int64_t formId, const Want &want, const sptr<IRemoteObject> hostRemoteObj);

    /**
     * @brief Get the uid of bundle.
     * @return Returns the uid.
     */
    int32_t GetUid() const;

private:
    class RemoteObjHash {
    public:
        size_t operator() (const sptr<IRemoteObject> remoteObj) const
        {
            return reinterpret_cast<size_t>(remoteObj.GetRefPtr());
        }
    };

    bool CreateEventHandler(const std::string &bundleName);

    bool CreateRuntime(const FormJsInfo &formJsInfo);

    std::shared_ptr<AbilityRuntime::Context> GetContext(const FormJsInfo &formJsInfo, const Want &want);

    std::shared_ptr<AbilityRuntime::Context> CreateContext(const FormJsInfo &formJsInfo, const Want &want);

    std::shared_ptr<Ace::FormRendererGroup> GetFormRendererGroup(const FormJsInfo &formJsInfo,
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<AbilityRuntime::Runtime> &runtime);

    std::shared_ptr<Ace::FormRendererGroup> CreateFormRendererGroupLock(const FormJsInfo &formJsInfo,
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<AbilityRuntime::Runtime> &runtime);

    void HandleUpdateInJsThread(const FormJsInfo &formJsInfo, const Want &want);

    void HandleDeleteInJsThread(int64_t formId, const Want &want);

    std::string bundleName_;
    int32_t uid_ = Constants::INVALID_UID;
    std::shared_ptr<EventRunner> eventRunner_;
    std::shared_ptr<EventHandler> eventHandler_;
    std::shared_ptr<AbilityRuntime::Runtime> runtime_;
    // <formId, hostRemoteObj>
    std::mutex hostsMapMutex_;
    std::unordered_map<int64_t, std::unordered_set<sptr<IRemoteObject>, RemoteObjHash>> hostsMapForFormId_;
    // <moduleName, Context>
    std::mutex contextsMapMutex_;
    std::unordered_map<std::string, std::shared_ptr<AbilityRuntime::Context>> contextsMapForModuleName_;
    // <formId, formRendererGroup>
    std::mutex formRendererGroupMutex_;
    std::map<int64_t, std::shared_ptr<Ace::FormRendererGroup>> formRendererGroupMap_;
};
}  // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_RENDER_RECORD_H