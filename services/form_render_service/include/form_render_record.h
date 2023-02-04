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
#include "js_runtime.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {

class FormRenderRecord : public std::enable_shared_from_this<FormRenderRecord> {
public:
    static std::shared_ptr<FormRenderRecord> Create(const FormJsInfo &formJsInfo, const int32_t uid);

    FormRenderRecord(const FormJsInfo &formJsInfo, const int32_t uid);

    /**
     * @brief When the host exits, clean up related resources
     * @param hostRemoteObj host token.
     * @return Returns TRUE: FormRenderRecord is empty, FALSE: FormRenderRecord is not empty.
     */
    bool HandleHostDied(sptr<IRemoteObject> hostRemoteObj);

    bool UpdateRenderRecord(const FormJsInfo &formJsInfo, sptr<IRemoteObject> hostRemoteObj);

    int32_t GetUid() const;

private:
    class RemoteObjHash {
    public:
        size_t operator() (const sptr<IRemoteObject> remoteObj) const
        {
            return reinterpret_cast<size_t>(remoteObj.GetRefPtr());
        }
    };

    bool CreateEventHandler(const FormJsInfo &formJsInfo);

    bool CreateRuntime(const FormJsInfo &formJsInfo);

    std::shared_ptr<AbilityRuntime::Context> ObtainContext(const FormJsInfo &formJsInfo);

    void HandleUpdateInJsThread(const FormJsInfo &formJsInfo);

    std::string bundleName_;
    int32_t uid_;
    std::shared_ptr<EventRunner> eventRunner_;
    std::shared_ptr<EventHandler> eventHandler_;
    std::shared_ptr<AbilityRuntime::Runtime> runtime_;
    // <formId, hostRemoteObj>
    std::unordered_map<int64_t, std::unordered_set<sptr<IRemoteObject>, RemoteObjHash>> hostsMapForFormId_;
    // <moduleName, Context>
    std::unordered_map<std::string, std::shared_ptr<AbilityRuntime::Context>> contextsMapForModuleName_;
};
}  // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_RENDER_RECORD_H
