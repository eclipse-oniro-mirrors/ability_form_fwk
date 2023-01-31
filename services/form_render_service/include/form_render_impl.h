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

#ifndef OHOS_FORM_FWK_FORM_RENDER_IMPL_H
#define OHOS_FORM_FWK_FORM_RENDER_IMPL_H

#include "form_render_stub.h"

#include <memory>
#include <singleton.h>

#include "context_impl.h"
#include "event_handler.h"
#include "js_runtime.h"
#include "runtime.h"
#include "ui_content.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
using OHOS::AAFwk::Want;
using namespace AbilityRuntime;

class FormRenderImpl : public FormRenderStub,
                       public std::enable_shared_from_this<FormRenderImpl> {
    DECLARE_DELAYED_SINGLETON(FormRenderImpl)
public:
    /**
     * @brief Render form. This is sync API.
     * @param formJsInfo The form js info.
     * @param want Indicates the {@link Want} structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RenderForm(const FormJsInfo &formJsInfo, const Want &want,
        const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Set the Runtime object
     *
     * @param runtime The runtime
     */
    void SetRuntime(AbilityRuntime::Runtime& runtime);

    int32_t DeleteRenderForm(const int64_t &formId, const Want &want,
        const sptr<IRemoteObject> &callerToken) override;

private:
    int32_t AddForm(const FormJsInfo &formJsInfo, const Want &want);
    void OnActionEvent(const std::string& action) const;

    /**
     * @brief Update form. This is sync API
     *
     * @param formJsInfo The form js info
     * @param want The want parameter
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t UpdateForm(const FormJsInfo &formJsInfo, const Want &want);

    std::shared_ptr<Runtime> ObtainRuntime(const FormJsInfo &formJsInfo, const std::shared_ptr<EventRunner> runner);
    std::shared_ptr<Runtime> CreateRuntimeLock(const FormJsInfo &formJsInfo, const std::shared_ptr<EventRunner> runner);

    std::shared_ptr<Context> ObtainContext(const FormJsInfo &formJsInfo, const std::shared_ptr<Runtime> &runtime);
    std::shared_ptr<Context> CreateContextLock(const FormJsInfo &formJsInfo, const std::shared_ptr<Runtime> &runtime);

    std::shared_ptr<EventRunner> ObtainEventRunner(const FormJsInfo &formJsInfo);
    std::shared_ptr<EventRunner> CreateEventRunnerLock(const FormJsInfo &formJsInfo);

    std::shared_ptr<Ace::UIContent> ObtainUIContent(
        const FormJsInfo &formJsInfo, const std::shared_ptr<Context> &context, const std::shared_ptr<Runtime> &runtime);
    std::shared_ptr<Ace::UIContent> CreateUIContentLock(const FormJsInfo &formJsInfo,
        const std::shared_ptr<Context> &context, const std::shared_ptr<Runtime> &runtime);

private:
    static sptr<FormRenderImpl> instance_;
    int32_t touchTimes_;
    bool formInitialized = false;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandlerMain_;
    std::mutex uiContentMutex_;
    std::map<int64_t, std::shared_ptr<Ace::UIContent>> uiContentMap_; // <formId, uiContent>
    std::mutex contextMutex_;
    std::map<std::string, std::shared_ptr<Context>> contextMap_; // <bundleName + moduleName, context>
    std::map<std::string, std::shared_ptr<NativeReference>> shellContextRefMap_; // <bundleName, eventHandler>
    std::mutex runTimeMutex_;
    std::map<std::string, std::shared_ptr<Runtime>> runTimeMap_; // <bundleName, context>
    std::mutex eventRunnerMutex_;
    std::map<std::string, std::shared_ptr<EventRunner>> eventRunnerMap_; // <bundleName, eventHandler>
};
}  // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_RENDER_IMPL_H
