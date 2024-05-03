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

#include "configuration.h"
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
enum class TaskState {
    NO_RUNNING = 0,
    RUNNING = 0,
    BLOCK,
};

class ThreadState {
public:
    explicit ThreadState(int32_t maxState);
    void ResetState();
    void NextState();
    int32_t GetCurrentState();
    bool IsMaxState();

private:
    int32_t state_ = 0;
    int32_t maxState_;
};

class HandlerDumper : public AppExecFwk::Dumper {
public:
    void Dump(const std::string &message) override;
    std::string GetTag() override;
    std::string GetDumpInfo();
private:
    std::string dumpInfo_;
};

class FormRenderRecord : public std::enable_shared_from_this<FormRenderRecord> {
public:
    /**
     * @brief Create a FormRenderRecord.
     * @param bundleName The bundleName of form bundle.
     * @param uid The uid of form bundle.(userId + bundleName)
     * @return Returns FormRenderRecord instance.
     */
    static std::shared_ptr<FormRenderRecord> Create(
        const std::string &bundleName, const std::string &uid, bool needMonitored = true);

    FormRenderRecord(const std::string &bundleName, const std::string &uid);

    ~FormRenderRecord();

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
     * @param hostRemoteObj host token.
     * @return Returns ERR_OK on success, others on failure.
     */
    void DeleteRenderRecord(int64_t formId, const std::string &compId,  const sptr<IRemoteObject> hostRemoteObj,
        bool &isRenderGroupEmpty);

    int32_t HandleOnUnlock();

    int32_t OnUnlock();

    int32_t ReloadFormRecord(const std::vector<FormJsInfo> &&formJsInfos, const Want &want);

    int32_t HandleReloadFormRecord(const std::vector<FormJsInfo> &&formJsInfos, const Want &want);

    /**
     * @brief Get the uid of bundle.
     * @return Returns the uid.
     */
    std::string GetUid() const;

    bool IsEmpty();

    void UpdateConfiguration(const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config);

    void SetConfiguration(const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config);

    void MarkThreadAlive();

    void ReleaseRenderer(int64_t formId, const std::string &compId, bool &isRenderGroupEmpty);

    void Release();

    void FormRenderGC();

    int32_t RecycleForm(const int64_t &formId, std::string &statusData);

    int32_t RecoverForm(const int64_t &formId, const std::string &statusData,
        const bool &isRecoverFormToHandleClickEvent);
private:
    class RemoteObjHash {
    public:
        size_t operator() (const sptr<IRemoteObject> remoteObj) const
        {
            return reinterpret_cast<size_t>(remoteObj.GetRefPtr());
        }
    };
    using IRemoteObjectSet = std::unordered_set<sptr<IRemoteObject>, RemoteObjHash>;

    bool CreateEventHandler(const std::string &bundleName, bool needMonitored = true);

    bool CreateRuntime(const FormJsInfo &formJsInfo);

    bool SetPkgContextInfoMap(const FormJsInfo &formJsInfo, AbilityRuntime::Runtime::Options &options,
        std::string &uid);

    std::shared_ptr<AbilityRuntime::Context> GetContext(const FormJsInfo &formJsInfo, const Want &want);

    std::shared_ptr<AbilityRuntime::Context> CreateContext(const FormJsInfo &formJsInfo, const Want &want);

    std::shared_ptr<Ace::FormRendererGroup> GetFormRendererGroup(const FormJsInfo &formJsInfo,
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<AbilityRuntime::Runtime> &runtime);

    std::shared_ptr<Ace::FormRendererGroup> CreateFormRendererGroupLock(const FormJsInfo &formJsInfo,
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<AbilityRuntime::Runtime> &runtime);

    void HandleUpdateInJsThread(const FormJsInfo &formJsInfo, const Want &want);

    bool HandleDeleteInJsThread(int64_t formId, const std::string &compId);

    void HandleDestroyInJsThread();

    bool HandleReleaseRendererInJsThread(int64_t formId, const std::string &compId, bool &isRenderGroupEmpty);

    void DeleteRendererGroup(int64_t formId);

    void HandleDeleteRendererGroup(int64_t formId);

    std::string GenerateContextKey(const FormJsInfo &formJsInfo);

    void ReleaseHapFileHandle();

    void HandleUpdateConfiguration(const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config);

    void AddWatchDogThreadMonitor();

    void Timer();

    bool BeforeHandleUpdateForm(const FormJsInfo &formJsInfo);

    void HandleUpdateForm(const FormJsInfo &formJsInfo, const Want &want);

    void MergeFormData(Ace::FormRequest &formRequest, const FormJsInfo &formJsInfo);

    void AddRenderer(const FormJsInfo &formJsInfo, const Want &want);

    void UpdateRenderer(const FormJsInfo &formJsInfo);

    TaskState RunTask();

    void DumpEventHandler();

    void HandleReleaseInJsThread();

    bool CheckEventHandler(bool createThead = true, bool needMonitored = false);

    void AddFormRequest(const FormJsInfo &formJsInfo, const Want &want);

    void AddFormRequest(int64_t formId, const Ace::FormRequest &formRequest);

    void DeleteFormRequest(int64_t formId, const std::string &compId);

    void UpdateFormRequestReleaseState(
        int64_t formId, const std::string &compId, bool hasRelease);

    void ReAddAllRecycledForms();

    void ReAddRecycledForms(const std::vector<FormJsInfo> &formJsInfos);

    int32_t HandleRecycleForm(const int64_t &formId, std::string &statusData);

    void HandleRecoverForm(const int64_t &formId, const std::string &statusData,
        const bool &isRecoverFormToHandleClickEvent);

    void HandleFormRenderGC();

    pid_t jsThreadId_;
    pid_t processId_;

    std::string bundleName_;
    std::string uid_;
    std::shared_ptr<EventRunner> eventRunner_;
    std::shared_ptr<EventHandler> eventHandler_;
    std::mutex eventHandlerMutex_;
    std::shared_ptr<AbilityRuntime::Runtime> runtime_;

    // <formId, hostRemoteObj>
    std::mutex hostsMapMutex_;
    std::unordered_map<int64_t, IRemoteObjectSet> hostsMapForFormId_;
    // <moduleName, Context>
    std::mutex contextsMapMutex_;
    std::unordered_map<std::string, std::shared_ptr<AbilityRuntime::Context>> contextsMapForModuleName_;
    // <formId, formRendererGroup>
    std::mutex formRendererGroupMutex_;
    std::unordered_map<int64_t, std::shared_ptr<Ace::FormRendererGroup>> formRendererGroupMap_;
    std::mutex formRequestsMutex_;
    std::unordered_map<int64_t, std::unordered_map<std::string, Ace::FormRequest>> formRequests_;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration_;

    std::string hapPath_;
    std::mutex watchDogMutex_;
    bool threadIsAlive_ = true;
    std::atomic_bool hasMonitor_ = false;
    std::shared_ptr<ThreadState> threadState_;
};
}  // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_RENDER_RECORD_H
