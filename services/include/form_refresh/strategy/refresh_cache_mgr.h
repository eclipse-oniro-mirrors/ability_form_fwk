/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_REFRESH_CACHE_MGR_H
#define OHOS_FORM_FWK_REFRESH_CACHE_MGR_H

#include <singleton.h>

#include "data_center/form_record/form_record.h"
#include "common/timer_mgr/form_timer.h"
#include "form_constants.h"

namespace OHOS {
namespace AppExecFwk {
/**
* @class RefreshCacheMgr
* RefreshCacheMgr is used to cache form refresh task.
*/
class RefreshCacheMgr : public DelayedRefSingleton<RefreshCacheMgr> {
    DECLARE_DELAYED_REF_SINGLETON(RefreshCacheMgr);
public:
    DISALLOW_COPY_AND_MOVE(RefreshCacheMgr);

    /**
     * @brief Current system overload, refresh task add to cache queue.
     * @param task Form timer task.
     */
    void AddToOverloadTaskQueue(const FormTimer &task);

    /**
     * @brief System load level down, consume refresh task.
     */
    void ConsumeOverloadTaskQueue();

    /**
     * @brief Refresh task be healthy controlled, add cache flag.
     * @param formId The formId.
     * @param isAskForProviderData True: ask for provider data, False: update by provider data.
     */
    void AddFlagByHealthyControl(const int64_t formId, bool isAskForProviderData);

    /**
     * @brief The application healthy control be released, consume cache flag.
     * @param record The form record.
     * @param userId Current active userId.
     */
    void ConsumeHealthyControlFlag(std::vector<FormRecord>::iterator &record, const int32_t userId);

    /**
     * @brief Refresh task be form invisible controlled, add cache flag.
     * @param formId The formId.
     * @param refreshType The refresh source type.
     */
    void AddFlagByInvisible(const int64_t formId, const int32_t refreshType);

    /**
     * @brief The form resume visible, consume cache flag.
     * @param formId The formId.
     * @param userId Current active userId.
     */
    void ConsumeInvisibleFlag(const int64_t formId, const int32_t userId);

    /**
     * @brief Refresh task be screen off controlled, add cache flag.
     * @param formId The formId.
     * @param want The want of the form to refresh.
     * @param record The form record.
     */
    void AddFlagByScreenOff(const int64_t formId, const Want &want, FormRecord &record);

    /**
     * @brief Receive screen unlock, consume cache flag.
     */
    void ConsumeScreenOffFlag();

    /**
     * @brief Render task be form invisible controlled, add cache queue.
     * @param formId The formId.
     * @param task The render form task.
     */
    void AddRenderTask(int64_t formId, std::function<void()> task);

    /**
     * @brief The form resume visible, consume cache task.
     * @param formId The formId.
     */
    void ConsumeRenderTask(int64_t formId);

    /**
     * @brief Delete the form render cache task.
     * @param formId The formId.
     */
    void DelRenderTask(int64_t formId);

    /**
     * @brief Cosume refresh when form exempt due control.
     * @param disableFormRecords The due disable form list.
     */
    void CosumeRefreshByDueControl(const std::vector<FormRecord> &disableFormRecords);

    /**
     * @brief The form add finish, consume cache flag.
     * @param formId The formId.
     * @param userId Current active userId.
     */
    void ConsumeAddUnfinishFlag(const int64_t formId);

private:
    std::mutex overloadTaskMutex_;
    std::vector<FormTimer> overloadTask_;
    std::mutex renderTaskMapMutex_;
    std::unordered_map<int64_t, std::function<void()>> renderTaskMap_;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_REFRESH_CACHE_MGR_H