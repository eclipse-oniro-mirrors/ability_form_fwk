/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for RefreshCacheMgr used in unit testing.
 */

#include "form_refresh/strategy/refresh_cache_mgr.h"

namespace OHOS {
namespace AppExecFwk {

RefreshCacheMgr::RefreshCacheMgr() {}
RefreshCacheMgr::~RefreshCacheMgr() {}

void RefreshCacheMgr::AddToOverloadTaskQueue(const FormTimer &task) {}
void RefreshCacheMgr::ConsumeOverloadTaskQueue() {}
void RefreshCacheMgr::AddFlagByHealthyControl(const int64_t formId, bool isAskForProviderData) {}
void RefreshCacheMgr::ConsumeHealthyControlFlag(std::vector<FormRecord>::iterator &record, const int32_t userId) {}
void RefreshCacheMgr::AddFlagByInvisible(const int64_t formId, const int32_t refreshType) {}
void RefreshCacheMgr::ConsumeInvisibleFlag(const std::vector<FormRecord> &visibleFormRecords, int32_t userId) {}
void RefreshCacheMgr::AddFlagByScreenOff(const int64_t formId, const Want &want, FormRecord &record) {}
void RefreshCacheMgr::ConsumeScreenOffFlag() {}
void RefreshCacheMgr::AddRenderTask(int64_t formId, std::function<void()> task) {}
void RefreshCacheMgr::ConsumeRenderTask(int64_t formId) {}
void RefreshCacheMgr::DelRenderTask(int64_t formId) {}
void RefreshCacheMgr::CosumeRefreshByDueControl(const std::vector<FormRecord> &disableFormRecords) {}
void RefreshCacheMgr::ConsumeAddUnfinishFlag(const int64_t formId, const int32_t userId) {}
Want RefreshCacheMgr::CreateWant(const std::vector<FormRecord>::iterator &record, const int32_t userId)
{
    return Want();
}
} // namespace AppExecFwk
} // namespace OHOS
