/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormCacheMgr used in unit testing.
 */

#include "data_center/form_cache_mgr.h"

namespace OHOS {
namespace AppExecFwk {

FormCacheMgr::FormCacheMgr() {}
FormCacheMgr::~FormCacheMgr() {}

void FormCacheMgr::Start() {}

bool FormCacheMgr::AddData(int64_t formId, const FormProviderData &formProviderData)
{
    return true;
}

bool FormCacheMgr::DeleteData(int64_t formId)
{
    return true;
}

bool FormCacheMgr::GetData(int64_t formId, std::string &data,
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> &imageDataMap) const
{
    return false;
}

bool FormCacheMgr::NeedAcquireProviderData(int64_t formId) const
{
    return false;
}

bool FormCacheMgr::IsDirtyDataCleaned() const
{
    return true;
}

void FormCacheMgr::SetIsDirtyDataCleaned() {}

bool FormCacheMgr::GetFormCacheIds(std::unordered_set<int64_t> &formIds)
{
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
