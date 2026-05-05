/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormProviderTaskMgr used in unit testing.
 */

#include "mock_form_provider_task_mgr.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "form_provider/form_provider_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormProviderTaskMgr> MockFormProviderTaskMgr::obj = nullptr;

FormProviderTaskMgr::FormProviderTaskMgr() {}
FormProviderTaskMgr::~FormProviderTaskMgr() {}

void FormProviderTaskMgr::PostAcquireDataTask(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostAcquireDataTask called";
    if (MockFormProviderTaskMgr::obj) {
        MockFormProviderTaskMgr::obj->PostAcquireDataTask(formId, want, remoteObject);
    }
}

void FormProviderTaskMgr::PostAcquireTask(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostAcquireTask called";
    if (MockFormProviderTaskMgr::obj) {
        MockFormProviderTaskMgr::obj->PostAcquireTask(formId, want, remoteObject);
    }
}

void FormProviderTaskMgr::PostRefreshTask(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostRefreshTask called";
    if (MockFormProviderTaskMgr::obj) {
        MockFormProviderTaskMgr::obj->PostRefreshTask(formId, want, remoteObject);
    }
}

void FormProviderTaskMgr::PostDeleteTask(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostDeleteTask called";
    if (MockFormProviderTaskMgr::obj) {
        MockFormProviderTaskMgr::obj->PostDeleteTask(formId, want, remoteObject);
    }
}

void FormProviderTaskMgr::PostProviderBatchDeleteTask(std::set<int64_t> &formIds, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostProviderBatchDeleteTask called";
    if (MockFormProviderTaskMgr::obj) {
        MockFormProviderTaskMgr::obj->PostProviderBatchDeleteTask(formIds, want, remoteObject);
    }
}

void FormProviderTaskMgr::PostCastTempTask(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostCastTempTask called";
    if (MockFormProviderTaskMgr::obj) {
        MockFormProviderTaskMgr::obj->PostCastTempTask(formId, want, remoteObject);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
