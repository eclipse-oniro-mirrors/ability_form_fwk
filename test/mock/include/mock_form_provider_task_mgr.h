/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub header for FormProviderTaskMgr used in unit testing.
 */

#ifndef OHOS_FORM_FWK_MOCK_FORM_PROVIDER_TASK_MGR_H
#define OHOS_FORM_FWK_MOCK_FORM_PROVIDER_TASK_MGR_H

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include "gmock/gmock.h"
#include "iremote_object.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

class AbstractMockFormProviderTaskMgr {
public:
    virtual ~AbstractMockFormProviderTaskMgr() = default;
    virtual void PostAcquireDataTask(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &remoteObject) = 0;
    virtual void PostAcquireTask(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &remoteObject) = 0;
    virtual void PostRefreshTask(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &remoteObject) = 0;
    virtual void PostDeleteTask(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &remoteObject) = 0;
    virtual void PostProviderBatchDeleteTask(std::set<int64_t> &formIds, const Want &want,
        const sptr<IRemoteObject> &remoteObject) = 0;
    virtual void PostCastTempTask(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &remoteObject) = 0;
    virtual void PostAcquireStateTask(const Want &wantArg, const std::string &provider, const Want &want,
        const sptr<IRemoteObject> &remoteObject) = 0;
};

class MockFormProviderTaskMgr : public AbstractMockFormProviderTaskMgr {
public:
    static std::shared_ptr<MockFormProviderTaskMgr> obj;
    MockFormProviderTaskMgr() = default;
    ~MockFormProviderTaskMgr() override = default;
    MOCK_METHOD3(PostAcquireDataTask, void(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &remoteObject));
    MOCK_METHOD3(PostAcquireTask, void(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &remoteObject));
    MOCK_METHOD3(PostRefreshTask, void(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &remoteObject));
    MOCK_METHOD3(PostDeleteTask, void(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &remoteObject));
    MOCK_METHOD3(PostProviderBatchDeleteTask, void(std::set<int64_t> &formIds, const Want &want,
        const sptr<IRemoteObject> &remoteObject));
    MOCK_METHOD3(PostCastTempTask, void(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &remoteObject));
    MOCK_METHOD4(PostAcquireStateTask, void(const Want &wantArg, const std::string &provider, const Want &want,
        const sptr<IRemoteObject> &remoteObject));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_PROVIDER_TASK_MGR_H
