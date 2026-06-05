/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub header for FormProviderRefreshErrorHandler used in unit testing.
 */

#ifndef OHOS_FORM_FWK_MOCK_FORM_PROVIDER_REFRESH_ERROR_HANDLER_H
#define OHOS_FORM_FWK_MOCK_FORM_PROVIDER_REFRESH_ERROR_HANDLER_H

#include <cstdint>
#include <memory>
#include <string>
#include "gmock/gmock.h"
#include "iremote_object.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

class AbstractMockFormProviderRefreshErrorHandler {
public:
    virtual ~AbstractMockFormProviderRefreshErrorHandler() = default;
    virtual bool HandleConnectError(int64_t formId,
        const sptr<IRemoteObject> &remoteObject, const Want &want) = 0;
    virtual bool HandleSendRequestFailed(int64_t formId,
        int errorCode, const Want &want) = 0;
    virtual bool HandleDisconnectError(int64_t formId,
        int resultCode, const Want &want) = 0;
};

class MockFormProviderRefreshErrorHandler : public AbstractMockFormProviderRefreshErrorHandler {
public:
    static std::shared_ptr<MockFormProviderRefreshErrorHandler> obj;
    MockFormProviderRefreshErrorHandler() = default;
    ~MockFormProviderRefreshErrorHandler() override = default;

    MOCK_METHOD3(HandleConnectError, bool(int64_t formId,
        const sptr<IRemoteObject> &remoteObject, const Want &want));
    MOCK_METHOD3(HandleSendRequestFailed, bool(int64_t formId,
        int errorCode, const Want &want));
    MOCK_METHOD3(HandleDisconnectError, bool(int64_t formId,
        int resultCode, const Want &want));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_PROVIDER_REFRESH_ERROR_HANDLER_H