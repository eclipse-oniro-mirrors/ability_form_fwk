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
#include "common/connection/form_ability_connection.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

class MockFormProviderRefreshErrorHandler {
public:
    static std::shared_ptr<MockFormProviderRefreshErrorHandler> obj;
    MockFormProviderRefreshErrorHandler() = default;
    virtual ~MockFormProviderRefreshErrorHandler() = default;

    MOCK_METHOD(bool, HandleSendRequestFailed, (int64_t formId,
        (int errorCode), (const Want &want)));
    MOCK_METHOD(bool, HandleDisconnectError, (int64_t formId,
        (const sptr<FormAbilityConnection> &connection)));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_PROVIDER_REFRESH_ERROR_HANDLER_H