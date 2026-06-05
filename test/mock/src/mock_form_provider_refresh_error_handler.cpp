/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormProviderRefreshErrorHandler and
 * FormProviderConnectionErrorHandler base methods used in unit testing.
 */

#include "mock_form_provider_refresh_error_handler.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "form_provider/error_handler/provider_error_handler_factory.h"
#include "form_provider/error_handler/provider_refresh_error_handler.h"
#include "form_provider/error_handler/provider_connection_error_handler.h"
#include "common/retry_policy/retry_policy.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormProviderRefreshErrorHandler> MockFormProviderRefreshErrorHandler::obj = nullptr;

// --- FormProviderRefreshErrorHandler (derived class overrides) ---
bool FormProviderRefreshErrorHandler::HandleConnectError(
    int64_t formId, const sptr<IRemoteObject> &remoteObject, const Want &want)
{
    GTEST_LOG_(INFO) << "HandleConnectError called";
    if (MockFormProviderRefreshErrorHandler::obj) {
        return MockFormProviderRefreshErrorHandler::obj->HandleConnectError(formId, remoteObject, want);
    }
    return false;
}

bool FormProviderRefreshErrorHandler::HandleSendRequestFailed(
    int64_t formId, int errorCode, const Want &want)
{
    GTEST_LOG_(INFO) << "HandleSendRequestFailed called";
    if (MockFormProviderRefreshErrorHandler::obj) {
        return MockFormProviderRefreshErrorHandler::obj->HandleSendRequestFailed(formId, errorCode, want);
    }
    return false;
}

bool FormProviderRefreshErrorHandler::HandleDisconnectError(
    int64_t formId, int resultCode, const Want &want)
{
    GTEST_LOG_(INFO) << "HandleDisconnectError called formId:" << formId
        << " resultCode:" << resultCode;
    if (MockFormProviderRefreshErrorHandler::obj) {
        return MockFormProviderRefreshErrorHandler::obj->HandleDisconnectError(formId, resultCode, want);
    }
    return false;
}

void FormProviderRefreshErrorHandler::ExecuteRefreshRetry(int64_t formId, const Want &want)
{
    GTEST_LOG_(INFO) << "ExecuteRefreshRetry called";
}

// --- FormProviderConnectionErrorHandler (base class methods) ---
void FormProviderConnectionErrorHandler::ScheduleRetry(int64_t formId, const Want &want,
    const RetryPolicy &policy, std::function<void()> retryFunc)
{
    GTEST_LOG_(INFO) << "ScheduleRetry stub called";
}

void FormProviderConnectionErrorHandler::RemoveRetryPolicy(int64_t formId)
{
    GTEST_LOG_(INFO) << "RemoveRetryPolicy stub called";
}

bool FormProviderConnectionErrorHandler::ShouldRetry(int errorCode)
{
    GTEST_LOG_(INFO) << "ShouldRetry stub called";
    return false;
}

bool FormProviderConnectionErrorHandler::IsRemoteDead(int errorCode)
{
    GTEST_LOG_(INFO) << "IsRemoteDead stub called";
    return false;
}

}  // namespace AppExecFwk
}  // namespace OHOS