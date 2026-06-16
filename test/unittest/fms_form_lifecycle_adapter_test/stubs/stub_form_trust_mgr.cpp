/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormTrustMgr used in unit testing.
 */

#include "common/util/form_trust_mgr.h"

namespace OHOS {
namespace AppExecFwk {

FormTrustMgr::FormTrustMgr() {}
FormTrustMgr::~FormTrustMgr() {}

bool FormTrustMgr::IsTrust(const std::string &bundleName)
{
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
