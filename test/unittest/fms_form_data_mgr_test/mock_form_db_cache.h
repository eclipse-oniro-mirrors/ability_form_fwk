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

#ifndef OHOS_MOCK_FORM_DB_CACHE_H
#define OHOS_MOCK_FORM_DB_CACHE_H

#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "common/util/form_util.h"

namespace OHOS {
    void MockGetAllFormInfoSize(int32_t mockRet, int callingUid);
}
#endif // OHOS_MOCK_FORM_DB_CACHE_H