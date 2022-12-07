/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "want.h"

namespace {
    bool g_mockGetBoolParamRet = true;
    bool g_mockGetStringParamRet = true;
}

void MockGetBoolParam(bool mockRet)
{
    g_mockGetBoolParamRet = mockRet;
}

void MockGetStringParam(bool mockRet)
{
    g_mockGetStringParamRet = mockRet;
}

namespace OHOS {
namespace AAFwk {
/**
 * @description:Default construcotr of Want class, which is used to initialzie flags and URI.
 * @param None
 * @return None
 */
Want::Want()
{}

/**
 * @description: Default deconstructor of Want class
 * @param None
 * @return None
 */
Want::~Want()
{}

/**
 * @description: Obtains a bool-type value matching the given key.
 * @param key   Indicates the key of WantParams.
 * @param defaultValue  Indicates the default bool-type value.
 * @return Returns the bool-type value of the parameter matching the given key;
 * returns the default value if the key does not exist.
 */
bool Want::GetBoolParam(const std::string &key, bool defaultValue) const
{
    return g_mockGetBoolParamRet;
}

std::string Want::GetStringParam(const std::string &key) const
{
    if (true == g_mockGetStringParamRet) {
        return "aa";
    }
    return std::string();
}
}  // namespace AAFwk
}  // namespace OHOS