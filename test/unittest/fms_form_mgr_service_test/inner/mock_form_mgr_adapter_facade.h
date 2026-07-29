/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef INNER_MOCK_FORM_MGR_ADAPTER_FACADE_H
#define INNER_MOCK_FORM_MGR_ADAPTER_FACADE_H

#include "form_constants.h"
#include "iremote_object.h"
#include "template_form_detail_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {

void MockFormMgrAdapterFacadeStartAbilityByFms(int mockRet);
void MockFormMgrAdapterFacadeRegisterChangeSceneAnimationStateProxy(int mockRet);
void MockFormMgrAdapterFacadeRegisterOverflowProxy(int mockRet);
void MockFormMgrAdapterFacadeRegisterGetFormRectProxy(int mockRet);
void MockFormMgrAdapterFacadeRegisterGetLiveFormStatusProxy(int mockRet);
void MockFormMgrAdapterFacadeUnregisterGetLiveFormStatusProxy(int mockRet);
void MockFormMgrAdapterFacadeUpdateFormSizeFloat(int mockRet);
void MockFormMgrAdapterFacadeRegisterTemplateFormDetailInfoChange(int mockRet);
void MockFormMgrAdapterFacadeUnregisterTemplateFormDetailInfoChange(int mockRet);
void MockFormMgrAdapterFacadeUpdateTemplateFormDetailInfo(int mockRet);
void MockFormMgrAdapterFacadeUnregisterPublishFormCrossBundleControl(int mockRet);
void MockFormMgrAdapterFacadePublishFormCrossBundleControl(bool mockRet);
void MockHasFormVisible(bool mockRet);
void MockEnableForms(int mockRet);
void MockRegisterFormWantCallback(int mockRet);
void MockUnregisterFormWantCallback(int mockRet);
void MockRegisterDeleteFormsCallback(int mockRet);
void MockUnregisterDeleteFormsCallback(int mockRet);
void MockDeleteForms(int mockRet);
void MockUpdateFormCrossBundle(int mockRet);

}  // namespace AppExecFwk
}  // namespace OHOS

#endif // INNER_MOCK_FORM_MGR_ADAPTER_FACADE_H
