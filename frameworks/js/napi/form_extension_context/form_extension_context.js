/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

let ExtensionContext = requireNapi('application.ExtensionContext');

class FormExtensionContext extends ExtensionContext {
  constructor(obj) {
    super(obj);
  }

  updateForm(formId, formBindingData, callback) {
    console.log('FormExtensionContext updateForm');
    return this.__context_impl__.updateForm(formId, formBindingData, callback);
  }

  startAbility(want, callback) {
    return this.__context_impl__.startAbility(want, callback);
  }

  connectServiceExtensionAbility(want, options) {
    console.log('connectServiceExtensionAbility');
    return this.__context_impl__.connectServiceExtensionAbility(want, options);
  }

  disconnectServiceExtensionAbility(connection, callback) {
    console.log('disconnectServiceExtensionAbility');
    return this.__context_impl__.disconnectServiceExtensionAbility(connection, callback);
  }
}

export default FormExtensionContext;
