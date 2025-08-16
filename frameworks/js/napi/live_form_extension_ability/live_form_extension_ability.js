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

let hilog = requireNapi('hilog');
let UIExtensionAbility = requireNapi('app.ability.UIExtensionAbility');

const domainID = 0xD001301;
const TAG = 'FormManagerService';

export default class LiveFormExtensionAbility extends UIExtensionAbility {
  liveFormInfo = undefined;

  onSessionCreate(want, session) {
    hilog.slogI(domainID, TAG, 'onSessionCreate');
    if (!want.parameters) {
      hilog.slogE(domainID, TAG, 'null parameters');
      this.onDestroy();
      return;
    }

    let extraInfo = want.parameters.extraInfo;
    if (!extraInfo) {
      hilog.slogE(domainID, TAG, 'null extraInfo');
      this.onDestroy();
      return;
    }

    this.liveFormInfo = extraInfo.formInfo;
    if (!this.liveFormInfo) {
      hilog.slogE(domainID, TAG, 'null liveFormInfo');
      this.onDestroy();
      return;
    }

    this.context.formId = this.liveFormInfo.formId;
    this.context.setWindowBackgroundColor()
      .then(() => {
          hilog.slogI(domainID, TAG, 'setWindowBackgroundColor succeed');
      })
      .catch((err) => {
        hilog.slogE(domainID, TAG, `setWindowBackgroundColor failed, code is ${err?.code}, message is ${err?.message}`);
      });

    this.onLiveFormCreate(this.liveFormInfo, session);
  }

  onLiveFormCreate(liveFormInfo, session) {
    hilog.slogI(domainID, TAG, 'onLiveFormCreate');
  }

  onDestroy() {
    hilog.slogI(domainID, TAG, 'onDestroy');
    this.onLiveFormDestroy(this.liveFormInfo);
  }

  onLiveFormDestroy(liveFormInfo) {
    hilog.slogI(domainID, TAG, 'onLiveFormDestroy');
  }
}