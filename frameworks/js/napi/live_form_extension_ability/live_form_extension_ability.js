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

let UIExtensionAbility = requireNapi('app.ability.UIExtensionAbility');

export default class LiveFormExtensionAbility extends UIExtensionAbility {
  liveFormInfo = undefined;

  onSessionCreate(want, session) {
    console.log('onSessionCreate');
    if (!want.parameters) {
      console.error('null parameters');
      this.onDestroy();
      return;
    }

    let extraInfo = want.parameters.extraInfo;
    if (!extraInfo) {
      console.error('null extraInfo');
      this.onDestroy();
      return;
    }

    this.liveFormInfo = extraInfo.formInfo;
    if (!this.liveFormInfo) {
      console.error('null liveFormInfo');
      this.onDestroy();
      return;
    }

    this.context.setWindowBackgroundColor('#00FFFFFF')
      .then(() => {
          console.info('setWindowBackgroundColor succeed');
      })
      .catch((err) => {
          console.error(`setWindowBackgroundColor failed, code is ${err?.code}, message is ${err?.message}`);
      });

    this.onLiveFormCreate(this.liveFormInfo, session);
  }

  onLiveFormCreate(liveFormInfo, session) {
    console.log('onLiveFormCreate');
  }

  onDestroy() {
    console.log('onDestroy');
    this.onLiveFormDestroy(this.liveFormInfo);
  }

  onLiveFormDestroy(liveFormInfo) {
    console.log('onLiveFormDestroy');
  }
}