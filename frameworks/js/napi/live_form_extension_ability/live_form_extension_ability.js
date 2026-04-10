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
const FORM_LAYOUT_SCALE = 'layout_scale';
const NUMBER_TYPE = 'number';
const FORM_FONT_SCALE_KEY = 'ohos.extra.param.key.form_font_size_scale';
const FORM_FONT_WEIGHT_SCALE_KEY = 'ohos.extra.param.key.form_font_weight_scale';

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

    let layoutScale = want.parameters[FORM_LAYOUT_SCALE];
    if (layoutScale > 0) {
      try {
        this.context.setUIExtCustomDensity(layoutScale)
          .then(() => {
            hilog.sLogI(domainID, TAG, 'setUIExtCustomDensity succeed');
          })
          .catch((err) => {
            hilog.sLogE(domainID, TAG, `setUIExtCustomDensity failed, code is ${err?.code}, message is ${err?.message}`);
          });
      } catch(err) {
        hilog.sLogE(domainID, TAG, `setUIExtCustomDensity failed, code is ${err?.code}, message is ${err?.message}`);
      }
    }

    let fontScale = want.parameters[FORM_FONT_SCALE_KEY];
    // fontWeight is unused until UEA providers api for setting font weight
    let fontWeight = want.parameters[FORM_FONT_WEIGHT_SCALE_KEY];
    if (typeof fontScale === NUMBER_TYPE && typeof fontWeight === NUMBER_TYPE) {
      hilog.sLogD(domainID, TAG,
        `setFontScale ${FORM_FONT_SCALE_KEY}: ${fontScale}, ${FORM_FONT_WEIGHT_SCALE_KEY}: ${fontWeight}`);
      try {
        this.context.setFontScale(fontScale)
          .then(() => {
            hilog.sLogI(domainID, TAG, `setFontScale succeed, scale is ${fontScale}`);
          })
          .catch((err) => {
            hilog.sLogE(domainID, TAG, `setFontScale failed, code is ${err?.code}, message is ${err?.message}`);
          });
      } catch(err) {
        hilog.sLogE(domainID, TAG, `setFontScale failed, code is ${err?.code}, message is ${err?.message}`);
      }
    } else {
      hilog.sLogE(domainID, TAG, `setFontScale fontScale or fontWeight isn't number type`);
    }

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