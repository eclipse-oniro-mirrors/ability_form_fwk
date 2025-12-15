/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

import { BusinessError, AsyncCallback } from '@ohos.base';
import UIExtensionAbility from '@ohos.app.ability.UIExtensionAbility'
import LiveFormExtensionContext from 'application.LiveFormExtensionContext';
import type UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import formInfo from '@ohos.app.form.formInfo';
import Want from '@ohos.app.ability.Want';
import { RecordData } from '@ohos.base';

interface LiveFormInfo {
  formId: string;
  rect: formInfo.Rect;
  borderRadius: double;
}

export default class LiveFormExtensionAbility extends UIExtensionAbility {
  public context: LiveFormExtensionContext = {};

  private native nativeSetWindowBackgroundColor(): void;

  setWindowBackgroundColor(): void {
    taskpool.execute((): void => {
      this.nativeSetWindowBackgroundColor();
    });
  }

  onSessionCreate(want: Want, session: UIExtensionContentSession): void {
    console.log('onSessionCreate');
    if (!want.parameters) {
      console.error('null parameters');
      this.onDestroy();
      return;
    }

    let extraInfo = want.parameters?.get("extraInfo") as Record<string, RecordData>;
    if (!extraInfo) {
      console.error('null extraInfo');
      this.onDestroy();
      return;
    }

    let formInfo = extraInfo?.get("formInfo") as Record<string, RecordData>;
    if (!formInfo) {
      console.error('null formInfo');
      this.onDestroy();
      return;
    }

    let rect = formInfo?.get("rect") as Record<string, RecordData>;
    if (rect == null) {
      console.error('null rect');
      this.onDestroy();
      return;
    }

    let left = rect?.get("left") as double;
    let top = rect?.get("top") as double;
    let width = rect?.get("width") as double;
    let height = rect?.get("height") as double;
    let formId = formInfo?.get("formId") as string;
    let borderRadius = formInfo?.get("borderRadius") as double;
    if (formId == null || borderRadius == null || left == null || top == null || width == null || height == null) {
      console.error('null formInfo data');
      this.onDestroy();
      return;
    }

    let liveFormInfo : LiveFormInfo =
    {
      formId: formId,
      rect: { left: left, top: top, width: width, height: height},
      borderRadius: borderRadius
    };

    this.setWindowBackgroundColor();

    this.onLiveFormCreate(liveFormInfo, session);
  }

  onLiveFormCreate(liveFormInfo: LiveFormInfo, session: UIExtensionContentSession): void {
    console.log('onLiveFormCreate');
  }

  onDestroy(): Promise<void> | undefined {
    console.log('onDestroy');
    let liveFormInfo : LiveFormInfo = { formId: "default", rect: { left: 0, top: 0, width: 0, height: 0}, borderRadius: 0 };
    this.onLiveFormDestroy(liveFormInfo);
    return undefined;
  }

  onLiveFormDestroy(liveFormInfo: LiveFormInfo):void {
    console.log('onLiveFormDestroy');
  }
}
