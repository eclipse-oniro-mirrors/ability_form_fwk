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

import { Callback, AsyncCallback, BusinessError } from '@ohos.base';
import Want from '@ohos.app.ability.Want';
import formInfo from '@ohos.app.form.formInfo';

export namespace formHost {

  loadLibrary("formHost_ani.z");

  native function addForm_inner(want: Want): formInfo.RunningFormInfo;
  native function deleteForm_inner(formId: string): void;
  native function deleteInvalidForms_inner(formIds: Array<string>): int;
  native function isSystemReady_inner(): void;
  native function getAllFormsInfo_inner(): Array<formInfo.FormInfo>;
  native function getFormsInfoByFilter_inner(filter: formInfo.FormInfoFilter): Array<formInfo.FormInfo>;
  native function getFormsInfo_inner(bundleName: string, moduleName: string): Array<formInfo.FormInfo>;
  native function notifyFormsEnableUpdate_inner(formIds: Array<string>, isEnableUpdate: boolean): void;
  native function notifyFormsVisible_inner(formIds: Array<string>, isVisible: boolean): void;
  native function releaseForm_inner(formId: string, isReleaseCache: boolean): void;
  native function requestForm_inner(formId: string): void;
  native function requestFormWithParams_inner(formId: string, wantParams: Record<string, Object>): void;
  native function castToNormalForm_inner(formId: string): void;
  native function notifyVisibleForms_inner(formIds: Array<string>): void;
  native function notifyInvisibleForms_inner(formIds: Array<string>): void;
  native function setFormUpdate_inner(formIds: Array<string>, isEnable: boolean): void;
  native function updateFormLocation(formId: string, location: formInfo.FormLocation): void;
  native function setFormsRecyclable_inner(formIds: Array<string>): void;
  native function recycleForms_inner(formIds: Array<string>): void;
  native function recoverForms_inner(formIds: Array<string>): void;

  const INVALID_PARAM_ERROR_CODE = 401;

  export function addForm(want: Want): Promise<formInfo.RunningFormInfo> {
    return new Promise<formInfo.RunningFormInfo>((resolve, reject) => {
      let runningFormInfo = addForm_inner(want);
      resolve(runningFormInfo);
    });
  }

  export function deleteForm(formId: string, callback: AsyncCallback<void>): void {
    if(formId == "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid')), undefined);
      return;
    }

    taskpool.execute(() : void => { return deleteForm_inner(formId); }).then(() => {
      callback(null, undefined);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function deleteForm(formId: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if(formId == "") {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid')));
      }

      deleteForm_inner(formId);
      resolve(undefined);
    });
  }

  export function deleteInvalidForms(formIds: Array<string>): Promise<int> {
    return new Promise<int>((resolve, reject) => {
      if(formIds.length == 0) {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')));
      }

      let count: int = deleteInvalidForms_inner(formIds);
      resolve(count);
    });
  }

  export function deleteInvalidForms(formIds: Array<string>, callback: AsyncCallback<int>): void {
    if(formIds.length == 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')), undefined);
      return;
    }

    taskpool.execute(() : int => { return deleteInvalidForms_inner(formIds); }).then((value : Any) => {
      let deletedFormCount : int = value as int
      callback(null, deletedFormCount);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function disableFormsUpdate(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if(formIds.length == 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')), undefined);
      return;
    }

    taskpool.execute(() : void => { return setFormUpdate_inner(formIds, false); }).then(() => {
      callback(null, undefined);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function disableFormsUpdate(formIds: Array<string>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if(formIds.length == 0) {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')));
      }

      setFormUpdate_inner(formIds, false);
      resolve(undefined);
    });
  }

  export function enableFormsUpdate(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if(formIds.length == 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')), undefined);
      return;
    }

    taskpool.execute(() : void => { return setFormUpdate_inner(formIds, true); }).then(() => {
      callback(null, undefined);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function enableFormsUpdate(formIds: Array<string>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if(formIds.length == 0) {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')));
      }

      setFormUpdate_inner(formIds, true);
      resolve(undefined);
    });
  }

  export function getAllFormsInfo(): Promise<Array<formInfo.FormInfo>> {
    return new Promise<Array<formInfo.FormInfo>>((resolve, reject) => {
      let formInfos : Array<formInfo.FormInfo> = getAllFormsInfo_inner();
      resolve(formInfos);
    });
  }

  export function getAllFormsInfo(callback: AsyncCallback<Array<formInfo.FormInfo>>): void {
    taskpool.execute(() : Array<formInfo.FormInfo> => {
      return getAllFormsInfo_inner(); }).then((result: Array<formInfo.FormInfo> | Any) => {
      callback(null, result as Array<formInfo.FormInfo>);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function getFormsInfo(filter: formInfo.FormInfoFilter): Promise<Array<formInfo.FormInfo>> {
    return new Promise<Array<formInfo.FormInfo>>((resolve, reject) => {
      let formInfos : Array<formInfo.FormInfo> = getFormsInfoByFilter_inner(filter);
      resolve(formInfos);
    });
  }

  export function getFormsInfo(bundleName: string, moduleName: string, callback: AsyncCallback<Array<formInfo.FormInfo>> ): void {
    if(bundleName == "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('bundleName param invalid')), undefined);
      return;
    } else if (moduleName == "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('moduleName param invalid')), undefined);
      return;
    }

    taskpool.execute(() : Array<formInfo.FormInfo> => {
      return getFormsInfo_inner(bundleName, moduleName); }).then((value : Any) => {
      let formInfos : Array<formInfo.FormInfo> = value as Array<formInfo.FormInfo>;
      callback(null, formInfos);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function getFormsInfo(bundleName: string, moduleName?: string): Promise<Array<formInfo.FormInfo>> {
    let tempModule: string = "";
    if (moduleName != undefined) {
      tempModule = moduleName;
    }
    return new Promise<Array<formInfo.FormInfo>>((resolve, reject) => {
      if(bundleName == "") {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('bundleName param invalid')));
      }

      let formInfos : Array<formInfo.FormInfo> = getFormsInfo_inner(bundleName, tempModule);
      resolve(formInfos);
    });
  }

  export function getFormsInfo(bundleName: string, callback: AsyncCallback<Array<formInfo.FormInfo>>): void {
    if(bundleName.length == 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('bundleName param invalid')), undefined);
      return;
    }

    let emptyString: string = ""
    taskpool.execute(() : Array<formInfo.FormInfo> => {
      return getFormsInfo_inner(bundleName, emptyString); }).then((value: Any) => {
      let formInfos: Array<formInfo.FormInfo> = value as Array<formInfo.FormInfo>;
      callback(null, formInfos);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function isSystemReady(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      isSystemReady_inner();
      resolve(undefined);
    });
  }

  export function isSystemReady(callback: AsyncCallback<void>): void {
    taskpool.execute(() : void => { return isSystemReady_inner(); }).then(() => {
      callback(null, undefined);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function notifyFormsEnableUpdate(formIds: Array<string>, isEnableUpdate: boolean, callback: AsyncCallback<void>): void{
    if(formIds.length == 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')), undefined);
      return;
    }

    taskpool.execute(() => {
        notifyFormsEnableUpdate_inner(formIds, isEnableUpdate);
      }).then(() => {
        callback(null, undefined);
      }).catch((e: Any) => {
        callback(e as BusinessError, undefined);
    });
  }

  export function notifyFormsEnableUpdate(formIds: Array<string>, isEnableUpdate: boolean): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if(formIds.length == 0) {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')));
      }

      notifyFormsEnableUpdate_inner(formIds, isEnableUpdate);
      resolve(undefined);
    });
  }

  export function notifyFormsVisible(formIds: Array<string>, isVisible: boolean, callback: AsyncCallback<void>): void {
    if(formIds.length == 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')), undefined);
      return;
    }

    taskpool.execute(() => {
        notifyFormsVisible_inner(formIds, isVisible);
      }).then(() => {
        callback(null, undefined);
      }).catch((e: Any) => {
        callback(e as BusinessError, undefined);
    });
  }

  export function notifyFormsVisible(formIds: Array<string>, isVisible: boolean): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if(formIds.length == 0) {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')));
      }

      notifyFormsVisible_inner(formIds, isVisible);
      resolve(undefined);
    });
  }

  export function releaseForm(formId: string, isReleaseCache?: boolean) : Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if(formId == "") {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid')));
      }

      if (isReleaseCache == undefined) {
        releaseForm_inner(formId, false);
      } else {
        releaseForm_inner(formId, isReleaseCache);
      }
      resolve(undefined);
    });
  }

  export function releaseForm(formId: string, isReleaseCache: boolean, callback: AsyncCallback<void>) : void {
    if(formId == "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid')), undefined);
      return;
    }

    taskpool.execute(() : void => { return releaseForm_inner(formId, isReleaseCache); }).then(() => {
      callback(null, undefined);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function releaseForm(formId: string, callback: AsyncCallback<void>) : void {
    if(formId == "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid')), undefined);
      return;
    }

    taskpool.execute(() : void => { return releaseForm_inner(formId, true); }).then(() => {
      callback(null, undefined);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function requestForm(formId: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if(formId == "") {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid')));
      }

      requestForm_inner(formId);
      resolve(undefined);
    });
  }

  export function requestForm(formId: string, callback: AsyncCallback<void>): void {
    if(formId == "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid')), undefined);
      return;
    }

    taskpool.execute(() : void => { return requestForm_inner(formId); }).then(() => {
      callback(null, undefined);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function requestFormWithParams(formId: string, wantParams?: Record<string, Object>): Promise<void> {
    let _wantParams: Record<string, Object> = {};
    if (wantParams) {
      _wantParams = wantParams;
    }

    return new Promise<void>((resolve, reject) => {
      if(formId == "") {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid')));
      }

      requestFormWithParams_inner(formId, _wantParams);
      resolve(undefined);
    });
  }

  export function castToNormalForm(formId: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if(formId == "") {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid')));
      }

      castToNormalForm_inner(formId);
      resolve(undefined);
    });
  }

  export function castToNormalForm(formId: string, callback: AsyncCallback<void>): void {
    if(formId == "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid')), undefined);
      return;
    }

    taskpool.execute(() : void => { return castToNormalForm_inner(formId); }).then(() => {
      callback(null, undefined);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function notifyVisibleForms(formIds: Array<string>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if(formIds.length == 0) {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')));
      }

      notifyVisibleForms_inner(formIds);
      resolve(undefined);
    });
  }

  export function notifyVisibleForms(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if(formIds.length == 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')), undefined);
      return;
    }

    taskpool.execute(() : void => { return notifyVisibleForms_inner(formIds); }).then(() => {
      callback(null, undefined);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function notifyInvisibleForms(formIds: Array<string>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if(formIds.length == 0) {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')));
      }

      notifyInvisibleForms_inner(formIds);
      resolve(undefined);
    });
  }

  export function notifyInvisibleForms(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if(formIds.length == 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')), undefined);
      return;
    }

    taskpool.execute(() : void => { return notifyInvisibleForms_inner(formIds); }).then(() => {
      callback(null, undefined);
    }).catch((e: Any) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function setFormsRecyclable(formIds: Array<string>): Promise<void> {
		return new Promise<void>((resolve, reject) => {
      if(formIds.length == 0) {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')));
      }

			setFormsRecyclable_inner(formIds);
			resolve(undefined);
		});
	}

	export function setFormsRecyclable(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if(formIds.length == 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')), undefined);
      return;
    }

		taskpool.execute(() => setFormsRecyclable_inner(formIds)).then(() => {
			callback(null, undefined);
		}).catch((e: Any) => {
			callback(e as BusinessError, undefined);
		});
	}

	export function recycleForms(formIds: Array<string>): Promise<void> {
		return new Promise<void>((resolve, reject) => {
      if(formIds.length == 0) {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')));
      }

			recycleForms_inner(formIds);
			resolve(undefined);
		});
	}

	export function recoverForms(formIds: Array<string>): Promise<void> {
		return new Promise<void>((resolve, reject) => {
      if(formIds.length == 0) {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')));
      }

			recoverForms_inner(formIds);
			resolve(undefined);
		});
	}

	export function recoverForms(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if(formIds.length == 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formIds param invalid')), undefined);
      return;
    }

		taskpool.execute(() => recoverForms_inner(formIds)).then(() => {
			callback(null, undefined);
		}).catch((e: Any) => {
			callback(e as BusinessError, undefined);
		});
	}
}