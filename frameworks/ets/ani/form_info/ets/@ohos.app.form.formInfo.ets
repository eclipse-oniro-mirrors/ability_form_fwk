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

import Want from '@ohos.app.ability.Want';

export default namespace formInfo {
  export interface FormInfo {
    bundleName: string;
    moduleName: string;
    abilityName: string;
    name: string;
    displayName: string;
    displayNameId: int;
    description: string;
    descriptionId: int;
    type: FormType;
    jsComponentName: string;
    isDefault: boolean;
    updateEnabled: boolean;
    formVisibleNotify: boolean;
    scheduledUpdateTime: string;
    formConfigAbility: string;
    updateDuration: int;
    defaultDimension: int;
    supportDimensions: Array<int>;
    customizeData: Record<string, string>;
    isDynamic: boolean;
    transparencyEnabled: boolean;
    supportedShapes: Array<int>;
    readonly previewImages?: Array<int>;
    readonly enableBlurBackground?: boolean;
    readonly renderingMode?: RenderingMode;
    readonly funInteractionParams?: FunInteractionParams;
    readonly sceneAnimationParams?: SceneAnimationParams;
    readonly resizable?: boolean;
    readonly groupId?: string;
    readonly isStandbySupported?: boolean;
    readonly isStandbyAdapted?: boolean;
    readonly isPrivacySensitive?: boolean;
  }

  enum RenderingMode {
    AUTO_COLOR = 0,
    FULL_COLOR = 1,
    SINGLE_COLOR = 2
  }

  enum FormType {
    JS = 1,
    eTS = 2
  }

  enum ColorMode {
    MODE_AUTO = -1,
    MODE_DARK = 0,
    MODE_LIGHT = 1
  }

  export interface FormStateInfo {
    formState: FormState;
    want: Want;
  }

  enum FormState {
    UNKNOWN = -1,
    DEFAULT = 0,
    READY = 1
  }

  enum FormParam {
    IDENTITY_KEY = 'ohos.extra.param.key.form_identity',
    DIMENSION_KEY = 'ohos.extra.param.key.form_dimension',
    NAME_KEY = 'ohos.extra.param.key.form_name',
    MODULE_NAME_KEY = 'ohos.extra.param.key.module_name',
    WIDTH_KEY = 'ohos.extra.param.key.form_width',
    HEIGHT_KEY = 'ohos.extra.param.key.form_height',
    TEMPORARY_KEY = 'ohos.extra.param.key.form_temporary',
    BUNDLE_NAME_KEY = 'ohos.extra.param.key.bundle_name',
    ABILITY_NAME_KEY = 'ohos.extra.param.key.ability_name',
    THEME_KEY = 'ohos.extra.param.key.form_is_theme',
    DEVICE_ID_KEY = 'ohos.extra.param.key.device_id',
    LAUNCH_REASON_KEY = 'ohos.extra.param.key.form_launch_reason',
    PARAM_FORM_CUSTOMIZE_KEY = 'ohos.extra.param.key.form_customize',
    FORM_LOCATION_KEY = 'ohos.extra.param.key.form_location',
    FORM_RENDERING_MODE_KEY = 'ohos.extra.param.key.form_rendering_mode',
    HOST_BG_INVERSE_COLOR_KEY = 'ohos.extra.param.key.host_bg_inverse_color',
    FORM_PERMISSION_NAME_KEY = 'ohos.extra.param.key.permission_name',
    FORM_PERMISSION_GRANTED_KEY = 'ohos.extra.param.key.permission_granted',
    ORIGINAL_FORM_KEY = 'ohos.extra.param.key.original_form_id',
  }

  export interface FormInfoFilter {
    bundleName?: string;
    moduleName?: string;
    supportedDimensions?: Array<int>;
    supportedShapes?: Array<int>;
  }

  enum FormDimension {
    Dimension_1_2 = 1,
    Dimension_2_2,
    Dimension_2_4,
    Dimension_4_4,
    Dimension_2_1,
    DIMENSION_1_1 = 6,
    DIMENSION_6_4 = 7,
    DIMENSION_2_3 = 8,
    DIMENSION_3_3 = 9
  }

  enum FormShape {
    RECT = 1,
    CIRCLE = 2
  }

  enum VisibilityType {
    UNKNOWN = 0,
    FORM_VISIBLE = 1,
    FORM_INVISIBLE = 2
  }

  enum LaunchReason {
    FORM_DEFAULT = 1,
    FORM_SHARE = 2,
    FORM_SIZE_CHANGE = 3
  }

  export interface PublishFormResult {
    code: PublishFormErrorCode;
    message: string;
  }

  enum PublishFormErrorCode {
    SUCCESS = 0,
    NO_SPACE = 1,
    PARAM_ERROR = 2,
    INTERNAL_ERROR = 3
  }

  export interface FormProviderFilter {
    bundleName: string;
    formName?: string;
    moduleName?: string;
    abilityName?: string;
    isUnusedIncluded?: boolean;
  }

  interface RunningFormInfo {
    readonly formId: string;
    readonly bundleName: string;
    readonly hostBundleName: string;
    readonly formLocation: FormLocation;
    readonly visibilityType: VisibilityType;
    readonly moduleName: string;
    readonly abilityName: string;
    readonly formName: string;
    readonly dimension: int;
    readonly formUsageState: FormUsageState;
    readonly formDescription: string;
    readonly extraData?: Record<string, Object>;
  }

  class RunningFormInfoInner implements RunningFormInfo {
    formId: string;
    bundleName: string;
    hostBundleName: string;
    formLocation: FormLocation;
    visibilityType: VisibilityType;
    moduleName: string;
    abilityName: string;
    formName: string;
    dimension: int;
    formUsageState: FormUsageState;
    formDescription: string;
    extraData?: Record<string, Object>;
  }

  enum FormUsageState {
    USED = 0,
    UNUSED = 1
  }

  enum FormLocation {
    OTHER = -1,
    DESKTOP = 0,
    FORM_CENTER = 1,
    FORM_MANAGER = 2,
    NEGATIVE_SCREEN = 3,
    FORM_CENTER_NEGATIVE_SCREEN = 4,
    FORM_MANAGER_NEGATIVE_SCREEN = 5,
    SCREEN_LOCK = 6,
    AI_SUGGESTION = 7,
    STANDBY = 8,
  }

  export class formInfoInner implements FormInfo {
    public bundleName: string = '';
    public moduleName: string = '';
    public abilityName: string = '';
    public name: string = '';
    public displayName: string = '';
    public displayNameId: int = 0;
    public description: string = '';
    public descriptionId: int = 0;
    public type: FormType = FormType.JS;
    public jsComponentName: string = '';
    public isDefault: boolean = false;
    public updateEnabled: boolean = false;
    public formVisibleNotify: boolean = false;
    public scheduledUpdateTime: string = '';
    public formConfigAbility: string = '';
    public updateDuration: int = 0;
    public defaultDimension: int = 0;
    public supportDimensions: Array<int> = {};
    public customizeData: Record<string, string> = {};
    public isDynamic: boolean = false;
    public transparencyEnabled: boolean = false;
    public supportedShapes: Array<int> = {};
    public previewImages?: Array<int> = {};
    public enableBlurBackground?: boolean = false;
    public renderingMode?: RenderingMode = RenderingMode.AUTO_COLOR;
    public funInteractionParams?: FunInteractionParams = { targetBundleName: "", subBundleName: "" };
    public sceneAnimationParams?: SceneAnimationParams = { abilityName: "" };
    public resizable?: boolean = false;
    public groupId?: string = '';
    public isStandbySupported?: boolean = true;
    public isStandbyAdapted?: boolean = false;
    public isPrivacySensitive?: boolean = false;
  }

  export class runningFormInfoInner implements RunningFormInfo {
    public formId: string = '';
    public bundleName: string = '';
    public hostBundleName: string = '';
    public formLocation: FormLocation = FormLocation.OTHER;
    public visibilityType: VisibilityType = VisibilityType.UNKNOWN;
    public moduleName: string = '';
    public abilityName: string = '';
    public formName: string = '';
    public dimension: int = 0;
    public formUsageState: FormUsageState = FormUsageState.USED;
    public formDescription: string = '';
    public extraData?: Record<string, Object> = {};
  }
  
  export class FormStateInfoInner implements FormStateInfo {
    formState: FormState;
    want: Want;
  }

  interface FunInteractionParams {
    abilityName?: string;
    targetBundleName: string;
    subBundleName: string;
    keepStateDuration?: int;
  }

  class FunInteractionParamsInner implements FunInteractionParams {
    abilityName?: string;
    targetBundleName: string;
    subBundleName: string;
    keepStateDuration?: int;
  }

  interface OverflowRequest {
    formId: string;
    isOverflow: boolean;
    overflowInfo?: OverflowInfo;
  }

  class OverflowRequestInner implements OverflowRequest {
    formId: string;
    isOverflow: boolean;
    overflowInfo?: OverflowInfo;
  }

  export interface Rect {
    left: double;
    top: double;
    width: double;
    height: double;
  }

  class RectInner implements Rect {
    left: double;
    top: double;
    width: double;
    height: double;
  }

  export interface OverflowInfo {
    area: Rect;
    duration: int;
    useDefaultAnimation?: boolean;
  }
  
  class OverflowInfoInner implements OverflowInfo {
    area: Rect;
    duration: int;
    useDefaultAnimation?: boolean;
  }

  interface ChangeSceneAnimationStateRequest {
    formId: string;
    state: int;
  }

  class ChangeSceneAnimationStateRequestInner implements ChangeSceneAnimationStateRequest {
    formId: string;
    state: int;
  }

  interface SceneAnimationParams {
    abilityName: string;
    disabledDesktopBehaviors?: string;
  }

  class SceneAnimationParamsInner implements SceneAnimationParams {
    abilityName: string;
    disabledDesktopBehaviors?: string;
  }

  type GetFormRectInfoCallback = (formId: string) => Promise<Rect>;

  interface PublishFormCrossBundleInfo {
    callerBundleName: string;
    targetBundleName: string;
    targetTemplateFormDetailId: string;
  }

  class PublishFormCrossBundleInfoInner implements PublishFormCrossBundleInfo {
    callerBundleName: string;
    targetBundleName: string;
    targetTemplateFormDetailId: string;
  }

  type PublishFormCrossBundleControlCallback = (info: PublishFormCrossBundleInfo) => boolean;
}
