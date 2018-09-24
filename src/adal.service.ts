import { Injectable } from '@angular/core';

import { Observable, bindCallback, timer } from 'rxjs';
import { map } from 'rxjs/operators';

export function deepCopy<T extends any>(value: T): T {
    if (Array.isArray(value)) {
        return value.map((o: T) => deepCopy(o));
    } else if (value && typeof value === 'object') {
        if (value['toJSON']) {
            return JSON.parse((value['toJSON'] as () => string)());
        }

        const copy = new (Object.getPrototypeOf(value).constructor)();
        for (const key of Object.getOwnPropertyNames(value)) {
            copy[key] = deepCopy(value[key]);
        }

        return copy;
    } else {
        return value;
    }
}

/**
 * Returns true if browser supports localStorage, false otherwise.
 */
export function localStorageSupported(): boolean {
    const test = 'adalStorageTest';
    try {
        window.localStorage.setItem(test, test);
        window.localStorage.removeItem(test);

        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Returns true if browser supports sessionStorage, false otherwise.
 */
export function sessionStorageSupported(): boolean {
    const test = 'adalStorageTest';
    try {
        window.sessionStorage.setItem(test, test);
        window.sessionStorage.removeItem(test);

        return true;
    } catch (e) {
        return false;
    }
}

export interface AuthenticationContextStatic {
    new (config: Config): AuthenticationContext;
}

export interface WindowWithAdalContext extends Window {
    _adalInstance?: AuthenticationContext;
    AuthenticationContext: AuthenticationContextStatic;
    callBackMappedToRenewStates: any;
}

/**
 * @TODO Remove
 * @deprecated
 */
declare var Logging: {
    log: (message: string) => void;
    level: LOGGING_LEVEL;
};

export interface JwtPayload {
    aud?: string;
    upn?: string;
    email?: string;
}

export interface RequestInfoParameters {
    id_token?: string;
    access_token?: string;
    session_state?: string;
    error?: string;
    error_description?: string;
    expires_in?: string;
    state?: string;
}

/**
 * Request info object created from the response received from AAD.
 */
export interface RequestInfo {
    /**
     * Object comprising of fields such as id_token/error, session_state, state, e.t.c.
     */
    parameters: RequestInfoParameters;
    /**
     * Either LOGIN, RENEW_TOKEN or UNKNOWN.
     */
    requestType: REQUEST_TYPE;
    /**
     * True if state is valid, false otherwise.
     */
    stateMatch: boolean;
    /**
     * Unique guid used to match the response with the request.
     */
    stateResponse: string;
    /**
     * True if requestType contains id_token, access_token or error, false otherwise.
     */
    valid: boolean;
}

export interface UserProfile {
    sid?: string;
    upn?: string;
    nonce?: string; // @TODO Check if optional
    exp?: string; // @TODO Check if optional
}

/**
 * User information
 */
export interface User {
    /**
     * Username assigned from upn or email.
     */
    userName: string;
    /**
     * Properties parsed from idToken.
     */
    profile: UserProfile;
    token: string | null;
    error: string | null;
    loginCached: boolean;
}

export interface AdalUser extends User {
    authenticated: boolean;
}

export enum TOKEN_TYPE {
    ACCESS_TOKEN = 'access_token',
    ID_TOKEN = 'id_token',
}

export interface TokenCallback {
    /**
     * @param {string} [errorDescription] - Error description returned from AAD if token request fails.
     * @param {string} [token] - Token returned from AAD if token request is successful.
     * @param {string} [error] - Error message returned from AAD if token request fails.
     * @param {TOKEN_TYPE} [tokenType] - @TODO Add parameter description for tokenType
     */
    (errorDescription?: string | null, token?: string | null, error?: string | null, tokenType?: TOKEN_TYPE): void;
}

export interface UserCallback {
    /**
     * @param {string} [error] - Error message if user info is not available.
     * @param {User} [user] - User object retrieved from the cache.
     */
    (error?: string, user?: User | null): void;
}

export class AdalUtility {
    /**
     * Generates RFC4122 version 4 guid (128 bits)
     */
    public static guid(): string {
        // tslint:disable no-bitwise comment-format number-literal-format

        // RFC4122: The version 4 UUID is meant for generating UUIDs from truly-random or
        // pseudo-random numbers.
        // The algorithm is as follows:
        //     Set the two most significant bits (bits 6 and 7) of the
        //        clock_seq_hi_and_reserved to zero and one, respectively.
        //     Set the four most significant bits (bits 12 through 15) of the
        //        time_hi_and_version field to the 4-bit version number from
        //        Section 4.1.3. Version4
        //     Set all the other bits to randomly (or pseudo-randomly) chosen
        //     values.
        // UUID                   = time-low "-" time-mid "-"time-high-and-version "-"clock-seq-reserved and low(2hexOctet)"-" node
        // time-low               = 4hexOctet
        // time-mid               = 2hexOctet
        // time-high-and-version  = 2hexOctet
        // clock-seq-and-reserved = hexOctet:
        // clock-seq-low          = hexOctet
        // node                   = 6hexOctet
        // Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        // y could be 1000, 1001, 1010, 1011 since most significant two bits needs to be 10
        // y values are 8, 9, A, B
        const cryptoObj = window.crypto || (window as any).msCrypto; // for IE 11
        if (cryptoObj && cryptoObj.getRandomValues) {
            const buffer = new Uint8Array(16);
            cryptoObj.getRandomValues(buffer);

            //buffer[6] and buffer[7] represents the time_hi_and_version field. We will set the four most significant bits (4 through 7) of buffer[6] to represent decimal number 4 (UUID version number).
            buffer[6] |= 0x40; //buffer[6] | 01000000 will set the 6 bit to 1.
            buffer[6] &= 0x4f; //buffer[6] & 01001111 will set the 4, 5, and 7 bit to 0 such that bits 4-7 == 0100 = "4".
            //buffer[8] represents the clock_seq_hi_and_reserved field. We will set the two most significant bits (6 and 7) of the clock_seq_hi_and_reserved to zero and one, respectively.
            buffer[8] |= 0x80; //buffer[8] | 10000000 will set the 7 bit to 1.
            buffer[8] &= 0xbf; //buffer[8] & 10111111 will set the 6 bit to 0.

            const decimalToHex = AdalUtility.decimalToHex;

            return decimalToHex(buffer[0]) + decimalToHex(buffer[1]) + decimalToHex(buffer[2]) + decimalToHex(buffer[3]) + '-' + decimalToHex(buffer[4]) + decimalToHex(buffer[5]) + '-' + decimalToHex(buffer[6]) + decimalToHex(buffer[7]) + '-' +
                decimalToHex(buffer[8]) + decimalToHex(buffer[9]) + '-' + decimalToHex(buffer[10]) + decimalToHex(buffer[11]) + decimalToHex(buffer[12]) + decimalToHex(buffer[13]) + decimalToHex(buffer[14]) + decimalToHex(buffer[15]);

        } else {
            const guidHolder = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
            const hex = '0123456789abcdef';
            let r = 0;
            let guidResponse = '';
            for (let i = 0; i < 36; i++) {
                if (guidHolder[i] !== '-' && guidHolder[i] !== '4') {
                    // each x and y needs to be random
                    r = Math.random() * 16 | 0;
                }
                if (guidHolder[i] === 'x') {
                    guidResponse += hex[r];
                } else if (guidHolder[i] === 'y') {
                    // clock-seq-and-reserved first hex is filtered and remaining hex values are random
                    r &= 0x3; // bit and with 0011 to set pos 2 to zero ?0??
                    r |= 0x8; // set pos 3 to 1 as 1???
                    guidResponse += hex[r];
                } else {
                    guidResponse += guidHolder[i];
                }
            }

            return guidResponse;
        }
        // tslint:enable
    }

    /**
     * Converts decimal value to hex equivalent
     */
    public static decimalToHex(value: number): string {
        let hex = value.toString(16);

        while (hex.length < 2) {
            hex = '0' + hex;
        }

        return hex;
    }

    /**
     * Returns the decoded JSON web token payload.
     *
     * @param {string} jwt
     * @throws Will throw an error if the token can not be decoded.
     */
    public static getPayloadFromToken(jwt: string): JwtPayload | null {
        const decodedToken = AdalUtility.decodeJwt(jwt);
        if (!decodedToken) {
            return null;
        }

        const base64Decoded = AdalUtility.base64DecodeStringUrlSafe(decodedToken.JWSPayload);
        if (!base64Decoded) {
            throw new Error('The token could not be base64 url safe decoded.');
        }

        try {
            return JSON.parse(base64Decoded);
        } catch (error) {
            throw new Error('The token could not be JSON decoded');
        }
    }

    /**
     * Decodes a JSON web token into an object with header, payload and signature fields.
     *
     * @param {string} [jwt]
     * @throws Will throw an error if the argument is not parsable.
     */
    public static decodeJwt(jwt?: string): { header: string, JWSPayload: string, JWSSig: string } | null {
        if (!jwt) {
            return null;
        }

        const idTokenPartsRegex = /^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/;

        const matches = idTokenPartsRegex.exec(jwt);
        if (!matches || matches.length < 4) {
            throw new Error('The given JSON web token is not parsable.');
        }

        return {
            header: matches[1],
            JWSPayload: matches[2],
            JWSSig: matches[3],
        };
    }

    /**
     * Decodes a string of data which has been encoded using base-64 encoding.
     *
     * @param {string} base64Token
     */
    public static base64DecodeStringUrlSafe(base64Token: string): string {
        return decodeURIComponent(
            escape(
                atob(
                    base64Token.replace(/-/g, '+')
                        .replace(/_/g, '/')
                )
            )
        );
    }
}

/**
 * Configuration options for Authentication Context.
 */
export interface Config {
    /**
     * Your target tenant.
     */
    tenant?: string;
    /**
     * Client ID assigned to your app by Azure Active Directory.
     */
    clientId: string;
    /**
     * Endpoint at which you expect to receive tokens.Defaults to `window.location.href`.
     */
    redirectUri?: string;
    /**
     * Azure Active Directory Instance.Defaults to `https://login.microsoftonline.com/`.
     */
    instance?: string;
    /**
     * Collection of {Endpoint-ResourceId} used for automatically attaching tokens in webApi calls.
     */
    endpoints?: {[key: string]: string};
    /**
     * Set this to true to enable login in a popup winodow instead of a full redirect.Defaults to `false`.
     */
    popUp?: boolean;
    /**
     * Set this to redirect the user to a custom login page.
     */
    localLoginUrl?: string;
    /**
     * User defined function of handling the navigation to Azure AD authorization endpoint in case of login. Defaults to 'null'.
     */
    displayCall?: (url: string) => void;
    /**
     * Redirects the user to postLogoutRedirectUri after logout. Defaults is 'redirectUri'.
     */
    postLogoutRedirectUri?: string;
    /**
     * Sets browser storage to either 'localStorage' or sessionStorage'. Defaults to 'sessionStorage'.
     */
    cacheLocation?: string;
    /**
     * Array of keywords or URI's. Adal will not attach a token to outgoing requests that have these keywords or uri. Defaults to 'null'.
     */
    anonymousEndpoints?: string[];
    /**
     * If the cached token is about to be expired in the expireOffsetSeconds (in seconds), Adal will renew the token instead of using the cached token. Defaults to 300 seconds.
     */
    expireOffsetSeconds?: number;
    /**
     *  Unique identifier used to map the request with the response. Defaults to RFC4122 version 4 guid (128 bits).
     */
    correlationId?: string;
    /**
     * The number of milliseconds of inactivity before a token renewal response from AAD should be considered timed out.
     */
    loadFrameTimeout?: number;

    // ==== NEW ==== (undefined in original config)
    /**
     * If unspecified, idToken is requested using clientId as resource.
     */
    loginResource?: string;
    /**
     * Whether to redirect the user to the login request url given in the login request response.
     * Defaults to `true`.
     */
    navigateToLoginRequestUrl?: boolean;
    /**
     * Extra query parameters to add to the authentication request
     */
    extraQueryParameter?: string;
    /**
     * Full url to ADAL logout page. Overrides derived logout url from instance and tenant.
     */
    logOutUri?: string;
    /**
     * Callback to be called with token or on error.
     */
    callback?: TokenCallback;

    slice?: string;
}

export interface InternalConfig extends Config {
    tenant?: string;
    clientId: string;
    redirectUri: string;
    instance?: string;
    endpoints?: {[key: string]: string};
    popUp?: boolean;
    localLoginUrl?: string;
    displayCall?: (url: string) => void;
    postLogoutRedirectUri: string;
    cacheLocation?: string;
    anonymousEndpoints: string[];
    expireOffsetSeconds?: number;
    correlationId?: string;
    loadFrameTimeout?: number;

    loginResource: string;
    navigateToLoginRequestUrl: boolean;
    extraQueryParameter?: string;
    logOutUri?: string;
    callback?: TokenCallback;
    slice?: string;
}

/**
 * Enum for request type
 * @enum {string}
 */
export enum REQUEST_TYPE {
    LOGIN = 'LOGIN',
    RENEW_TOKEN = 'RENEW_TOKEN',
    UNKNOWN = 'UNKNOWN',
}

/**
 * Enum for response type
 * @enum {string}
 */
export enum RESPONSE_TYPE {
    ID_TOKEN = 'id_token',
    ID_TOKEN_TOKEN = 'id_token token',
    TOKEN = 'token',
}

export enum LOGGING_LEVEL {
    ERROR = 0,
    WARNING = 1,
    INFO = 2,
    VERBOSE = 3,
}

/**
 * Enum for storage constants
 * @enum {string}
 */
export const CONSTANTS = {
    RESOURCE_DELIMETER: '|',
    CACHE_DELIMETER: '||',
    LOADFRAME_TIMEOUT: 6000,
    TOKEN_RENEW_STATUS_CANCELED: 'Canceled',
    TOKEN_RENEW_STATUS_COMPLETED: 'Completed',
    TOKEN_RENEW_STATUS_IN_PROGRESS: 'In Progress',
    LEVEL_STRING_MAP: {
        0: 'ERROR:',
        1: 'WARNING:',
        2: 'INFO:',
        3: 'VERBOSE:',
    },
    POPUP_WIDTH: 483,
    POPUP_HEIGHT: 600,
};

/**
 * Enum for storage constants
 * @enum {string}
 */
export const STORAGE_CONSTANTS = {
    TOKEN_KEYS: 'adal.token.keys',
    ACCESS_TOKEN_KEY: 'adal.access.token.key',
    EXPIRATION_KEY: 'adal.expiration.key',
    STATE_LOGIN: 'adal.state.login',
    STATE_RENEW: 'adal.state.renew',
    NONCE_IDTOKEN: 'adal.nonce.idtoken',
    SESSION_STATE: 'adal.session.state',
    USERNAME: 'adal.username',
    IDTOKEN: 'adal.idtoken',
    ERROR: 'adal.error',
    ERROR_DESCRIPTION: 'adal.error.description',
    LOGIN_REQUEST: 'adal.login.request',
    LOGIN_ERROR: 'adal.login.error',
    RENEW_STATUS: 'adal.token.renew.status',
    ANGULAR_LOGIN_REQUEST: 'adal.angular.login.request',
};

export class AuthenticationContext {
    /**
     * The library version.
     */
    public static readonly VERSION: string = '1.0.17';

    public RESPONSE_TYPE: typeof RESPONSE_TYPE = RESPONSE_TYPE;
    public CONSTANTS: typeof CONSTANTS = deepCopy(CONSTANTS);
    public STORAGE_CONSTANTS: typeof STORAGE_CONSTANTS = deepCopy(STORAGE_CONSTANTS);

    public readonly supportsLocalStorage: boolean = localStorageSupported();
    public readonly supportsSessionStorage: boolean = sessionStorageSupported();

    // public
    public instance: string = 'https://login.microsoftonline.com/';
    public config: InternalConfig;
    public callback: TokenCallback;
    public popUp: boolean = false;

    // @TODO Remove eventually
    public isAngular: boolean = true;

    public get state(): string {
        return this._state;
    }

    // private
    private _user: User | null = null;
    private _activeRenewals: Map<string, string> = new Map();
    private _loginInProgress: boolean = false;
    private _acquireTokenInProgress: boolean = false;
    private _renewStates: string[] = [];
    private _callBackMappedToRenewStates: Map<string, TokenCallback> = new Map();
    private _callBacksMappedToRenewStates: Map<string, TokenCallback[]> = new Map();
    private _openedWindows: Window[] = [];
    private _requestType: REQUEST_TYPE = REQUEST_TYPE.LOGIN;

    private _state: string = '';

    constructor(config: Config) {
        (window as WindowWithAdalContext)._adalInstance = this;

        if (!config) {
            throw new Error('You must set config, when calling init.');
        }

        // validate before constructor assignments
        if (config.displayCall && typeof config.displayCall !== 'function') {
            throw new Error('displayCall is not a function');
        }

        if (!config.clientId) {
            throw new Error('clientId is required');
        }

        const configClone = deepCopy(config) as InternalConfig;

        this.callback = () => {}; // tslint:disable-line no-empty

        if (config.navigateToLoginRequestUrl === undefined) {
            config.navigateToLoginRequestUrl = true;
        }

        if (config.popUp) {
            this.popUp = true;
        }

        if (config.callback && typeof config.callback === 'function') {
            this.callback = config.callback;
        }

        if (config.instance) {
            this.instance = config.instance;
        }

        // App can request idtoken for itself using clientid as resource
        if (!config.loginResource) {
            configClone.loginResource = config.clientId;
        }

        // redirect and logout_redirect are set to current location by default
        if (!config.redirectUri) {
            // strip off query parameters or hashes from the redirect uri as AAD does not allow those.
            configClone.redirectUri = window.location.href
                .split('?')[0]
                .split('#')[0];
        }

        if (!config.postLogoutRedirectUri) {
            // strip off query parameters or hashes from the post logout redirect uri as AAD does not allow those.
            configClone.postLogoutRedirectUri = window.location.href
                .split('?')[0]
                .split('#')[0];
        }

        if (!config.anonymousEndpoints) {
            configClone.anonymousEndpoints = [];
        }

        if (config.loadFrameTimeout) {
            this.CONSTANTS.LOADFRAME_TIMEOUT = config.loadFrameTimeout;
        }

        this.config = configClone;
    }

    /**
     * Initiates the login process by redirecting the user to Azure AD authorization endpoint.
     */
    public login(): void {
        if (this._loginInProgress) {
            this.info('Login in progress');

            return;
        }

        this._loginInProgress = true;

        // Token is not present and user needs to login
        const expectedState = AdalUtility.guid();
        this._state = expectedState;
        const idTokenNonce = AdalUtility.guid();
        let loginStartPage = this.getItem(this.STORAGE_CONSTANTS.ANGULAR_LOGIN_REQUEST);

        if (!loginStartPage || loginStartPage === '') {
            loginStartPage = window.location.href;
        } else {
            this._saveItem(this.STORAGE_CONSTANTS.ANGULAR_LOGIN_REQUEST, '');
        }

        this.verbose('Expected state: ' + expectedState + ' startPage:' + loginStartPage);
        this._saveItem(this.STORAGE_CONSTANTS.LOGIN_REQUEST, loginStartPage);
        this._saveItem(this.STORAGE_CONSTANTS.LOGIN_ERROR, '');
        this._saveItem(this.STORAGE_CONSTANTS.STATE_LOGIN, expectedState, true);
        this._saveItem(this.STORAGE_CONSTANTS.NONCE_IDTOKEN, idTokenNonce, true);
        this._saveItem(this.STORAGE_CONSTANTS.ERROR, '');
        this._saveItem(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, '');
        const urlNavigate = this._getNavigateUrl(RESPONSE_TYPE.ID_TOKEN) + '&nonce=' + encodeURIComponent(idTokenNonce);

        if (this.config.displayCall) {
            // User defined way of handling the navigation
            this.config.displayCall(urlNavigate);

        } else if (this.popUp) {
            this._saveItem(this.STORAGE_CONSTANTS.STATE_LOGIN, ''); // so requestInfo does not match redirect case
            this._renewStates.push(expectedState);
            this.registerCallback(expectedState, this.config.clientId, this.callback);
            this._loginPopup(urlNavigate);

        } else {
            this.promptUser(urlNavigate);
        }
    }

    /**
     * Configures popup window for login.
     */
    protected _openPopup(urlNavigate: string, title: string, popUpWidth: number, popUpHeight: number): Window | null {
        try {
            /**
             * adding winLeft and winTop to account for dual monitor
             * using screenLeft and screenTop for IE8 and earlier
             */
            const winLeft = window.screenLeft ? window.screenLeft : window.screenX;
            const winTop = window.screenTop ? window.screenTop : window.screenY;
            /**
             * window.innerWidth displays browser window's height and width excluding toolbars
             * using document.documentElement.clientWidth for IE8 and earlier
             */
            const width = window.innerWidth || document.documentElement.clientWidth || document.body.clientWidth;
            const height = window.innerHeight || document.documentElement.clientHeight || document.body.clientHeight;
            const left = ((width / 2) - (popUpWidth / 2)) + winLeft;
            const top = ((height / 2) - (popUpHeight / 2)) + winTop;

            const popupWindow = window.open(urlNavigate, title, 'width=' + popUpWidth + ', height=' + popUpHeight + ', top=' + top + ', left=' + left);

            if (popupWindow && popupWindow.focus) {
                popupWindow.focus();
            }

            return popupWindow;
        } catch (e) {
            this.warn('Error opening popup, ' + e.message);
            this._loginInProgress = false;
            this._acquireTokenInProgress = false;

            return null;
        }
    }

    protected _handlePopupError(loginCallback?: TokenCallback | null, resource?: string, error?: string | null, errorDesc?: string | null, loginError?: string | null): void {
        this.warn(errorDesc!);
        this._saveItem(this.STORAGE_CONSTANTS.ERROR, error);
        this._saveItem(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, errorDesc);
        this._saveItem(this.STORAGE_CONSTANTS.LOGIN_ERROR, loginError);

        if (resource) {
            this._activeRenewals.delete(resource);
        }

        this._loginInProgress = false;
        this._acquireTokenInProgress = false;

        if (loginCallback) {
            loginCallback(errorDesc, null, error);
        }
    }

    /**
     * After authorization, the user will be sent to your specified redirect_uri with the user's bearer token
     * attached to the URI fragment as an id_token field. It closes popup window after redirection.
     */
    protected _loginPopup(urlNavigate: string, resource?: string, callback?: TokenCallback): void {
        const popupWindow = this._openPopup(urlNavigate, 'login', this.CONSTANTS.POPUP_WIDTH, this.CONSTANTS.POPUP_HEIGHT);
        const loginCallback = callback || this.callback;

        if (popupWindow == null) {
            const error = 'Error opening popup';
            const errorDesc = 'Popup Window is null. This can happen if you are using IE';
            this._handlePopupError(loginCallback, resource, error, errorDesc, errorDesc);

            return;
        }

        this._openedWindows.push(popupWindow);

        const registeredRedirectUri = (
            this.config.redirectUri.indexOf('#') !== -1
                ? this.config.redirectUri.split('#')[0]
                : this.config.redirectUri
        );

        const pollTimer = window.setInterval(() => {
            if (!popupWindow || popupWindow.closed || null == popupWindow.closed) {
                const error = 'Popup Window closed';
                const errorDesc = 'Popup Window closed by UI action/ Popup Window handle destroyed due to cross zone navigation in IE/Edge';

                if (this.isAngular) {
                    this._broadcast('adal:popUpClosed', errorDesc + this.CONSTANTS.RESOURCE_DELIMETER + error);
                }

                this._handlePopupError(loginCallback, resource, error, errorDesc, errorDesc);
                window.clearInterval(pollTimer);

                return;
            }

            try {
                const popUpWindowLocation = popupWindow.location;
                const urisEqual = (encodeURI(popUpWindowLocation.href)
                    .indexOf(encodeURI(registeredRedirectUri)) !== -1);
                if (urisEqual) {
                    if (this.isAngular) {
                        this._broadcast('adal:popUpHashChanged', popUpWindowLocation.hash);
                    } else {
                        this.handleWindowCallback(popUpWindowLocation.hash);
                    }

                    window.clearInterval(pollTimer);
                    this._loginInProgress = false;
                    this._acquireTokenInProgress = false;
                    this.info('Closing popup window');
                    this._openedWindows = [];
                    popupWindow.close();

                    return;
                }
            } catch (e) {} // tslint:disable-line no-empty
        }, 1);
    }

    protected _broadcast(event: string, data: string): void {
        // Custom Event is not supported in IE, below IIFE will polyfill the CustomEvent() constructor functionality in Internet Explorer 9 and higher
        (() => {

            if (typeof (window as any).CustomEvent === 'function') {
                return false;
            }

            function CustomEvent(eventName: string, params: any) {
                params = params || { bubbles: false, cancelable: false, detail: undefined };
                const evt = document.createEvent('CustomEvent');
                evt.initCustomEvent(eventName, params.bubbles, params.cancelable, params.detail);

                return evt;
            }

            CustomEvent.prototype = (window as any).Event.prototype;
            (window as any).CustomEvent = CustomEvent;
        })();

        const customEvent = new CustomEvent(event, { detail: data });
        window.dispatchEvent(customEvent);
    }

    /**
     * Indicates whether login is in progress.
     */
    public loginInProgress(): boolean {
        return this._loginInProgress;
    }

    /**
     * Checks for the resource in the cache. By default, cache location is Session Storage
     *
     * @returns {boolean} - 'true' if login is in progress, else returns 'false'.
     */
    protected _hasResource(key: string): boolean {
        const keys = this.getItem(this.STORAGE_CONSTANTS.TOKEN_KEYS);

        return !!keys
            && (keys.indexOf(key + this.CONSTANTS.RESOURCE_DELIMETER) !== -1);
    }

    /**
     * Gets token for the specified resource from the cache.
     *
     * @param {string} resource  -  A URI that identifies the resource for which the token is valid.
     * @returns {string} The token if it exists and is not expired, otherwise null.
     */
    public getCachedToken(resource: string): string | null {
        if (!this._hasResource(resource)) {
            return null;
        }

        const token = this.getItem(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + resource);
        const expiration = this.getItem(this.STORAGE_CONSTANTS.EXPIRATION_KEY + resource);
        const expiry = (expiration ? parseInt(expiration, 10) : null);

        // If expiration is within offset, it will force renew
        const offset = this.config.expireOffsetSeconds || 300;

        if (expiry && (expiry > this._now() + offset)) {
            return token;
        } else {
            this._saveItem(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + resource, '');
            this._saveItem(this.STORAGE_CONSTANTS.EXPIRATION_KEY + resource, 0);

            return null;
        }
    }

    /**
     * If user object exists, returns it. Else creates a new user object by decoding id_token from the cache.
     *
     * @returns {User} User object
     */
    public getCachedUser(): User | null {
        if (this._user) {
            return this._user;
        }

        let user = null;

        const idToken = this.getItem(this.STORAGE_CONSTANTS.IDTOKEN);
        if (idToken) {
            user = this._createUserFromIdToken(idToken);
        }
        this._user = user;

        return user;
    }

    /**
     * Adds the passed callback to the array of callbacks for the specified resource and puts the array on the window object.
     *
     * @param {string} resource  -  A URI that identifies the resource for which the token is requested.
     * @param {string} expectedState  -  A unique identifier (guid).
     * @param {TokenCallback} callback  -  The callback provided by the caller. It will be called with token or error.
     */
    public registerCallback(expectedState: string, resource: string, callback: TokenCallback): void {
        this._activeRenewals.set(resource, expectedState);

        let callbacks = this._callBacksMappedToRenewStates.get(expectedState);
        if (!callbacks) {
            callbacks = [];
            this._callBacksMappedToRenewStates.set(expectedState, callbacks);
        }
        callbacks.push(callback);

        if (!this._callBackMappedToRenewStates.has(expectedState)) {
            this._callBackMappedToRenewStates.set(expectedState, (errorDescription?: string | null, token?: string | null, error?: string | null, tokenType?: TOKEN_TYPE) => {
                this._activeRenewals.delete(resource);

                const renewStateCallbacks = this._callBacksMappedToRenewStates.get(expectedState) || [];
                for (let i = 0; i < renewStateCallbacks.length; i += 1) {
                    try {
                        renewStateCallbacks[i](errorDescription, token, error, tokenType);
                    } catch (error) {
                        this.warn(error);
                    }
                }

                this._callBacksMappedToRenewStates.delete(expectedState);
                this._callBackMappedToRenewStates.delete(expectedState);
            });
        }
    }

    /**
     * Acquires access token with hidden iframe
     */
    protected _renewToken(resource: string, callback: TokenCallback, responseType?: RESPONSE_TYPE): void {
        // use iframe to try to renew token
        // use given resource to create new authz url
        this.info('renewToken is called for resource:' + resource);
        const frameHandle = this._addAdalFrame('adalRenewFrame' + resource);
        const expectedState = AdalUtility.guid() + '|' + resource;

        this._state = expectedState;
        // renew happens in iframe, so it keeps javascript context
        this._renewStates.push(expectedState);
        this.verbose('Renew token Expected state: ' + expectedState);

        // remove the existing prompt=... query parameter and add prompt=none
        responseType = responseType || RESPONSE_TYPE.TOKEN;
        let urlNavigate = this._urlRemoveQueryStringParameter(this._getNavigateUrl(responseType, resource), 'prompt');

        if (responseType === this.RESPONSE_TYPE.ID_TOKEN_TOKEN) {
            const idTokenNonce = AdalUtility.guid();
            this._saveItem(this.STORAGE_CONSTANTS.NONCE_IDTOKEN, idTokenNonce, true);
            urlNavigate += '&nonce=' + encodeURIComponent(idTokenNonce);
        }

        urlNavigate = urlNavigate + '&prompt=none';
        urlNavigate = this._addHintParameters(urlNavigate);

        this.registerCallback(expectedState, resource, callback);
        this.verbosePii('Navigate to:' + urlNavigate);
        frameHandle.src = 'about:blank';

        this._loadFrameTimeout(urlNavigate, 'adalRenewFrame' + resource, resource);
    }

    /**
     * Renews idtoken for app's own backend when resource is clientId and calls the callback with token/error
     */
    protected _renewIdToken(callback: TokenCallback, responseType?: RESPONSE_TYPE): void {
        // use iframe to try to renew token
        this.info('renewIdToken is called');
        const frameHandle = this._addAdalFrame('adalIdTokenFrame');
        const expectedState = AdalUtility.guid() + '|' + this.config.clientId;

        const idTokenNonce = AdalUtility.guid();
        this._saveItem(this.STORAGE_CONSTANTS.NONCE_IDTOKEN, idTokenNonce, true);

        this._state = expectedState;
        // renew happens in iframe, so it keeps javascript context
        this._renewStates.push(expectedState);
        this.verbose('Renew Idtoken Expected state: ' + expectedState);

        // remove the existing prompt=... query parameter and add prompt=none
        const resource = (responseType == null ? undefined : this.config.clientId);
        responseType = responseType || RESPONSE_TYPE.ID_TOKEN;

        let urlNavigate = this._urlRemoveQueryStringParameter(this._getNavigateUrl(responseType, resource), 'prompt');
        urlNavigate = urlNavigate + '&prompt=none';
        urlNavigate = this._addHintParameters(urlNavigate);
        urlNavigate += '&nonce=' + encodeURIComponent(idTokenNonce);

        this.registerCallback(expectedState, this.config.clientId, callback);
        this.verbosePii('Navigate to:' + urlNavigate);
        frameHandle.src = 'about:blank';

        this._loadFrameTimeout(urlNavigate, 'adalIdTokenFrame', this.config.clientId);
    }

    /**
     * Checks if the authorization endpoint URL contains query string parameters
     */
    protected _urlContainsQueryStringParameter(name: string, url: string): boolean {
        // regex to detect pattern of a ? or & followed by the name parameter and an equals character
        const regex = new RegExp('[\\?&]' + name + '=');

        return regex.test(url);
    }

    /**
     * Removes the query string parameter from the authorization endpoint URL if it exists
     */
    protected _urlRemoveQueryStringParameter(url: string, name: string): string {
        // we remove &name=value, name=value& and name=value
        // &name=value
        let regex = new RegExp('(\\&' + name + '=)[^\&]+');
        url = url.replace(regex, '');
        // name=value&
        regex = new RegExp('(' + name + '=)[^\&]+&');
        url = url.replace(regex, '');
        // name=value
        regex = new RegExp('(' + name + '=)[^\&]+');
        url = url.replace(regex, '');

        return url;
    }

    /**
     * Calling _loadFrame but with a timeout to signal failure in loadframeStatus. Callbacks are left
     * registered when network errors occur and subsequent token requests for same resource are registered to the pending request
     */
    protected _loadFrameTimeout(urlNavigation: string, frameName: string, resource: string): void {
        // Set iframe session to pending
        this.verbose('Set loading state to pending for: ' + resource);
        this._saveItem(this.STORAGE_CONSTANTS.RENEW_STATUS + resource, this.CONSTANTS.TOKEN_RENEW_STATUS_IN_PROGRESS);
        this._loadFrame(urlNavigation, frameName);

        setTimeout(() => {
            if (this.getItem(this.STORAGE_CONSTANTS.RENEW_STATUS + resource) === this.CONSTANTS.TOKEN_RENEW_STATUS_IN_PROGRESS) {
                // fail the iframe session if it's in pending state
                this.verbose('Loading frame has timed out after: ' + (this.CONSTANTS.LOADFRAME_TIMEOUT / 1000) + ' seconds for resource ' + resource);
                const expectedState = this._activeRenewals.get(resource);

                if (expectedState) {
                    const callback = this._callBackMappedToRenewStates.get(expectedState);
                    if (callback) {
                        callback('Token renewal operation failed due to timeout', null, 'Token Renewal Failed');
                    }
                }

                this._saveItem(this.STORAGE_CONSTANTS.RENEW_STATUS + resource, this.CONSTANTS.TOKEN_RENEW_STATUS_CANCELED);
            }
        }, this.CONSTANTS.LOADFRAME_TIMEOUT);
    }

    /**
     * Loads iframe with authorization endpoint URL
     */
    protected _loadFrame(urlNavigate: string, frameName: string): void {
        // This trick overcomes iframe navigation in IE
        // IE does not load the page consistently in iframe
        this.info('LoadFrame: ' + frameName);
        const frameCheck = frameName;

        setTimeout(() => {
            const frameHandle = this._addAdalFrame(frameCheck);

            if (frameHandle.src === '' || frameHandle.src === 'about:blank') {
                frameHandle.src = urlNavigate;
                this._loadFrame(urlNavigate, frameCheck);
            }

        }, 500);
    }

    /**
     * Acquires token from the cache if it is not expired. Otherwise sends request to AAD to obtain a new token.
     *
     * @param {string} resource  -  ResourceUri identifying the target resource
     * @param {TokenCallback} callback  -  The callback provided by the caller. It will be called with token or error.
     */
    public acquireToken(resource: string, callback: TokenCallback): void {
        if (!resource) {
            this.warn('resource is required');
            callback('resource is required', null, 'resource is required');

            return;
        }

        const token = this.getCachedToken(resource);

        if (token) {
            this.info('Token is already in cache for resource:' + resource);
            callback(null, token, null);

            return;
        }

        if (!this._user && !(this.config.extraQueryParameter && this.config.extraQueryParameter.indexOf('login_hint') !== -1)) {
            this.warn('User login is required');
            callback('User login is required', null, 'login required');

            return;
        }

        // renew attempt with iframe
        // Already renewing for this resource, callback when we get the token.
        const activeRenewal = this._activeRenewals.get(resource);
        if (activeRenewal) {
            // Active renewals contains the state for each renewal.
            this.registerCallback(activeRenewal, resource, callback);

        } else {
            this._requestType = REQUEST_TYPE.RENEW_TOKEN;
            if (resource === this.config.clientId) {
                // App uses idtoken to send to api endpoints
                // Default resource is tracked as clientid to store this token
                if (this._user) {
                    this.verbose('renewing idtoken');
                    this._renewIdToken(callback);

                } else {
                    this.verbose('renewing idtoken and access_token');
                    this._renewIdToken(callback, this.RESPONSE_TYPE.ID_TOKEN_TOKEN);
                }

            } else {
                if (this._user) {
                    this.verbose('renewing access_token');
                    this._renewToken(resource, callback);

                } else {
                    this.verbose('renewing idtoken and access_token');
                    this._renewToken(resource, callback, this.RESPONSE_TYPE.ID_TOKEN_TOKEN);
                }
            }
        }
    }

    /**
     * Acquires token (interactive flow using a popUp window) by sending request to AAD to obtain a new token.
     *
     * @param {string} resource - ResourceUri identifying the target resource
     * @param {string} extraQueryParameters - Extra query parameters to add to the authentication request
     * @param {string} claims - @TODO Add parameter description for claims
     * @param {TokenCallback} callback - The callback provided by the caller. It will be called with token or error.
     */
    public acquireTokenPopup(resource: string, extraQueryParameters: string, claims: string, callback: TokenCallback): void {
        if (!resource) {
            this.warn('resource is required');
            callback('resource is required', null, 'resource is required');

            return;
        }

        if (!this._user) {
            this.warn('User login is required');
            callback('User login is required', null, 'login required');

            return;
        }

        if (this._acquireTokenInProgress) {
            this.warn('Acquire token interactive is already in progress');
            callback('Acquire token interactive is already in progress', null, 'Acquire token interactive is already in progress');

            return;
        }

        const expectedState = AdalUtility.guid() + '|' + resource;
        this._state = expectedState;
        this._renewStates.push(expectedState);
        this._requestType = REQUEST_TYPE.RENEW_TOKEN;
        this.verbose('Renew token Expected state: ' + expectedState);

        // remove the existing prompt=... query parameter and add prompt=select_account
        let urlNavigate = this._urlRemoveQueryStringParameter(this._getNavigateUrl(RESPONSE_TYPE.TOKEN, resource), 'prompt');
        urlNavigate = urlNavigate + '&prompt=select_account';

        if (extraQueryParameters) {
            urlNavigate += extraQueryParameters;
        }

        if (claims && (urlNavigate.indexOf('&claims') === -1)) {
            urlNavigate += '&claims=' + encodeURIComponent(claims);
        } else if (claims && (urlNavigate.indexOf('&claims') !== -1)) {
            throw new Error('Claims cannot be passed as an extraQueryParameter');
        }

        urlNavigate = this._addHintParameters(urlNavigate);
        this._acquireTokenInProgress = true;
        this.info('acquireToken interactive is called for the resource ' + resource);
        this.registerCallback(expectedState, resource, callback);
        this._loginPopup(urlNavigate, resource, callback);
    }

    /**
     * Acquires token (interactive flow using a redirect) by sending request to AAD to obtain a new token.
     * In this case the callback passed in the Authentication request constructor will be called.
     *
     * @param {string} resource - ResourceUri identifying the target resource
     * @param {string} extraQueryParameters - Extra query parameters to add to the authentication request
     * @param {string} claims - @TODO Add parameter description for claims
     */
    public acquireTokenRedirect(resource: string, extraQueryParameters: string, claims: string): void {
        if (!resource) {
            this.warn('resource is required');
            this.callback('resource is required', null, 'resource is required');

            return;
        }

        if (!this._user) {
            this.warn('User login is required');
            this.callback('User login is required', null, 'login required');

            return;
        }

        if (this._acquireTokenInProgress) {
            this.warn('Acquire token interactive is already in progress');
            this.callback('Acquire token interactive is already in progress', null, 'Acquire token interactive is already in progress');

            return;
        }

        const expectedState = AdalUtility.guid() + '|' + resource;
        this._state = expectedState;
        this.verbose('Renew token Expected state: ' + expectedState);

        // remove the existing prompt=... query parameter and add prompt=select_account
        let urlNavigate = this._urlRemoveQueryStringParameter(this._getNavigateUrl(RESPONSE_TYPE.TOKEN, resource), 'prompt');
        urlNavigate = urlNavigate + '&prompt=select_account';

        if (extraQueryParameters) {
            urlNavigate += extraQueryParameters;
        }

        if (claims && (urlNavigate.indexOf('&claims') === -1)) {
            urlNavigate += '&claims=' + encodeURIComponent(claims);
        } else if (claims && (urlNavigate.indexOf('&claims') !== -1)) {
            throw new Error('Claims cannot be passed as an extraQueryParameter');
        }

        urlNavigate = this._addHintParameters(urlNavigate);
        this._acquireTokenInProgress = true;
        this.info('acquireToken interactive is called for the resource ' + resource);
        this._saveItem(this.STORAGE_CONSTANTS.LOGIN_REQUEST, window.location.href);
        this._saveItem(this.STORAGE_CONSTANTS.STATE_RENEW, expectedState, true);
        this.promptUser(urlNavigate);
    }

    /**
     * Redirects the browser to Azure AD authorization endpoint.
     *
     * @param {string} urlNavigate  -  Url of the authorization endpoint.
     */
    public promptUser(urlNavigate: string): void {
        if (urlNavigate) {
            this.infoPii('Navigate to:' + urlNavigate);
            window.location.replace(urlNavigate);
        } else {
            this.info('Navigate url is empty');
        }
    }

    /**
     * Clears cache items.
     */
    public clearCache(): void {
        this._saveItem(this.STORAGE_CONSTANTS.LOGIN_REQUEST, '');
        this._saveItem(this.STORAGE_CONSTANTS.ANGULAR_LOGIN_REQUEST, '');
        this._saveItem(this.STORAGE_CONSTANTS.SESSION_STATE, '');
        this._saveItem(this.STORAGE_CONSTANTS.STATE_LOGIN, '');
        this._saveItem(this.STORAGE_CONSTANTS.STATE_RENEW, '');
        this._renewStates = [];
        this._saveItem(this.STORAGE_CONSTANTS.NONCE_IDTOKEN, '');
        this._saveItem(this.STORAGE_CONSTANTS.IDTOKEN, '');
        this._saveItem(this.STORAGE_CONSTANTS.ERROR, '');
        this._saveItem(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, '');
        this._saveItem(this.STORAGE_CONSTANTS.LOGIN_ERROR, '');
        this._saveItem(this.STORAGE_CONSTANTS.LOGIN_ERROR, '');

        const keys = this.getItem(this.STORAGE_CONSTANTS.TOKEN_KEYS);
        if (keys) {
            const tokenKeys = keys.split(this.CONSTANTS.RESOURCE_DELIMETER);
            for (let i = 0; i < tokenKeys.length; i += 1) {
                const tokenValue = tokenKeys[i];
                if (tokenValue !== '') {
                    this._saveItem(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + tokenValue, '');
                    this._saveItem(this.STORAGE_CONSTANTS.EXPIRATION_KEY + tokenValue, 0);
                }
            }
        }

        this._saveItem(this.STORAGE_CONSTANTS.TOKEN_KEYS, '');
    }

    /**
     * Clears cache items for a given resource.
     *
     * @param {string} resource  -  A URI that identifies the resource.
     */
    public clearCacheForResource(resource: string): void {
        this._saveItem(this.STORAGE_CONSTANTS.STATE_RENEW, '');
        this._saveItem(this.STORAGE_CONSTANTS.ERROR, '');
        this._saveItem(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, '');

        if (this._hasResource(resource)) {
            this._saveItem(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + resource, '');
            this._saveItem(this.STORAGE_CONSTANTS.EXPIRATION_KEY + resource, 0);
        }
    }

    /**
     * Redirects user to logout endpoint.
     * After logout, it will redirect to postLogoutRedirectUri if provided.
     */
    public logOut(): void {
        this.clearCache();
        this._user = null;
        let urlNavigate;

        if (this.config.logOutUri) {
            urlNavigate = this.config.logOutUri;
        } else {
            const tenant = (this.config.tenant ? this.config.tenant : 'common');
            const logout = (
                this.config.postLogoutRedirectUri
                ? 'post_logout_redirect_uri=' + encodeURIComponent(this.config.postLogoutRedirectUri)
                : ''
            );

            urlNavigate = this.instance + tenant + '/oauth2/logout?' + logout;
        }

        this.infoPii('Logout navigate to: ' + urlNavigate);
        this.promptUser(urlNavigate);
    }

    /**
     * Calls the passed in callback with the user object or error message related to the user.
     *
     * @param {UserCallback} callback  -  The callback provided by the caller. It will be called with user or error.
     */
    public getUser(callback: UserCallback): void {
        // IDToken is first call
        if (typeof callback !== 'function') {
            throw new Error('callback is not a function');
        }

        // user in memory
        if (this._user) {
            callback(undefined, this._user);

            return;
        }

        // frame is used to get idtoken
        const idToken = this.getItem(this.STORAGE_CONSTANTS.IDTOKEN);
        if (!!idToken) {
            this.info('User exists in cache: ');
            this._user = this._createUserFromIdToken(idToken);
            callback(undefined, this._user);
        } else {
            this.warn('User information is not available');
            callback('User information is not available', undefined);
        }
    }

    /**
     * Adds login_hint to authorization URL which is used to pre-fill the username field of sign in page for the user if known ahead of time.
     * domain_hint can be one of users/organisations which when added skips the email based discovery process of the user.
     */
    protected _addHintParameters(urlNavigate: string): string {
        // If you don't use prompt=none, then if the session does not exist, there will be a failure.
        // If sid is sent alongside domain or login hints, there will be a failure since request is ambiguous.
        // If sid is sent with a prompt value other than none or attempt_none, there will be a failure since the request is ambiguous.

        if (this._user && this._user.profile) {
            if (this._user.profile.sid && urlNavigate.indexOf('&prompt=none') !== -1) {
                // don't add sid twice if user provided it in the extraQueryParameter value
                if (!this._urlContainsQueryStringParameter('sid', urlNavigate)) {
                    // add sid
                    urlNavigate += '&sid=' + encodeURIComponent(this._user.profile.sid);
                }

            } else if (this._user.profile.upn) {
                // don't add login_hint twice if user provided it in the extraQueryParameter value
                if (!this._urlContainsQueryStringParameter('login_hint', urlNavigate)) {
                    // add login_hint
                    urlNavigate += '&login_hint=' + encodeURIComponent(this._user.profile.upn);
                }

                // don't add domain_hint twice if user provided it in the extraQueryParameter value
                if (
                    !this._urlContainsQueryStringParameter('domain_hint', urlNavigate)
                    && this._user.profile.upn.indexOf('@') !== -1
                ) {
                    const parts = this._user.profile.upn.split('@');
                    // local part can include @ in quotes. Sending last part handles that.
                    urlNavigate += '&domain_hint=' + encodeURIComponent(parts[parts.length - 1]);
                }
            }

        }

        return urlNavigate;
    }

    /**
     * Creates a user object by decoding the id_token
     *
     * @param {string} idToken
     */
    protected _createUserFromIdToken(idToken: string): User | null {
        let user = null;
        const parsedJson = AdalUtility.getPayloadFromToken(idToken);

        if (parsedJson && parsedJson.aud !== undefined) {
            if (parsedJson.aud.toLowerCase() === this.config.clientId.toLowerCase()) {
                let userName = '';
                if (parsedJson.upn !== undefined) {
                    userName = parsedJson.upn;
                } else if (parsedJson.email !== undefined) {
                    userName = parsedJson.email;
                }

                user = {
                    userName: userName,
                    profile: parsedJson,
                    token: null,
                    error: null,
                    loginCached: false,
                };
            } else {
                this.warn('IdToken has invalid aud field');
            }
        }

        return user;
    }

    /**
     * Returns the anchor part(#) of the URL
     *
     * @param {string} hash
     */
    protected _getHash(hash: string): string {
        if (hash.indexOf('#/') !== -1) {
            hash = hash.substring(hash.indexOf('#/') + 2);
        } else if (hash.indexOf('#') !== -1) {
            hash = hash.substring(1);
        }

        return hash;
    }

    /**
     * Checks if the URL fragment contains access token, id token or error_description.
     *
     * @param {string} hash  -  Hash passed from redirect page
     * @returns {Boolean} true if response contains id_token, access_token or error, false otherwise.
     */
    public isCallback(hash: string): boolean {
        hash = this._getHash(hash);
        const parameters = this._deserialize(hash);

        return (
               parameters.error_description !== undefined
            || parameters.access_token !== undefined
            || parameters.id_token !== undefined
        );
    }

    /**
     * Gets login error
     *
     * @returns {string} Error message related to login.
     */
    public getLoginError(): string | null {
        return this.getItem(this.STORAGE_CONSTANTS.LOGIN_ERROR);
    }

    /**
     * Creates a requestInfo object from the URL fragment and returns it.
     *
     * @param {string} hash
     * @returns {RequestInfo} - An object created from the redirect response from AAD comprising of the keys - parameters, requestType, stateMatch, stateResponse and valid.
     */
    public getRequestInfo(hash: string): RequestInfo {
        hash = this._getHash(hash);
        const parameters = this._deserialize(hash);
        const requestInfo: RequestInfo = {
            valid: false,
            parameters: parameters,
            stateMatch: false,
            stateResponse: '',
            requestType: REQUEST_TYPE.UNKNOWN,
        };

        if (
               parameters.error_description !== undefined
            || parameters.access_token !== undefined
            || parameters.id_token !== undefined
        ) {
            requestInfo.valid = true;

            // which call
            let stateResponse = '';
            if (parameters.state !== undefined) {
                this.verbose('State: ' + parameters.state);
                stateResponse = parameters.state;
            } else {
                this.warn('No state returned');

                return requestInfo;
            }

            requestInfo.stateResponse = stateResponse;

            // async calls can fire iframe and login request at the same time if developer does not use the API as expected
            // incoming callback needs to be looked up to find the request type
            if (this._matchState(requestInfo)) { // loginRedirect or acquireTokenRedirect
                return requestInfo;
            }

            // external api requests may have many renewtoken requests for different resource
            if (!requestInfo.stateMatch && window.parent) {
                requestInfo.requestType = this._requestType;
                const statesInParentContext = this._renewStates;
                for (let i = 0; i < statesInParentContext.length; i += 1) {
                    if (statesInParentContext[i] === requestInfo.stateResponse) {
                        requestInfo.stateMatch = true;
                        break;
                    }
                }
            }
        }

        return requestInfo;
    }

    /**
     * Matches nonce from the request with the response.
     */
    protected _matchNonce(user: User): boolean {
        const requestNonce = this.getItem(this.STORAGE_CONSTANTS.NONCE_IDTOKEN);

        if (requestNonce) {
            const nonces = requestNonce.split(this.CONSTANTS.CACHE_DELIMETER);
            for (let i = 0; i < nonces.length; i += 1) {
                if (nonces[i] === user.profile.nonce) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Matches state from the request with the response.
     *
     * @param {RequestInfo} requestInfo
     */
    protected _matchState(requestInfo: RequestInfo): boolean {
        const loginStatesStr = this.getItem(this.STORAGE_CONSTANTS.STATE_LOGIN);
        if (loginStatesStr) {
            const loginStates = loginStatesStr.split(this.CONSTANTS.CACHE_DELIMETER);
            for (let i = 0; i < loginStates.length; i += 1) {
                if (loginStates[i] === requestInfo.stateResponse) {
                    requestInfo.requestType = REQUEST_TYPE.LOGIN;
                    requestInfo.stateMatch = true;

                    return true;
                }
            }
        }

        const acquireTokenStatesStr = this.getItem(this.STORAGE_CONSTANTS.STATE_RENEW);
        if (acquireTokenStatesStr) {
            const acquireTokenStates = acquireTokenStatesStr.split(this.CONSTANTS.CACHE_DELIMETER);
            for (let i = 0; i < acquireTokenStates.length; i += 1) {
                if (acquireTokenStates[i] === requestInfo.stateResponse) {
                    requestInfo.requestType = REQUEST_TYPE.RENEW_TOKEN;
                    requestInfo.stateMatch = true;

                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Extracts resource value from state.
     *
     * @param {string} state
     */
    protected _getResourceFromState(state: string): string {
        if (state) {
            const splitIndex = state.indexOf('|');

            if (splitIndex !== -1 && splitIndex + 1 < state.length) {
                return state.substring(splitIndex + 1);
            }
        }

        return '';
    }

    /**
     * Saves token or error received in the response from AAD in the cache.
     * In case of id_token, it also creates the user object.
     *
     * @param {RequestInfo} requestInfo
     */
    public saveTokenFromHash(requestInfo: RequestInfo): void {
        this.info('State status:' + requestInfo.stateMatch + '; Request type:' + requestInfo.requestType);
        this._saveItem(this.STORAGE_CONSTANTS.ERROR, '');
        this._saveItem(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, '');

        const resource = this._getResourceFromState(requestInfo.stateResponse);

        // Record error
        if (requestInfo.parameters.error_description !== undefined) {
            this.infoPii('Error :' + requestInfo.parameters.error + '; Error description:' + requestInfo.parameters.error_description);
            this._saveItem(this.STORAGE_CONSTANTS.ERROR, requestInfo.parameters.error);
            this._saveItem(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, requestInfo.parameters.error_description);

            if (requestInfo.requestType === REQUEST_TYPE.LOGIN) {
                this._loginInProgress = false;
                this._saveItem(this.STORAGE_CONSTANTS.LOGIN_ERROR, requestInfo.parameters.error_description);
            }
        } else {
            // It must verify the state from redirect
            if (requestInfo.stateMatch) {
                // record tokens to storage if exists
                this.info('State is right');
                if (requestInfo.parameters.session_state !== undefined) {
                    this._saveItem(this.STORAGE_CONSTANTS.SESSION_STATE, requestInfo.parameters.session_state);
                }

                let keys: string;

                if (requestInfo.parameters.access_token !== undefined) {
                    this.info('Fragment has access token');

                    if (!this._hasResource(resource)) {
                        keys = this.getItem(this.STORAGE_CONSTANTS.TOKEN_KEYS) || '';
                        this._saveItem(this.STORAGE_CONSTANTS.TOKEN_KEYS, keys + resource + this.CONSTANTS.RESOURCE_DELIMETER);
                    }

                    // save token with related resource
                    this._saveItem(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + resource, requestInfo.parameters.access_token);
                    this._saveItem(this.STORAGE_CONSTANTS.EXPIRATION_KEY + resource, this._expiresIn(requestInfo.parameters.expires_in));
                }

                if (requestInfo.parameters.id_token !== undefined) {
                    this.info('Fragment has id token');
                    this._loginInProgress = false;
                    this._user = this._createUserFromIdToken(requestInfo.parameters.id_token);

                    if (this._user && this._user.profile) {
                        if (!this._matchNonce(this._user)) {
                            this._saveItem(
                                this.STORAGE_CONSTANTS.LOGIN_ERROR,
                                'Nonce received: ' + this._user.profile.nonce + ' is not same as requested: ' + this.getItem(this.STORAGE_CONSTANTS.NONCE_IDTOKEN)
                            );
                            this._user = null;

                        } else {
                            this._saveItem(this.STORAGE_CONSTANTS.IDTOKEN, requestInfo.parameters.id_token);

                            // Save idtoken as access token for app itself
                            // resource = this.config.loginResource ? this.config.loginResource : this.config.clientId;
                            const idTokenResource = this.config.loginResource ? this.config.loginResource : this.config.clientId;

                            // if (!this._hasResource(resource)) {
                            if (!this._hasResource(idTokenResource)) {
                                keys = this.getItem(this.STORAGE_CONSTANTS.TOKEN_KEYS) || '';
                                // this._saveItem(this.STORAGE_CONSTANTS.TOKEN_KEYS, keys + resource + this.CONSTANTS.RESOURCE_DELIMETER);
                                this._saveItem(this.STORAGE_CONSTANTS.TOKEN_KEYS, keys + idTokenResource + this.CONSTANTS.RESOURCE_DELIMETER);
                            }

                            // this._saveItem(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + resource, requestInfo.parameters[this.CONSTANTS.ID_TOKEN]);
                            this._saveItem(this.STORAGE_CONSTANTS.EXPIRATION_KEY + idTokenResource, this._user.profile.exp);
                            // this._saveItem(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + resource, requestInfo.parameters[this.CONSTANTS.ID_TOKEN]);
                            this._saveItem(this.STORAGE_CONSTANTS.EXPIRATION_KEY + idTokenResource, this._user.profile.exp);
                        }

                    } else {
                        requestInfo.parameters.error = 'invalid id_token';
                        requestInfo.parameters.error_description = 'Invalid id_token. id_token: ' + requestInfo.parameters.id_token;
                        this._saveItem(this.STORAGE_CONSTANTS.ERROR, 'invalid id_token');
                        this._saveItem(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, 'Invalid id_token. id_token: ' + requestInfo.parameters.id_token);
                    }
                }
            } else {
                requestInfo.parameters.error = 'Invalid_state';
                requestInfo.parameters.error_description = 'Invalid_state. state: ' + requestInfo.stateResponse;
                this._saveItem(this.STORAGE_CONSTANTS.ERROR, 'Invalid_state');
                this._saveItem(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, 'Invalid_state. state: ' + requestInfo.stateResponse);
            }
        }

        this._saveItem(this.STORAGE_CONSTANTS.RENEW_STATUS + resource, this.CONSTANTS.TOKEN_RENEW_STATUS_COMPLETED);
    }

    /**
     * Gets resource for given endpoint if mapping is provided with config.
     *
     * @param {string} endpoint - The URI for which the resource Id is requested.
     * @returns {string} Resource for this API endpoint.
     */
    public getResourceForEndpoint(endpoint: string): string | null {

        // if user specified list of anonymous endpoints, no need to send token to these endpoints, return null.
        if (this.config && this.config.anonymousEndpoints) {
            for (let i = 0; i < this.config.anonymousEndpoints.length; i++) {
                if (endpoint.indexOf(this.config.anonymousEndpoints[i]) > -1) {
                    return null;
                }
            }
        }

        if (this.config && this.config.endpoints) {
            for (const configEndpoint in this.config.endpoints) {
                // configEndpoint is like /api/Todo requested endpoint can be /api/Todo/1
                if (endpoint.indexOf(configEndpoint) > -1) {
                    return this.config.endpoints[configEndpoint];
                }
            }
        }

        // default resource will be clientid if nothing specified
        // App will use idtoken for calls to itself
        // check if it's staring from http or https, needs to match with app host
        if (endpoint.indexOf('http://') > -1 || endpoint.indexOf('https://') > -1) {
            if (this._getHostFromUri(endpoint) === this._getHostFromUri(this.config.redirectUri)) {
                return this.config.loginResource;
            }
        } else {
            // in angular level, the url for $http interceptor call could be relative url,
            // if it's relative call, we'll treat it as app backend call.
            return this.config.loginResource;
        }

        // if not the app's own backend or not a domain listed in the endpoints structure
        return null;
    }

    /**
     * Strips the protocol part of the URL and returns it.
     */
    protected _getHostFromUri(uri: string): string {
        // remove http:// or https:// from uri
        return String(uri)
            .replace(/^(https?:)\/\//, '')
            .split('/')[0];
    }

    /**
     * This method must be called for processing the response received from AAD.
     * It extracts the hash, processes the token or error, saves it in the cache and
     * calls the registered callbacks with the result.
     *
     * @param {string} [hash=window.location.hash] - Hash fragment of Url.
     */
    public handleWindowCallback(hash?: string): void {
        // This is for regular javascript usage for redirect handling
        // need to make sure this is for callback
        if (null == hash) {
            hash = window.location.hash;
        }

        if (this.isCallback(hash)) {
            let self: AuthenticationContext = null as any;
            let isPopup = false;

            if (
                this._openedWindows.length > 0
                && this._openedWindows[this._openedWindows.length - 1].opener
                && this._openedWindows[this._openedWindows.length - 1].opener._adalInstance
            ) {
                self = this._openedWindows[this._openedWindows.length - 1].opener._adalInstance;
                isPopup = true;

            } else if (window.parent && (window.parent as WindowWithAdalContext)._adalInstance) {
                self = (window.parent as WindowWithAdalContext)._adalInstance!;
            }

            const requestInfo = self.getRequestInfo(hash);
            let token;
            let tokenReceivedCallback;
            let tokenType: TOKEN_TYPE | undefined;

            if (isPopup || window.parent !== window) {
                tokenReceivedCallback = self._callBackMappedToRenewStates.get(requestInfo.stateResponse);
            } else {
                tokenReceivedCallback = self.callback;
            }

            self.info('Returned from redirect url');
            self.saveTokenFromHash(requestInfo);

            if ((requestInfo.requestType === REQUEST_TYPE.RENEW_TOKEN) && window.parent) {
                if (window.parent !== window) {
                    self.verbose('Window is in iframe, acquiring token silently');
                } else {
                    self.verbose('acquiring token interactive in progress');
                }

                token = requestInfo.parameters.access_token || requestInfo.parameters.id_token;
                tokenType = TOKEN_TYPE.ACCESS_TOKEN;

            } else if (requestInfo.requestType === REQUEST_TYPE.LOGIN) {
                token = requestInfo.parameters.id_token;
                tokenType = TOKEN_TYPE.ID_TOKEN;
            }

            const errorDesc = requestInfo.parameters.error_description;
            const error = requestInfo.parameters.error;
            try {
                if (tokenReceivedCallback) {
                    tokenReceivedCallback(errorDesc, token, error, tokenType);
                }

            } catch (err) {
                self.error('Error occurred in user defined callback function: ' + err);
            }

            if (window.parent === window && !isPopup) {
                if (self.config.navigateToLoginRequestUrl) {
                    window.location.href = self.getItem(self.STORAGE_CONSTANTS.LOGIN_REQUEST)!;
                } else {
                    window.location.hash = '';
                }
            }
        }
    }

    /**
     * Constructs the authorization endpoint URL and returns it.
     */
    protected _getNavigateUrl(responseType: RESPONSE_TYPE, resource?: string): string {
        const tenant = (this.config.tenant ? this.config.tenant : 'common');

        const urlNavigate = this.instance
            + tenant
            + '/oauth2/authorize'
            + this._serialize(responseType, this.config, resource)
            + this._addLibMetadata();
        this.info('Navigate url:' + urlNavigate);

        return urlNavigate;
    }

    /**
     * Serializes the parameters for the authorization endpoint URL and returns the serialized uri string.
     * @TODO Do not use InternalConfig directly
     */
    protected _serialize(responseType: RESPONSE_TYPE, obj?: InternalConfig, resource?: string): string {
        const str = [];

        if (null != obj) {
            str.push('?response_type=' + responseType);
            str.push('client_id=' + encodeURIComponent(obj.clientId));
            if (resource) {
                str.push('resource=' + encodeURIComponent(resource));
            }

            str.push('redirect_uri=' + encodeURIComponent(obj.redirectUri));
            str.push('state=' + encodeURIComponent(this.state));

            if (null != obj.slice) {
                str.push('slice=' + encodeURIComponent(obj.slice));
            }

            if (obj.hasOwnProperty('extraQueryParameter')) {
                str.push(obj.extraQueryParameter);
            }

            const correlationId = obj.correlationId ? obj.correlationId : AdalUtility.guid();
            str.push('client-request-id=' + encodeURIComponent(correlationId));
        }

        return str.join('&');
    }

    /**
     * Parses the query string parameters into a key-value pair object.
     */
    protected _deserialize(query: string): RequestInfoParameters {
        let match;
        const pl = /\+/g;  // Regex for replacing addition symbol with a space
        const search = /([^&=]+)=([^&]*)/g;
        const decode = (s: string): string => {
            return decodeURIComponent(s.replace(pl, ' '));
        };
        const obj: { [key: string]: string } = {};

        match = search.exec(query);

        while (match) {
            obj[decode(match[1])] = decode(match[2]);
            match = search.exec(query);
        }

        return obj;
    }

    /**
     * Calculates the expires in value in milliseconds for the acquired token
     *
     * @param {string | number} [expires]
     */
    protected _expiresIn(expires?: string | number): number {
        // if AAD did not send "expires_in" property, use default expiration of 3599 seconds, for some reason AAD sends 3599 as "expires_in" value instead of 3600
        if (!expires) {
            expires = 3599;
        }

        return this._now() + parseInt(expires as string, 10);
    }

    /**
     * Return the number of milliseconds since 1970/01/01
     */
    protected _now(): number {
        return Math.round(new Date().getTime() / 1000);
    }

    /**
     * Adds the hidden iframe for silent token renewal
     */
    protected _addAdalFrame(iframeId: string): HTMLIFrameElement {
        this.info('Add adal frame to document:' + iframeId);
        const adalFrame = document.getElementById(iframeId) as HTMLIFrameElement;

        if (!adalFrame) {
            const iframe = document.createElement('iframe');
            iframe.setAttribute('id', iframeId);
            iframe.setAttribute('aria-hidden', 'true');
            iframe.style.visibility = 'hidden';
            iframe.style.position = 'absolute';
            iframe.style.width = '0px';
            iframe.style.height = '0px';
            (iframe as any).borderWidth = '0px';

            return document.body.appendChild(iframe);
        }

        return adalFrame;
    }

    /**
     * Saves the key-value pair in the cache
     */
    protected _saveItem(key: string, obj: any, preserve?: boolean): boolean {

        if (this.config.cacheLocation === 'localStorage') {

            if (!this.supportsLocalStorage) {
                this.info('Local storage is not supported');

                return false;
            }

            if (preserve) {
                const value = this.getItem(key) || '';
                localStorage.setItem(key, value + obj + this.CONSTANTS.CACHE_DELIMETER);
            } else {
                localStorage.setItem(key, obj);
            }

            return true;
        }

        // Default as session storage
        if (!this.supportsSessionStorage) {
            this.info('Session storage is not supported');

            return false;
        }

        sessionStorage.setItem(key, obj);

        return true;
    }

    /**
     * Searches the value for the given key in the cache
     */
    public getItem(key: string): string | null {

        if (this.config.cacheLocation === 'localStorage') {

            if (!this.supportsLocalStorage) {
                this.info('Local storage is not supported');

                return null;
            }

            return localStorage.getItem(key);
        }

        // Default as session storage
        if (!this.supportsSessionStorage) {
            this.info('Session storage is not supported');

            return null;
        }

        return sessionStorage.getItem(key);
    }

    /**
     * Returns true if browser supports localStorage, false otherwise.
     */
    protected _supportsLocalStorage(): boolean {
        const test = 'adalStorageTest';
        try {
            window.localStorage.setItem(test, test);
            window.localStorage.removeItem(test);

            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Returns true if browser supports sessionStorage, false otherwise.
     */
    protected _supportsSessionStorage(): boolean {
        const test = 'adalStorageTest';
        try {
            window.sessionStorage.setItem(test, test);
            window.sessionStorage.removeItem(test);

            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Adds the library version and returns it.
     */
    protected _addLibMetadata(): string {
        // x-client-SKU
        // x-client-Ver
        return '&x-client-SKU=Js&x-client-Ver=' + AuthenticationContext.VERSION;
    }

    /**
     * Checks the Logging Level, constructs the Log message and logs it. Users need to implement/override this method to turn on Logging.
     *
     * @param {LOGGING_LEVEL} level  -  Level can be set 0,1,2 and 3 which turns on 'error', 'warning', 'info' or 'verbose' level logging respectively.
     * @param {string} message  -  Message to log.
     * @param {string | Error} error  -  Error to log.
     */
    public log(level: LOGGING_LEVEL, message: string, error?: string | Error, containsPii?: boolean): void {
        if (level <= Logging.level) {

            if (!(Logging as any).piiLoggingEnabled && containsPii) {
                return;
            }

            const timestamp = (new Date()).toUTCString();
            let formattedMessage = '';

            const levelStr = (this.CONSTANTS.LEVEL_STRING_MAP as any)[level];

            if (this.config.correlationId) {
                formattedMessage = timestamp + ':' + this.config.correlationId + '-' + AuthenticationContext.VERSION + '-' + levelStr + ' ' + message;
            } else {
                formattedMessage = timestamp + ':' + AuthenticationContext.VERSION + '-' + levelStr + ' ' + message;
            }

            if (error) {
                if (error instanceof Error) {
                    formattedMessage += '\nstack:\n' + error.stack;
                } else {
                    formattedMessage += '\nerror:\n' + error;
                }
            }

            Logging.log(formattedMessage);
        }
    }

    /**
     * Logs messages when Logging Level is set to 0.
     * @param {string} message  -  Message to log.
     * @param {Error} [error]  -  Error to log.
     */
    public error(message: string, error?: string | Error): void {
        this.log(LOGGING_LEVEL.ERROR, message, error);
    }

    /**
     * Logs messages when Logging Level is set to 1.
     * @param {string} message  -  Message to log.
     */
    public warn(message: string): void {
        this.log(LOGGING_LEVEL.WARNING, message);
    }

    /**
     * Logs messages when Logging Level is set to 2.
     * @param {string} message  -  Message to log.
     */
    public info(message: string): void {
        this.log(LOGGING_LEVEL.INFO, message);
    }

    /**
     * Logs messages when Logging Level is set to 3.
     * @param {string} message  -  Message to log.
     */
    public verbose(message: string): void {
        this.log(LOGGING_LEVEL.VERBOSE, message);
    }

    /**
     * Logs Pii messages when Logging Level is set to 0 and window.piiLoggingEnabled is set to true.
     * @param {string} message  -  Message to log.
     * @param {Error} error  -  Error to log.
     */
    public errorPii(message: string, error: Error): void {
        this.log(LOGGING_LEVEL.ERROR, message, error, true);
    }

    /**
     * Logs  Pii messages when Logging Level is set to 1 and window.piiLoggingEnabled is set to true.
     * @param {string} message  -  Message to log.
     */
    public warnPii(message: string): void {
        this.log(LOGGING_LEVEL.WARNING, message, undefined, true);
    }

    /**
     * Logs messages when Logging Level is set to 2 and window.piiLoggingEnabled is set to true.
     * @param {string} message  -  Message to log.
     */
    public infoPii(message: string): void {
        this.log(LOGGING_LEVEL.INFO, message, undefined, true);
    }

    /**
     * Logs messages when Logging Level is set to 3 and window.piiLoggingEnabled is set to true.
     * @param {string} message  -  Message to log.
     */
    public verbosePii(message: string): void {
        this.log(LOGGING_LEVEL.VERBOSE, message, undefined, true);
    }
}

@Injectable({
    providedIn: 'root',
})
export class AdalService {

    private context: AuthenticationContext = null as any;
    private loginRefreshTimer = null as any;

    private user: AdalUser = {
        authenticated: false,
        userName: '',
        error: null,
        token: null,
        profile: {},
        loginCached: false,
    };

    constructor() {} // tslint:disable-line no-empty

    public init(configOptions: Config): void {
        if (!configOptions) {
            throw new Error('You must set config, when calling init.');
        }

        // redirect and logout_redirect are set to current location by default
        const existingHash = window.location.hash;

        let pathDefault = window.location.href;
        if (existingHash) {
            pathDefault = pathDefault.replace(existingHash, '');
        }

        configOptions.redirectUri = configOptions.redirectUri || pathDefault;
        configOptions.postLogoutRedirectUri = configOptions.postLogoutRedirectUri || pathDefault;

        // create instance with given config
        this.context = new AuthenticationContext(configOptions);

        (window as WindowWithAdalContext).AuthenticationContext = this.context.constructor as AuthenticationContextStatic;

        // loginresource is used to set authenticated status

        this.updateDataFromCache();

        if (this.user.loginCached && !this.user.authenticated && window.self === window.top && !this.isInCallbackRedirectMode) {
            this.refreshLoginToken();
        } else if (this.user.loginCached && this.user.authenticated && !this.loginRefreshTimer && window.self === window.top) {
            this.setupLoginTokenRefreshTimer();
        }

    }

    public get config(): InternalConfig {
        return this.context.config;
    }

    public get userInfo(): AdalUser {
        return this.user;
    }

    public login(): void {
        this.context.login();
    }

    public loginInProgress(): boolean {
        return this.context.loginInProgress();
    }

    public logOut(): void {
        this.context.logOut();
    }

    /**
     * Handles redirection after login operation.
     * Gets access token from url and saves token to the (local/session) storage
     * or saves error in case unsuccessful login.
     */
    public handleWindowCallback(): void {
        const hash = window.location.hash;
        if (this.context.isCallback(hash)) {
            const requestInfo = this.context.getRequestInfo(hash);
            this.context.saveTokenFromHash(requestInfo);

            if (requestInfo.requestType === REQUEST_TYPE.LOGIN) {
                this.updateDataFromCache();
                this.setupLoginTokenRefreshTimer();
            } else if (requestInfo.requestType === REQUEST_TYPE.RENEW_TOKEN) {
                this.context.callback = (window.parent as WindowWithAdalContext).callBackMappedToRenewStates[requestInfo.stateResponse];
            }

            if (requestInfo.stateMatch) {
                if (typeof this.context.callback === 'function') {
                    if (requestInfo.requestType === REQUEST_TYPE.RENEW_TOKEN) {
                        // Idtoken or Accestoken can be renewed
                        if (requestInfo.parameters['access_token']) {
                            this.context.callback(this.context.getItem(this.context.STORAGE_CONSTANTS.ERROR_DESCRIPTION)
                                , requestInfo.parameters['access_token']);
                        } else if (requestInfo.parameters['id_token']) {
                            this.context.callback(this.context.getItem(this.context.STORAGE_CONSTANTS.ERROR_DESCRIPTION)
                                , requestInfo.parameters['id_token']);
                        } else if (requestInfo.parameters['error']) {
                            this.context.callback(this.context.getItem(this.context.STORAGE_CONSTANTS.ERROR_DESCRIPTION), null);
                        }
                    }
                }
            }
        }

        // Remove hash from url
        if (window.location.hash) {
            if (window.history.replaceState) {
                window.history.replaceState('', '/', window.location.pathname);
            } else {
                window.location.hash = '';
            }
        }
    }

    public getCachedToken(resource: string): string | null {
        return this.context.getCachedToken(resource);
    }

    public acquireToken(resource: string): Observable<string | null> {
        return bindCallback<string | null, string | null>((callback) => {
            this.context.acquireToken(resource, (errorDescription?: string | null, token?: string | null) => {
                if (errorDescription) {
                    this.context.error('Error when acquiring token for resource: ' + resource, errorDescription);
                    callback(null, errorDescription);
                } else {
                    callback(token || null, null);
                }
            });
        })()
            .pipe<string | null>(
                map((result) => {
                    if (!result[0] && result[1]) {
                        throw (result[1]);
                    }

                    return result[0];
                })
            );
    }

    public getUser(): Observable<User | null> {
        return bindCallback<User | null>((callback) => {
            this.context.getUser( (error?: string, user?: User | null) => {
                if (error) {
                    this.context.error('Error when getting user', error);
                    callback(null);
                } else {
                    callback(user || null);
                }
            });
        })();
    }

    public clearCache(): void {
        this.context.clearCache();
    }

    public clearCacheForResource(resource: string): void {
        this.context.clearCacheForResource(resource);
    }

    public info(message: string): void {
        this.context.info(message);
    }

    public verbose(message: string): void {
        this.context.verbose(message);
    }

    /**
     * Gets resource for given endpoint if mapping is provided with config.
     *
     * @param {string} url  -  API endpoint
     * @returns {string | null} Resource for this API endpoint
     */
    public getResourceForEndpoint(url: string): string | null {
        return this.context.getResourceForEndpoint(url);
    }

    public refreshDataFromCache(): void {
        this.updateDataFromCache();
    }

    private updateDataFromCache(): void {
        const token = this.context.getCachedToken(this.context.config.loginResource);
        this.user.authenticated = token !== null && token.length > 0;

        const user = this.context.getCachedUser();

        if (user) {
            this.user.userName = user.userName;
            this.user.profile = user.profile;
            this.user.token = token;
            this.user.error = this.context.getLoginError();
            this.user.loginCached = true;
        } else {
            this.user.userName = '';
            this.user.profile = {};
            this.user.token = null;
            this.user.error = this.context.getLoginError();
            this.user.loginCached = false;
        }
    }

    private refreshLoginToken(): void {
        if (!this.user.loginCached) {
            throw new Error('User not logged in');
        }

        this.acquireToken(this.context.config.loginResource)
            .subscribe((token: string | null) => {
                this.user.token = token;
                if (!this.user.authenticated) {
                    this.user.authenticated = true;
                    this.user.error = null;
                    window.location.reload();
                } else {
                    this.setupLoginTokenRefreshTimer();
                }
            }, (error: string) => {
                this.user.authenticated = false;
                this.user.error = this.context.getLoginError();
            });
    }

    private now(): number {
        return Math.round(new Date().getTime() / 1000);
    }

    private get isInCallbackRedirectMode(): boolean {
      return window.location.href.indexOf('#access_token') !== -1 || window.location.href.indexOf('#id_token') !== -1;
    }

    private setupLoginTokenRefreshTimer(): void {
        // Get expiration of login token
        const expirationStr = this.context.getItem(this.context.STORAGE_CONSTANTS.EXPIRATION_KEY + this.context.config.loginResource);
        const expiration = parseInt(expirationStr!, 10);

        // Either wait until the refresh window is valid or refresh in 1 second (measured in seconds)
        const timerDelay = expiration - this.now() - (this.context.config.expireOffsetSeconds || 300) > 0 ? expiration - this.now() - (this.context.config.expireOffsetSeconds || 300) : 1;
        if (this.loginRefreshTimer) {
            this.loginRefreshTimer.unsubscribe();
        }
        this.loginRefreshTimer = timer(timerDelay * 1000)
            .subscribe((x) => {
                this.refreshLoginToken();
            });
    }
}
