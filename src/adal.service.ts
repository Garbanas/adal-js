import { Injectable } from '@angular/core';

import { bindCallback, Observable, Subscription, throwError, timer } from 'rxjs';
import { catchError, take, tap } from 'rxjs/operators';

import { guid } from './utilities/guid';
import { JwtUtility } from './utilities/jwt-utilty';
import { Storage } from './storage/storage';
import { localStorageSupported, sessionStorageSupported } from './storage/storage-helper';
import { LocalStorage } from './storage/local.storage';
import { SessionStorage } from './storage/session.storage';
import { fromPromise } from 'rxjs/internal-compatibility';
import { AdalEvents } from './event/adal.events';
import { CONSTANTS, LOGGING_LEVEL, REQUEST_TYPE, RESPONSE_TYPE, STORAGE_CONSTANTS, TOKEN_TYPE } from './constants';
import { deepCopy } from './utilities/deep-copy';

// tslint:disable member-ordering

export interface AuthenticationContextStatic {
    new (config: Config): AuthenticationContext;
}

export interface WindowWithAdalContext extends Window {
    _adalInstance?: AuthenticationContext;
    AuthenticationContext: AuthenticationContextStatic;
}

/**
 * @TODO Remove
 * @deprecated
 */
declare var Logging: {
    log: (message: string) => void;
    level: LOGGING_LEVEL;
};

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

export interface TokenReceivedCallbackInfo extends RequestInfo {
    tokenType?: TOKEN_TYPE;
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

export interface TokenCallback {
    /**
     * @param {string} [errorDescription] - Error description returned from AAD if token request fails.
     * @param {string} [token] - Token returned from AAD if token request is successful.
     * @param {string} [error] - Error message returned from AAD if token request fails.
     * @param {TOKEN_TYPE} [tokenType] - @TODO Add parameter description for tokenType
     */
    (errorDescription?: string | null, token?: string | null, error?: string | null, tokenType?: TOKEN_TYPE): void;
}

export interface TokenReceivedCallback {
    /**
     * @param {string} token - Token returned from AAD if token request is successful.
     * @param {TOKEN_TYPE} tokenType - @TODO Add parameter description for tokenType
     * @param {mixed} error - Error message returned from AAD if token request fails.
     */
    (token: string | null, info: TokenReceivedCallbackInfo, error: { message: string, description?: string } | null): void;
}

export interface UserCallback {
    /**
     * @param {string} [error] - Error message if user info is not available.
     * @param {User} [user] - User object retrieved from the cache.
     */
    (error?: string, user?: User | null): void;
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
     * Set this to true to enable login in a popup window instead of a full redirect. Defaults to `false`.
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
    callback?: TokenReceivedCallback;

    slice?: string;

    storage?: Storage;
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
    callback?: TokenReceivedCallback;
    slice?: string;
}

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
    public popUp: boolean = false;

    // @TODO Remove eventually
    public isAngular: boolean = true;

    public get state(): string {
        return this._state;
    }

    public readonly storage: Storage;

    public readonly origin: string;
    public readonly isPopup: boolean;
    public readonly isIFrame: boolean;
    public readonly isRoot: boolean;

    // private
    private _user: User | null = null;
    private _activeRenewals: Map<string, string> = new Map();
    private _loginInProgress: boolean = false;
    private _acquireTokenInProgress: boolean = false;
    private _renewStates: string[] = [];
    private _openedWindows: Window[] = [];
    private _requestType: REQUEST_TYPE = REQUEST_TYPE.LOGIN;

    private _state: string = '';

    private _promiseForExpectedState: Map<string, Promise<string>> = new Map();

    private _events: AdalEvents = new AdalEvents();

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

        this.origin = window.location.protocol + '//' + window.location.host;
        this.isPopup = (window.opener && !!((window.opener as WindowWithAdalContext)._adalInstance));
        this.isIFrame = (window.parent && window.parent !== window && !!((window.parent as WindowWithAdalContext)._adalInstance));
        this.isRoot = (!this.isPopup && ! this.isIFrame);

        if (!this.isRoot) {
            console.info('I am in an iFrame :)');
            window.parent.postMessage({
                    type: 'AdalTokenRefresh',
                    data: {
                        message: 'This is a *secure* message from the iFrame :D ',
                    },
                },
                this.origin
            );
        } else {
            console.info('I am in the root window :)');
            window.addEventListener('message', (event: MessageEvent) => {
                if (event.origin === this.origin && event.data && event.data.type === 'AdalTokenRefresh') {
                    console.info('Received message event: ', event.data, event);
                }
            }, false);
        }

        const configClone = deepCopy(config) as InternalConfig;

        this.storage = this.getStorageImplementation(configClone);

        if (config.navigateToLoginRequestUrl === undefined) {
            config.navigateToLoginRequestUrl = true;
        }

        if (config.popUp) {
            this.popUp = true;
        }

        if (config.callback && typeof config.callback === 'function') {
            this.onTokenReceived(config.callback);
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

    public onTokenReceived(callback: TokenReceivedCallback): () => void {
        return this._events.on('tokenReceived', callback);
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
        const expectedState = guid();
        this._state = expectedState;
        const idTokenNonce = guid();
        let loginStartPage = this.storage.get(this.STORAGE_CONSTANTS.ANGULAR_LOGIN_REQUEST);

        if (!loginStartPage || loginStartPage === '') {
            loginStartPage = window.location.href;
        } else {
            this.storage.set(this.STORAGE_CONSTANTS.ANGULAR_LOGIN_REQUEST, '');
        }

        this.verbose('Expected state: ' + expectedState + ', startPage: ' + loginStartPage);
        this.storage.set(this.STORAGE_CONSTANTS.LOGIN_REQUEST, loginStartPage);
        this.storage.set(this.STORAGE_CONSTANTS.LOGIN_ERROR, '');
        const existingLoginState = this.storage.get(this.STORAGE_CONSTANTS.STATE_LOGIN) || '';
        this.storage.set(this.STORAGE_CONSTANTS.STATE_LOGIN, existingLoginState + expectedState + this.CONSTANTS.CACHE_DELIMETER);
        const existingIdTokenNonce = this.storage.get(this.STORAGE_CONSTANTS.NONCE_IDTOKEN) || '';
        this.storage.set(this.STORAGE_CONSTANTS.NONCE_IDTOKEN, existingIdTokenNonce + idTokenNonce + this.CONSTANTS.CACHE_DELIMETER);
        this.storage.set(this.STORAGE_CONSTANTS.ERROR, '');
        this.storage.set(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, '');
        const urlNavigate = this._getNavigateUrl(RESPONSE_TYPE.ID_TOKEN) + '&nonce=' + encodeURIComponent(idTokenNonce);

        if (this.config.displayCall) {
            // User defined way of handling the navigation
            this.config.displayCall(urlNavigate);

        } else if (this.popUp) {
            this.storage.set(this.STORAGE_CONSTANTS.STATE_LOGIN, ''); // so requestInfo does not match redirect case
            this._renewStates.push(expectedState);
            this.registerCallback(expectedState, this.config.clientId/*, this.callback*/);
            this._loginPopup(urlNavigate);

        } else {
            this.redirectToUrl(urlNavigate);
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
        this.storage.set(this.STORAGE_CONSTANTS.ERROR, error || '');
        this.storage.set(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, errorDesc || '');
        this.storage.set(this.STORAGE_CONSTANTS.LOGIN_ERROR, loginError || '');

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
        const loginCallback = callback;

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
        const keys = this.storage.get(this.STORAGE_CONSTANTS.TOKEN_KEYS);

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

        const token = this.storage.get(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + resource);
        const expiration = this.storage.get(this.STORAGE_CONSTANTS.EXPIRATION_KEY + resource);
        const expiry = (expiration ? parseInt(expiration, 10) : null);

        // If expiration is within offset, it will force renew
        const offset = this.config.expireOffsetSeconds || 300;

        if (expiry && (expiry > this._now() + offset)) {
            return token || null;
        } else {
            this.storage.set(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + resource, '');
            this.storage.set(this.STORAGE_CONSTANTS.EXPIRATION_KEY + resource, '0');

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

        const idToken = this.storage.get(this.STORAGE_CONSTANTS.IDTOKEN);
        if (idToken) {
            user = this._createUserFromIdToken(idToken);
        }
        this._user = user;

        return user;
    }

    protected getActiveRenewalForResource(resource: string): string | undefined {
        return this._activeRenewals.get(resource);
    }

    /**
     * Returns a promise for when the given resource completes the token renewal.
     *
     * @param {string} resource  -  A URI that identifies the resource for which the token is requested.
     * @param {string} expectedState  -  A unique identifier (guid).
     */
    protected registerStateCallback(resource: string, expectedState: string): Promise<string> {
        this._activeRenewals.set(resource, expectedState);

        let promise = this._promiseForExpectedState.get(expectedState);
        if (!promise) {
            promise = new Promise<string>((resolve, reject) => {
                const unbind = this._events.on<TokenReceivedCallback>('tokenReceived', (token, info, error) => {
                    if (resource === this.config.clientId) {
                        if (info.requestType === REQUEST_TYPE.LOGIN) {
                            unbind();
                            if (!error) {
                                resolve(token!);
                            } else {
                                reject(error.message);
                            }
                            this._promiseForExpectedState.delete(expectedState);
                            this._activeRenewals.delete(resource);
                        }
                    } else {
                        if (info.requestType === REQUEST_TYPE.RENEW_TOKEN && info.parameters.state === expectedState) {
                            unbind();
                            if (!error) {
                                resolve(token!);
                            } else {
                                reject(error.message);
                            }
                            this._promiseForExpectedState.delete(expectedState);
                            this._activeRenewals.delete(resource);
                        }
                    }
                });
            });
            this._promiseForExpectedState.set(expectedState, promise);
        }

        return promise;
    }

    /**
     * Adds the passed callback to the array of callbacks for the specified resource and puts the array on the window object.
     *
     * @param {string} resource  -  A URI that identifies the resource for which the token is requested.
     * @param {string} expectedState  -  A unique identifier (guid).
     * @param {TokenCallback} callback  -  The callback provided by the caller. It will be called with token or error.
     * @deprecated
     */
    public registerCallback(expectedState: string, resource: string, callback?: TokenCallback): Promise<string> {
        return Promise.reject('DO NOT CALL THIS');
    }

    /**
     * Acquires access token with hidden iframe
     */
    protected _renewToken(resource: string, responseType?: RESPONSE_TYPE): Promise<any> {
        // Already renewing for this resource, callback when we get the token.
        const activeRenewal = this.getActiveRenewalForResource(resource);
        if (activeRenewal) {
            // Active renewals contains the state for each renewal.
            return this.registerStateCallback(resource, activeRenewal);
        }

        // use iframe to try to renew token
        // use given resource to create new auth url
        this.info('renewToken is called for resource: ' + resource);

        const frameName = 'adalRenewFrameFor' + resource;
        const frameHandle = this._addAdalFrame(frameName);
        const expectedState = guid() + '|' + resource;

        this._state = expectedState;
        // renew happens in iframe, so it keeps javascript context
        this._renewStates.push(expectedState);
        this.verbose('Renew token Expected state: ' + expectedState);

        // remove the existing prompt=... query parameter and add prompt=none
        responseType = responseType || RESPONSE_TYPE.TOKEN;
        let urlNavigate = this._urlRemoveQueryStringParameter(this._getNavigateUrl(responseType, resource), 'prompt');

        if (responseType === this.RESPONSE_TYPE.ID_TOKEN_TOKEN) {
            const idTokenNonce = guid();
            const existingIdTokenNonce = this.storage.get(this.STORAGE_CONSTANTS.NONCE_IDTOKEN) || '';
            this.storage.set(this.STORAGE_CONSTANTS.NONCE_IDTOKEN, existingIdTokenNonce + idTokenNonce + this.CONSTANTS.CACHE_DELIMETER);
            urlNavigate += '&nonce=' + encodeURIComponent(idTokenNonce);
        }

        urlNavigate = urlNavigate + '&prompt=none';
        urlNavigate = this._addHintParameters(urlNavigate);

        const promise = this.registerStateCallback(resource, expectedState);
        this.verbosePii('Navigate to: ' + urlNavigate);
        frameHandle.src = 'about:blank';

        this._loadFrameTimeout(urlNavigate, frameName, resource, REQUEST_TYPE.RENEW_TOKEN);

        return promise;
    }

    /**
     * Renews idtoken for app's own backend when resource is clientId and calls the callback with token/error
     */
    protected _renewIdToken(responseType?: RESPONSE_TYPE): Promise<string> {
        // Already renewing for this resource, callback when we get the token.
        const activeRenewal = this.getActiveRenewalForResource(this.config.clientId);
        if (activeRenewal) {
            // Active renewals contains the state for each renewal.
            return this.registerStateCallback(this.config.clientId, activeRenewal);
        }

        // use iframe to try to renew token
        this.info('renewIdToken is called');
        const frameId = 'adalIdTokenFrame';
        const frameHandle = this._addAdalFrame(frameId);
        const expectedState = guid() + '|' + this.config.clientId;

        const idTokenNonce = guid();
        const existingIdTokenNonce = this.storage.get(this.STORAGE_CONSTANTS.NONCE_IDTOKEN) || '';
        this.storage.set(this.STORAGE_CONSTANTS.NONCE_IDTOKEN, existingIdTokenNonce + idTokenNonce + this.CONSTANTS.CACHE_DELIMETER);

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

        const promise = this.registerStateCallback(this.config.clientId, expectedState);
        this.verbosePii('Navigate to: ' + urlNavigate);
        frameHandle.src = 'about:blank';

        this._loadFrameTimeout(urlNavigate, frameId, this.config.clientId, REQUEST_TYPE.LOGIN);

        return promise;
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
    protected _loadFrameTimeout(urlNavigation: string, frameName: string, resource: string, requestType: REQUEST_TYPE): void {
        // Set iframe session to pending
        this.verbose('Set loading state to pending for: ' + resource);
        this.storage.set(this.STORAGE_CONSTANTS.RENEW_STATUS + resource, this.CONSTANTS.TOKEN_RENEW_STATUS_IN_PROGRESS);
        this._loadFrame(urlNavigation, frameName);

        setTimeout(() => {
            if (this.storage.get(this.STORAGE_CONSTANTS.RENEW_STATUS + resource) === this.CONSTANTS.TOKEN_RENEW_STATUS_IN_PROGRESS) {
                // fail the iframe session if it's in pending state
                this.verbose('Loading frame has timed out after: ' + (this.CONSTANTS.LOADFRAME_TIMEOUT / 1000) + ' seconds for resource ' + resource);
                const expectedState = this.getActiveRenewalForResource(resource);

                if (expectedState) {
                    const info: TokenReceivedCallbackInfo = Object.create(null);
                    info.requestType = requestType;
                    info.parameters = {
                        state: expectedState,
                    };

                    const error = Object.create(null);
                    error.message = 'Token Renewal Failed';
                    error.description = 'Token renewal operation failed due to timeout';

                    this._events.emit('tokenReceived', null, info, error);
                }

                this.storage.set(this.STORAGE_CONSTANTS.RENEW_STATUS + resource, this.CONSTANTS.TOKEN_RENEW_STATUS_CANCELED);
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
     */
    public acquireToken(resource: string): Promise<string> {
        let errorMessage: string;

        if (!resource) {
            errorMessage = 'Resource is required';
            this.warn(errorMessage);

            return Promise.reject(errorMessage);
        }

        const token = this.getCachedToken(resource);

        if (token) {
            this.info('Token is already in cache for resource: ' + resource);

            return Promise.resolve(token);
        }

        if (!this.isRoot) {
            errorMessage = 'Can not acquire token from iFrame';
            this.warn(errorMessage);

            return Promise.reject(errorMessage);
        }

        if (!this._user && !(this.config.extraQueryParameter && this.config.extraQueryParameter.indexOf('login_hint') !== -1)) {
            errorMessage = 'User login is required';
            this.warn(errorMessage);

            return Promise.reject(errorMessage);
        }

        // renew attempt with iframe
        this._requestType = REQUEST_TYPE.RENEW_TOKEN;
        let promise;
        if (resource === this.config.clientId) {
            // App uses idToken to send to api endpoints
            // Default resource is tracked as clientId to store this token
            if (this._user) {
                this.verbose('renewing idtoken');
                promise = this._renewIdToken();

            } else {
                this.verbose('renewing idtoken and access_token');
                promise = this._renewIdToken(this.RESPONSE_TYPE.ID_TOKEN_TOKEN);
            }

        } else {
            if (this._user) {
                this.verbose('renewing access_token');
                promise = this._renewToken(resource);

            } else {
                this.verbose('renewing idtoken and access_token');
                promise = this._renewToken(resource, this.RESPONSE_TYPE.ID_TOKEN_TOKEN);
            }
        }

        return promise;
    }

    /**
     * Acquires token (interactive flow using a popUp window) by sending request to AAD to obtain a new token.
     *
     * @param {string} resource - ResourceUri identifying the target resource
     * @param {string} extraQueryParameters - Extra query parameters to add to the authentication request
     * @param {string} claims - @TODO Add parameter description for claims
     * @param {TokenCallback} callback - The callback provided by the caller. It will be called with token or error.
     */
    public acquireTokenPopup(resource: string, extraQueryParameters: string, claims: string, callback: TokenCallback): Promise<string> {
        if (!resource) {
            this.warn('resource is required');
            callback('resource is required', null, 'resource is required');

            return Promise.reject('Resource is required');
        }

        if (!this.isRoot) {
            this.warn('Can not acquire token from iFrame');
            callback('Can not acquire token from iFrame', null, 'Can not acquire token from iFrame');

            return Promise.reject('Can not acquire token from iFrame');
        }

        if (!this._user) {
            this.warn('User login is required');
            callback('User login is required', null, 'login required');

            return Promise.reject('User login is required');
        }

        if (this._acquireTokenInProgress) {
            this.warn('Acquire token interactive is already in progress');
            callback('Acquire token interactive is already in progress', null, 'Acquire token interactive is already in progress');

            return Promise.reject('Acquire token interactive is already in progress');
        }

        const expectedState = guid() + '|' + resource;
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
        const promise = this.registerCallback(expectedState, resource, callback);
        this._loginPopup(urlNavigate, resource, callback);

        return promise;
    }

    /**
     * Acquires token (interactive flow using a redirect) by sending request to AAD to obtain a new token.
     * In this case the callback passed in the Authentication request constructor will be called.
     *
     * @param {string} resource - ResourceUri identifying the target resource
     * @param {string} extraQueryParameters - Extra query parameters to add to the authentication request
     * @param {string} claims - @TODO Add parameter description for claims
     */
    public acquireTokenRedirect(resource: string, extraQueryParameters: string, claims: string): Promise<string> {
        const token: string | null = null;
        const info: TokenReceivedCallbackInfo = Object.create(null);
        const error: {message: string, description?: string} = Object.create(null);
        let errorMessage: string;
        // let errorDescription: string;

        if (!resource) {
            errorMessage = 'Resource is required';

            this.warn(errorMessage);

            error.message = errorMessage;
            this._events.emit('tokenReceived', token, info, error);

            return Promise.reject(errorMessage);
        }

        if (!this.isRoot) {
            errorMessage = 'Can not acquire token from iFrame';

            this.warn(errorMessage);

            error.message = errorMessage;
            this._events.emit('tokenReceived', token, info, error);

            return Promise.reject('Can not acquire token from iFrame');
        }

        if (!this._user) {
            errorMessage = 'User login is required';
            this.warn(errorMessage);

            error.message = errorMessage;
            this._events.emit('tokenReceived', token, info, error);

            return Promise.reject(errorMessage);
        }

        if (this._acquireTokenInProgress) {
            errorMessage = 'Acquire token interactive is already in progress';
            this.warn(errorMessage);

            error.message = errorMessage;
            this._events.emit('tokenReceived', token, info, error);

            return Promise.reject(errorMessage);
        }

        const expectedState = guid() + '|' + resource;
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
        this.storage.set(this.STORAGE_CONSTANTS.LOGIN_REQUEST, window.location.href);
        const existingState = this.storage.get(this.STORAGE_CONSTANTS.STATE_RENEW) || '';
        this.storage.set(this.STORAGE_CONSTANTS.STATE_RENEW, existingState + expectedState + this.CONSTANTS.CACHE_DELIMETER);
        this.redirectToUrl(urlNavigate);

        return Promise.resolve('');
    }

    /**
     * Redirects the browser to Azure AD authorization endpoint.
     *
     * @param {string} urlNavigate  -  Url of the authorization endpoint.
     */
    public redirectToUrl(urlNavigate: string): void {
        if (urlNavigate) {
            this.infoPii('Navigate to: ' + urlNavigate);
            window.location.replace(urlNavigate);
        } else {
            this.info('Navigate url is empty');
        }
    }

    /**
     * Clears cache items.
     */
    public clearCache(): void {
        this.storage.set(this.STORAGE_CONSTANTS.LOGIN_REQUEST, '');
        this.storage.set(this.STORAGE_CONSTANTS.ANGULAR_LOGIN_REQUEST, '');
        this.storage.set(this.STORAGE_CONSTANTS.SESSION_STATE, '');
        this.storage.set(this.STORAGE_CONSTANTS.STATE_LOGIN, '');
        this.storage.set(this.STORAGE_CONSTANTS.STATE_RENEW, '');
        this._renewStates = [];
        this.storage.set(this.STORAGE_CONSTANTS.NONCE_IDTOKEN, '');
        this.storage.set(this.STORAGE_CONSTANTS.IDTOKEN, '');
        this.storage.set(this.STORAGE_CONSTANTS.ERROR, '');
        this.storage.set(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, '');
        this.storage.set(this.STORAGE_CONSTANTS.LOGIN_ERROR, '');
        this.storage.set(this.STORAGE_CONSTANTS.LOGIN_ERROR, '');

        const keys = this.storage.get(this.STORAGE_CONSTANTS.TOKEN_KEYS);
        if (keys) {
            const tokenKeys = keys.split(this.CONSTANTS.RESOURCE_DELIMETER);
            for (let i = 0; i < tokenKeys.length; i += 1) {
                const tokenValue = tokenKeys[i];
                if (tokenValue !== '') {
                    this.storage.set(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + tokenValue, '');
                    this.storage.set(this.STORAGE_CONSTANTS.EXPIRATION_KEY + tokenValue, '0');
                }
            }
        }

        this.storage.set(this.STORAGE_CONSTANTS.TOKEN_KEYS, '');
    }

    /**
     * Clears cache items for a given resource.
     *
     * @param {string} resource  -  A URI that identifies the resource.
     */
    public clearCacheForResource(resource: string): void {
        this.storage.set(this.STORAGE_CONSTANTS.STATE_RENEW, '');
        this.storage.set(this.STORAGE_CONSTANTS.ERROR, '');
        this.storage.set(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, '');

        if (this._hasResource(resource)) {
            this.storage.set(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + resource, '');
            this.storage.set(this.STORAGE_CONSTANTS.EXPIRATION_KEY + resource, '0');
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
        this.redirectToUrl(urlNavigate);
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
        const idToken = this.storage.get(this.STORAGE_CONSTANTS.IDTOKEN);
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
        const parsedJson = JwtUtility.getPayloadFromToken(idToken);

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

    public getClosestInstance(): AuthenticationContext {
        if (this.isRoot) {
            return this;
        }

        if (this.isPopup) {
            return (window.opener as WindowWithAdalContext)._adalInstance!;
        }

        return (window.parent as WindowWithAdalContext)._adalInstance!;
    }

    /**
     * Gets login error
     *
     * @returns {string} Error message related to login.
     */
    public getLoginError(): string | null {
        return this.storage.get(this.STORAGE_CONSTANTS.LOGIN_ERROR) || null;
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
        const requestNonce = this.storage.get(this.STORAGE_CONSTANTS.NONCE_IDTOKEN);

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
        const loginStatesStr = this.storage.get(this.STORAGE_CONSTANTS.STATE_LOGIN);
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

        const acquireTokenStatesStr = this.storage.get(this.STORAGE_CONSTANTS.STATE_RENEW);
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
        this.info('State status: ' + requestInfo.stateMatch + '; Request type: ' + requestInfo.requestType);
        this.storage.set(this.STORAGE_CONSTANTS.ERROR, '');
        this.storage.set(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, '');

        const resource = this._getResourceFromState(requestInfo.stateResponse);

        // Record error
        if (requestInfo.parameters.error_description !== undefined) {
            this.infoPii('Error: ' + requestInfo.parameters.error + '; Error description: ' + requestInfo.parameters.error_description);
            this.storage.set(this.STORAGE_CONSTANTS.ERROR, requestInfo.parameters.error || '');
            this.storage.set(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, requestInfo.parameters.error_description);

            if (requestInfo.requestType === REQUEST_TYPE.LOGIN) {
                this._loginInProgress = false;
                this.storage.set(this.STORAGE_CONSTANTS.LOGIN_ERROR, requestInfo.parameters.error_description);
            }

            // window.parent.postMessage({
            //     type: 'AdalTokenRefresh',
            //     data: {
            //       isError: true,
            //       resource: resource,
            //       requestType: requestInfo.requestType,
            //       error: requestInfo.parameters.error || '',
            //       errorDescription: requestInfo.parameters.error_description,
            //     },
            //   },
            //   this.origin
            // );

        } else {
            // It must verify the state from redirect
            if (requestInfo.stateMatch) {
                // record tokens to storage if exists
                this.info('State is right');
                if (requestInfo.parameters.session_state !== undefined) {
                    this.storage.set(this.STORAGE_CONSTANTS.SESSION_STATE, requestInfo.parameters.session_state);
                }

                let keys: string;

                if (requestInfo.parameters.access_token !== undefined) {
                    this.info('Fragment has access token');

                    if (!this._hasResource(resource)) {
                        keys = this.storage.get(this.STORAGE_CONSTANTS.TOKEN_KEYS) || '';
                        this.storage.set(this.STORAGE_CONSTANTS.TOKEN_KEYS, keys + resource + this.CONSTANTS.RESOURCE_DELIMETER);
                    }

                    // save token with related resource
                    this.storage.set(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + resource, requestInfo.parameters.access_token);
                    this.storage.set(this.STORAGE_CONSTANTS.EXPIRATION_KEY + resource, `${this._expiresIn(requestInfo.parameters.expires_in)}`);
                }

                if (requestInfo.parameters.id_token !== undefined) {
                    this.info('Fragment has id token');
                    this._loginInProgress = false;
                    this._user = this._createUserFromIdToken(requestInfo.parameters.id_token);

                    if (this._user && this._user.profile) {
                        if (!this._matchNonce(this._user)) {
                            this.storage.set(
                                this.STORAGE_CONSTANTS.LOGIN_ERROR,
                                'Nonce received: ' + this._user.profile.nonce + ' is not same as requested: ' + this.storage.get(this.STORAGE_CONSTANTS.NONCE_IDTOKEN)
                            );
                            this._user = null;

                        } else {
                            this.storage.set(this.STORAGE_CONSTANTS.IDTOKEN, requestInfo.parameters.id_token);

                            // Save idtoken as access token for app itself
                            // resource = this.config.loginResource ? this.config.loginResource : this.config.clientId;
                            const idTokenResource = this.config.loginResource ? this.config.loginResource : this.config.clientId;

                            // if (!this._hasResource(resource)) {
                            if (!this._hasResource(idTokenResource)) {
                                keys = this.storage.get(this.STORAGE_CONSTANTS.TOKEN_KEYS) || '';
                                // this.storage.set(this.STORAGE_CONSTANTS.TOKEN_KEYS, keys + resource + this.CONSTANTS.RESOURCE_DELIMETER);
                                this.storage.set(this.STORAGE_CONSTANTS.TOKEN_KEYS, keys + idTokenResource + this.CONSTANTS.RESOURCE_DELIMETER);
                            }

                            // this.storage.set(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + resource, requestInfo.parameters.id_token);
                            this.storage.set(this.STORAGE_CONSTANTS.ACCESS_TOKEN_KEY + idTokenResource, requestInfo.parameters.id_token);
                            // this.storage.set(this.STORAGE_CONSTANTS.EXPIRATION_KEY + resource, this._user.profile.exp || '');
                            this.storage.set(this.STORAGE_CONSTANTS.EXPIRATION_KEY + idTokenResource, this._user.profile.exp || '');
                        }

                    } else {
                        requestInfo.parameters.error = 'invalid id_token';
                        requestInfo.parameters.error_description = 'Invalid id_token. id_token: ' + requestInfo.parameters.id_token;
                        this.storage.set(this.STORAGE_CONSTANTS.ERROR, 'invalid id_token');
                        this.storage.set(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, 'Invalid id_token. id_token: ' + requestInfo.parameters.id_token);
                    }
                }
            } else {
                requestInfo.parameters.error = 'Invalid_state';
                requestInfo.parameters.error_description = 'Invalid_state. state: ' + requestInfo.stateResponse;
                this.storage.set(this.STORAGE_CONSTANTS.ERROR, 'Invalid_state');
                this.storage.set(this.STORAGE_CONSTANTS.ERROR_DESCRIPTION, 'Invalid_state. state: ' + requestInfo.stateResponse);
            }
        }

        this.storage.set(this.STORAGE_CONSTANTS.RENEW_STATUS + resource, this.CONSTANTS.TOKEN_RENEW_STATUS_COMPLETED);
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
    public handleWindowCallback(hash?: string, noLocationChange: boolean = false, noHashChange: boolean = false): RequestInfo | null {
        // This is for regular javascript usage for redirect handling
        // need to make sure this is for callback
        if (null == hash) {
            hash = window.location.hash;
        }

        if (this.isCallback(hash)) {
            this.verbose('Getting closest AuthenticationContext...');
            const self: AuthenticationContext = this.getClosestInstance();
            self.verbose('...done!');

            // let isPopup = false;
            // if (
            //     this._openedWindows.length > 0
            //     && this._openedWindows[this._openedWindows.length - 1].opener
            //     && this._openedWindows[this._openedWindows.length - 1].opener._adalInstance
            // ) {
            //     self = this._openedWindows[this._openedWindows.length - 1].opener._adalInstance;
            //     isPopup = true;
            //
            // } else if (window.parent && (window.parent as WindowWithAdalContext)._adalInstance) {
            //     self = (window.parent as WindowWithAdalContext)._adalInstance!;
            // }

            const requestInfo = self.getRequestInfo(hash);
            let token;
            let tokenType: TOKEN_TYPE | undefined;

            self.info('Returned from redirect url');
            self.saveTokenFromHash(requestInfo);

            const errorMessage = requestInfo.parameters.error_description || requestInfo.parameters.error;

            if (requestInfo.requestType === REQUEST_TYPE.RENEW_TOKEN) {
                if (!this.isRoot) {
                    self.verbose('Window is in iframe, acquiring token silently');
                } else {
                    self.verbose('acquiring token interactive in progress');
                }

                token = requestInfo.parameters.access_token || requestInfo.parameters.id_token;
                tokenType = TOKEN_TYPE.ACCESS_TOKEN;

                if (errorMessage) {
                    self._events.emit('renewTokenError', errorMessage, requestInfo.parameters.state, requestInfo.requestType);
                } else {
                    self._events.emit('renewTokenSuccess', token, requestInfo.parameters.state, requestInfo.requestType);
                }

            } else if (requestInfo.requestType === REQUEST_TYPE.LOGIN) {
                token = requestInfo.parameters.id_token;
                tokenType = TOKEN_TYPE.ID_TOKEN;

                if (errorMessage) {
                    self._events.emit('renewIdTokenError', errorMessage);
                } else {
                    self._events.emit('renewIdTokenSuccess', token);
                }
            }

            const errorDesc = requestInfo.parameters.error_description;
            const error = requestInfo.parameters.error;

            const info = Object.create(null);
            info.tokenType = tokenType;
            info.parameters = requestInfo.parameters;
            info.requestType = requestInfo.requestType;
            info.stateMatch = requestInfo.stateMatch;
            info.stateResponse = requestInfo.stateResponse;
            info.valid = requestInfo.valid;

            let errorObject = null;
            if (error || errorDesc) {
                errorObject = Object.create(null);
                errorObject.message = error || errorDesc;
                if (error && errorDesc) {
                    errorObject.description = errorDesc;
                }
            }

            this._events.emit('tokenReceived', token || null, info, errorObject);

            if (this.isRoot) {
                if (self.config.navigateToLoginRequestUrl) {
                    if (!noLocationChange) {
                        window.location.href = self.storage.get(self.STORAGE_CONSTANTS.LOGIN_REQUEST)!;
                    }
                } else {
                    if (!noHashChange) {
                        window.history.replaceState(
                            '',
                            document.title,
                            window.location.pathname + window.location.search
                        );
                    }
                }
            }

            return requestInfo;
        }

        return null;
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
        this.info('Navigate url: ' + urlNavigate);

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

            const correlationId = obj.correlationId ? obj.correlationId : guid();
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
        this.info('Add adal frame to document: ' + iframeId);
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

    protected getStorageImplementation(config: Config): Storage {
        if (config.storage) {
            return config.storage;
        }

        if (config.cacheLocation === 'localStorage' && localStorageSupported()) {
            return new LocalStorage();
        }

        if (sessionStorageSupported()) {
            return new SessionStorage();
        }

        if (config.cacheLocation === 'localStorage') {
            throw new Error('Neither local storage nor session storage are supported on this device.');
        } else {
            throw new Error('Session storage is not supported on this device.');
        }
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
     * @param {string | Error} [error]  -  Error to log.
     * @param {boolean} [containsPii]  -  Set to true if logged data contains Personally Identifiable Information (PII) or Organizational Identifiable Information (OII)
     */
    public log(level: LOGGING_LEVEL, message: string, error?: string | Error, containsPii?: boolean): void {
        if (level <= Logging.level) {

            if (!(Logging as any).piiLoggingEnabled && containsPii) {
                return;
            }

            const timestamp = (new Date()).toISOString();
            let formattedMessage = '';

            const levelStr = (this.CONSTANTS.LEVEL_STRING_MAP as any)[level];

            let type = 'root';
            if (this.isIFrame) {
                type = 'iFrame';
            } else if (this.isPopup) {
                type = 'popUp';
            }

            if (this.config.correlationId) {
                formattedMessage = timestamp + ': (' + type + ') ' + this.config.correlationId + '-' + AuthenticationContext.VERSION + '-' + levelStr + ' ' + message;
            } else {
                formattedMessage = timestamp + ': (' + type + ') ' + AuthenticationContext.VERSION + '-' + levelStr + ' ' + message;
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
    private loginRefreshTimer: Subscription = null as any;

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

        this.context.onTokenReceived((token: string | null, info: TokenReceivedCallbackInfo, error: { message: string, description?: string } | null) => {
            console.info('onTokenReceived', token, info, error);

            if (this.context.isRoot) {
                if (info.requestType === REQUEST_TYPE.LOGIN) {
                    this.updateDataFromCache();
                    this.setupLoginTokenRefreshTimer();
                }
            }
        });

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
        const requestInfo = this.context.handleWindowCallback();

        if (requestInfo && this.context.isRoot) {
            if (requestInfo.requestType === REQUEST_TYPE.LOGIN) {
                this.updateDataFromCache();
                this.setupLoginTokenRefreshTimer();
            }
        }
    }

    public getCachedToken(resource: string): string | null {
        return this.context.getCachedToken(resource);
    }

    public acquireToken(resource: string): Observable<string | null> {
        return fromPromise(this.context.acquireToken(resource))
            .pipe(
                catchError((error) => throwError('Error when acquiring token for resource "' + resource + '": ' + error)),
                take(1)
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
        this.user.authenticated = (!!token);

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
        const expirationStr = this.context.storage.get(this.context.STORAGE_CONSTANTS.EXPIRATION_KEY + this.context.config.loginResource);
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
