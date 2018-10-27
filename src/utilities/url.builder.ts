import { RESPONSE_TYPE } from '../constants';
import { AuthenticationContext, User, UserProfile } from '../adal.service';
import { guid } from './guid';
import { SimpleURLSearchParams } from './simple-url-search-params';

const MICROSOFT_LOGIN_URL = 'https://login.microsoftonline.com/';
const TENANT_DEFAULT = 'common';

type KNOWN_QUERY_PARAMS =
    'response_type'
    | 'client_id'
    | 'resource'
    | 'redirect_uri'
    | 'state'
    | 'slice'
    | 'correlationId'
    | 'nonce'
    // | 'postLogoutRedirectUri'
    // | 'logOutUri'

    // CorrelationID || GUID
    | 'client-request-id'

    // From extraQueryParameter, i.e. KNOWN_ADDITIONAL_QUERY_PARAMS
    | 'prompt'
    | 'sid'
    | 'login_hint'
    | 'domain_hint'

    | 'claims' // ?

    // Library Metadata
    | 'x-client-SKU'
    | 'x-client-Ver'
    ;

type KNOWN_ADDITIONAL_QUERY_PARAMS =
    'prompt'
    | 'sid'
    | 'login_hint'
    | 'domain_hint'
    ;

export interface UrlBuilderConfig {
    instance?: string;
    tenant?: string;
    // responseType?: RESPONSE_TYPE;
    clientId?: string;
    // resource?: string;
    redirectUri?: string;
    state?: string;
    slice?: string;
    extraQueryParameter?: string;
    correlationId?: string;
    // nonce?: string;
    postLogoutRedirectUri?: string;
    logOutUri?: string;
}

export class UrlBuilder {
    private instance!: string;
    private tenant!: string;

    private correlationId?: string;
    // private nonce?: string;

    private postLogoutRedirectUri?: string;
    private logOutUri?: string;

    private parametersToRemove: string[] = [];

    private profile?: UserProfile;

    private queryParams!: SimpleURLSearchParams<KNOWN_QUERY_PARAMS>;
    private additionalQueryParams!: SimpleURLSearchParams<KNOWN_ADDITIONAL_QUERY_PARAMS>;
    private extraQueryParams!: SimpleURLSearchParams;

    private config: UrlBuilderConfig;

    constructor(config?: UrlBuilderConfig) {
        this.config = config || Object.create(null);
        this.reset();
    }

    public reset(): UrlBuilder {
        this.instance = this.config.instance || MICROSOFT_LOGIN_URL;
        this.tenant = this.config.tenant || TENANT_DEFAULT;

        const queryParams = new SimpleURLSearchParams<KNOWN_QUERY_PARAMS>();
        // if (this.config.responseType != null) {
        //   queryParams.set('response_type', this.config.responseType);
        // }
        if (this.config.clientId != null) {
            queryParams.set('client_id', this.config.clientId);
        }
        // if (this.config.resource != null) {
        //   queryParams.set('resource', this.config.resource);
        // }
        if (this.config.redirectUri != null) {
            queryParams.set('redirect_uri', this.config.redirectUri);
        }
        if (this.config.state != null) {
            queryParams.set('state', this.config.state);
        }
        if (this.config.slice != null) {
            queryParams.set('slice', this.config.slice);
        }
        // if (this.config.correlationId != null) {
        //   queryParams.set('correlationId', this.config.correlationId);
        // }
        this.correlationId = this.config.correlationId;
        // if (this.config.nonce != null) {
        //   queryParams.set('nonce', this.config.nonce);
        // }
        // if (this.config.postLogoutRedirectUri != null) {
        //   queryParams.set('postLogoutRedirectUri', this.config.postLogoutRedirectUri);
        // }
        this.postLogoutRedirectUri = this.config.postLogoutRedirectUri;
        // if (this.config.logOutUri != null) {
        //   queryParams.set('logOutUri', this.config.logOutUri);
        // }
        this.logOutUri = this.config.logOutUri;

        this.additionalQueryParams = new SimpleURLSearchParams<KNOWN_ADDITIONAL_QUERY_PARAMS>(this.config.extraQueryParameter, true);
        this.extraQueryParams = new SimpleURLSearchParams();

        this.parametersToRemove = ['nonce'];

        this.profile = undefined;

        this.queryParams = queryParams;

        return this;
    }

    public setResponseType(responseType?: RESPONSE_TYPE): UrlBuilder {
        if (responseType) {
            this.queryParams.set('response_type', responseType);
        } else {
            this.queryParams.delete('response_type');
        }

        return this;
    }

    public setResource(resource?: string): UrlBuilder {
        if (resource) {
            this.queryParams.set('resource', resource);
        } else {
            this.queryParams.delete('resource');
        }

        return this;
    }

    public setNonce(nonce?: string): UrlBuilder {
        // @TODO To be applied last, overriding additionalQueryParams
        if (nonce) {
            this.queryParams.set('nonce', nonce);
        } else {
            this.queryParams.delete('nonce');
        }

        return this;
    }

    public setPrompt(prompt?: string): UrlBuilder {
        // @TODO To be applied last, overriding additionalQueryParams
        if (prompt) {
            this.queryParams.set('prompt', prompt);
        } else {
            this.queryParams.delete('prompt');
        }

        return this;
    }

    public setClaims(claims?: string): UrlBuilder {
        if (claims) {
            this.queryParams.set('claims', claims);
        } else {
            this.queryParams.delete('claims');
        }

        return this;
    }

    public setParametersToRemove(parametersToRemove: string[]): UrlBuilder {
        this.parametersToRemove = parametersToRemove || [];

        return this;
    }

    public addParameterToRemove(parameterToRemove: string): UrlBuilder {
        this.parametersToRemove.push(parameterToRemove);

        return this;
    }

    public setExtraQueryParameters(extraQueryParameters: string): UrlBuilder {
        this.extraQueryParams = new SimpleURLSearchParams(extraQueryParameters, true);

        return this;
    }

    /**
     * Adds login_hint to authorization URL which is used to pre-fill the username field of sign in page for the user if known ahead of time.
     * domain_hint can be one of users/organisations which when added skips the email based discovery process of the user.
     */
    public addLoginHintForUser(user?: User | null): UrlBuilder {
        // @TODO To be applied last, overriding additionalQueryParams

        // If you don't use prompt=none, then if the session does not exist, there will be a failure.
        // If sid is sent alongside domain or login hints, there will be a failure since request is ambiguous.
        // If sid is sent with a prompt value other than none or attempt_none, there will be a failure since the request is ambiguous.

        if (user && user.profile) {
            const profile: UserProfile = Object.create(null);
            profile.sid = user.profile.sid;
            profile.upn = user.profile.upn;

            this.profile = profile;
        } else {
            this.profile = undefined;
        }

        return this;
    }

    public forRedirect(responseType: RESPONSE_TYPE, resource?: string): string {
        return this.setResource(resource)
            .setResponseType(responseType)
            .build();
    }

    public forLogout(): string {
        if (this.logOutUri) {
            return this.logOutUri;
        }

        const queryParams = new SimpleURLSearchParams();
        if (this.postLogoutRedirectUri) {
            queryParams.set('post_logout_redirect_uri', this.postLogoutRedirectUri);
        }

        return this.instance
            + this.tenant
            + '/oauth2/logout?'
            + queryParams.toString();
    }

    public build(): string {
        return this.instance
            + this.tenant
            + '/oauth2/authorize?'
            + this.serializeQueryParams();
    }

    /**
     * Serializes the parameters for the authorization endpoint URL and returns the serialized uri string.
     */
    protected serializeQueryParams(): string {
        if (!this.queryParams.has('response_type')) {
            throw new Error('responseType not set');
        }
        if (!this.queryParams.has('client_id')) {
            throw new Error('clientId not set');
        }
        if (!this.queryParams.has('redirect_uri')) {
            throw new Error('redirectUri not set');
        }
        if (!this.queryParams.has('state')) {
            throw new Error('state not set');
        }

        const queryParams = new SimpleURLSearchParams<KNOWN_QUERY_PARAMS>();
        this.queryParams.forEach((value, name) => {
            queryParams.set(name, value);
        });

        const sanitizedAdditionalQueryParams = new SimpleURLSearchParams<KNOWN_ADDITIONAL_QUERY_PARAMS>();
        this.additionalQueryParams.forEach((value, name) => {
            // Removes the query string parameter from the authorization endpoint URL if it exists
            if (this.parametersToRemove.indexOf(name) === -1) {
                queryParams.set(name as KNOWN_QUERY_PARAMS, value);
                sanitizedAdditionalQueryParams.set(name, value);
            }
        });

        const correlationId = this.correlationId ? this.correlationId : guid();
        queryParams.set('client-request-id', correlationId);

        this.extraQueryParams.forEach((value, name) => {
            queryParams.set(name as KNOWN_QUERY_PARAMS, value);
        });

        this.addLoginHintParameters(queryParams, sanitizedAdditionalQueryParams);

        this.addLibMetadata(queryParams);

        return queryParams.toString();
    }

    /**
     * Adds login_hint to authorization URL which is used to pre-fill the username field of sign in page for the user if known ahead of time.
     * domain_hint can be one of users/organisations which when added skips the email based discovery process of the user.
     */
    protected addLoginHintParameters(queryParams: SimpleURLSearchParams<KNOWN_QUERY_PARAMS>, additionalQueryParams: SimpleURLSearchParams<KNOWN_ADDITIONAL_QUERY_PARAMS>): void {
        // If you don't use prompt=none, then if the session does not exist, there will be a failure.
        // If sid is sent alongside domain or login hints, there will be a failure since request is ambiguous.
        // If sid is sent with a prompt value other than none or attempt_none, there will be a failure since the request is ambiguous.

        if (this.profile) {
            if (this.profile.sid && additionalQueryParams.get('prompt') === 'none') {
                // don't add sid twice if user provided it in the extraQueryParameter value
                if (!additionalQueryParams.has('sid')) {
                    // add sid
                    queryParams.set('sid', this.profile.sid);
                }

            } else if (this.profile.upn) {
                // don't add login_hint twice if user provided it in the extraQueryParameter value
                if (!additionalQueryParams.has('login_hint')) {
                    // add login_hint
                    queryParams.set('login_hint', this.profile.upn);
                }

                // don't add domain_hint twice if user provided it in the extraQueryParameter value
                if (
                    !additionalQueryParams.has('domain_hint')
                    && this.profile.upn.indexOf('@') !== -1
                ) {
                    const parts = this.profile.upn.split('@');
                    // local part can include @ in quotes. Sending last part handles that.
                    queryParams.set('domain_hint', parts[parts.length - 1]);
                }
            }
        }
    }

    /**
     * Adds the library version and returns it.
     */
    protected addLibMetadata(queryParams: SimpleURLSearchParams<KNOWN_QUERY_PARAMS>): void {
        // x-client-SKU
        // x-client-Ver
        queryParams.append('x-client-SKU', 'Js');
        queryParams.append('x-client-Ver', AuthenticationContext.VERSION);
    }
}
