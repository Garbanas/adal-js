export interface JwtPayload {
    /**
     * Audience
     *
     * Identifies the intended recipient of the token. In ID tokens, the audience is your app's Application ID, assigned
     * to your app in the Microsoft Application Registration Portal.
     * Your app should validate this value, and reject the token if the value does not match.
     *
     * @example 6731de76-14a6-49ae-97bc-6eba6914391e
     */
    aud?: string;

    /**
     * Issuer
     *
     * Identifies the security token service (STS) that constructs and returns the token, and the Azure AD tenant in
     * which the user was authenticated. Your app should validate the issuer claim to ensure that the token came from
     * the v2.0 endpoint. It also should use the GUID portion of the claim to restrict the set of tenants that can sign
     * in to the app. The GUID that indicates that the user is a consumer user from a Microsoft account is
     * 9188040d-6c67-4c5b-b112-36a304b66dad.
     *
     * @example https://login.microsoftonline.com/b9419818-09af-49c2-b0c3-653adc1f376e/v2.0
     */
    iss?: string;

    /**
     * Issued at
     *
     * The time at which the token was issued, represented in epoch time.
     *
     * @example 1452285331
     */
    iat?: string;

    /**
     * Expiration time
     *
     * The time at which the token becomes invalid, represented in epoch time. Your app should use this claim to verify
     * the validity of the token lifetime.
     *
     * @example 1452289231
     */
    exp?: string;

    /**
     * Not before
     *
     * The time at which the token becomes valid, represented in epoch time. It is usually the same as the issuance
     * time. Your app should use this claim to verify the validity of the token lifetime.
     *
     * @example 1452285331
     */
    nbf?: string;

    /**
     * Version
     *
     * The version of the ID token, as defined by Azure AD. For the v2.0 endpoint, the value is 2.0.
     *
     * @example 2.0
     */
    ver?: string;

    /**
     * Tenant ID
     *
     * A GUID that represents the Azure AD tenant that the user is from. For work and school accounts, the GUID is the
     * immutable tenant ID of the organization that the user belongs to. For personal accounts, the value is
     * 9188040d-6c67-4c5b-b112-36a304b66dad. The profile scope is required in order to receive this claim.
     *
     * @example b9419818-09af-49c2-b0c3-653adc1f376e
     */
    tid?: string;

    /**
     * Code hash
     *
     * The code hash is included in ID tokens only when the ID token is issued with an OAuth 2.0 authorization code.
     * It can be used to validate the authenticity of an authorization code. For details about performing this
     * validation, see the OpenID Connect specification.
     *
     * @example SGCPtt01wxwfgnYZy2VJtQ
     */
    c_hash?: string;

    /**
     * Access token hash
     *
     * The access token hash is included in ID tokens only when the ID token is issued with an OAuth 2.0 access token.
     * It can be used to validate the authenticity of an access token. For details about performing this validation,
     * see the OpenID Connect specification.
     *
     * @example SGCPtt01wxwfgnYZy2VJtQ
     */
    at_hash?: string;

    /**
     * Nonce
     *
     * The nonce is a strategy for mitigating token replay attacks. Your app can specify a nonce in an authorization
     * request by using the nonce query parameter. The value you provide in the request is emitted in the ID token's
     * nonce claim, unmodified. Your app can verify the value against the value it specified on the request, which
     * associates the app's session with a specific ID token. Your app should perform this validation during the ID
     * token validation process.
     *
     * @example 12345
     */
    nonce?: string;

    /**
     * Name
     *
     * The name claim provides a human-readable value that identifies the subject of the token. The value is not
     * guaranteed to be unique, it is mutable, and it's designed to be used only for display purposes. The profile
     * scope is required in order to receive this claim.
     *
     * @example Babe Ruth
     */
    name?: string;

    /**
     * Email
     *
     * The primary email address associated with the user account, if one exists. Its value is mutable and might change
     * over time. The email scope is required in order to receive this claim.
     *
     * @example thegreatbambino@nyy.onmicrosoft.com
     */
    email?: string;

    /**
     * Preferred username
     *
     * The primary username that represents the user in the v2.0 endpoint. It could be an email address, phone number,
     * or a generic username without a specified format. Its value is mutable and might change over time. Since it is
     * mutable, this value must not be used to make authorization decisions. The profile scope is required in order to
     * receive this claim.
     *
     * @example thegreatbambino@nyy.onmicrosoft.com
     */
    preferred_username?: string;

    /**
     * Subject
     *
     * The principal about which the token asserts information, such as the user of an app. This value is immutable and
     * cannot be reassigned or reused. It can be used to perform authorization checks safely, such as when the token is
     * used to access a resource, and can be used as a key in database tables. Because the subject is always present in
     * the tokens that Azure AD issues, we recommend using this value in a general-purpose authorization system.
     * The subject is, however, a pairwise identifier - it is unique to a particular application ID. Therefore, if a
     * single user signs into two different apps using two different client IDs, those apps will receive two different
     * values for the subject claim. This may or may not be desired depending on your architecture and privacy
     * requirements.
     *
     * @example MF4f-ggWMEji12KynJUNQZphaUTvLcQug5jdF2nl01Q
     */
    sub?: string;

    /**
     * Object ID
     *
     * The immutable identifier for an object in the Microsoft identity system, in this case, a user account. It can
     * also be used to perform authorization checks safely and as a key in database tables. This ID uniquely identifies
     * the user across applications - two different applications signing in the same user will receive the same value in
     * the oid claim. This means that it can be used when making queries to Microsoft online services, such as the
     * Microsoft Graph. The Microsoft Graph will return this ID as the id property for a given user account. Because
     * the oid allows multiple apps to correlate users, the profile scope is required in order to receive this claim.
     * Note that if a single user exists in multiple tenants, the user will contain a different object ID in each tenant
     * - they are considered different accounts, even though the user logs into each account with the same credentials.
     *
     * @example a1dbdde8-e4f9-4571-ad93-3059e3750d23
     */
    oid?: string;

    // From adal-angular
    upn?: string;

    // From different spec
    amr?: string[];
    family_name?: string;
    given_name: string;
    ipaddr: string;
    platf?: string;
    unique_name: string;
}

export class JwtUtility {
    /**
     * Returns the decoded JSON web token payload.
     *
     * @param {string} jwt
     * @throws Will throw an error if the token can not be decoded.
     */
    public static getPayloadFromToken(jwt: string): JwtPayload {
        const decodedToken = JwtUtility.decodeJwt(jwt);

        const base64Decoded = JwtUtility.base64DecodeStringUrlSafe(decodedToken.JWSPayload);
        if (!base64Decoded) {
            throw new Error('The token could not be base64 url safe decoded.');
        }

        return JSON.parse(base64Decoded);
    }

    /**
     * Decodes a JSON web token into an object with header, payload and signature fields.
     *
     * @param {string} jwt
     * @throws Will throw an error if the argument is not parsable.
     */
    public static decodeJwt(jwt: string): { header: string, JWSPayload: string, JWSSig: string } {
        const idTokenPartsRegex = /^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/;

        const matches = idTokenPartsRegex.exec(jwt);
        if (!matches || matches.length < 4) {
            throw new Error('Failed to decode token. Value has invalid format.');
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
