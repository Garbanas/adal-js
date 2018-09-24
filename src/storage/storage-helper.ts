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
