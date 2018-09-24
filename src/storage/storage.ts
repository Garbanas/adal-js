export interface Storage {
    /**
     * The set() method adds or updates an element with a specified key and value.
     *
     * @param {string} key  -  The key of the element to add to the storage.
     * @param {string} value  -  The value of the element to add to the storage.
     * @returns {Storage} The object itself for chaining calls.
     */
    set(key: string, value: string): Storage;

    /**
     * The get() method returns a specified element.
     *
     * @param key - The key of the element to return from the storage.
     * @returns Returns the element associated with the specified key or undefined if the key can't be found in the storage.
     */
    get(key: string): string | undefined;
}
