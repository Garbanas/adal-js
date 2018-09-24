import { Storage } from './storage';

export class SessionStorage implements Storage {
    public set(key: string, value: string): SessionStorage {
        sessionStorage.setItem(key, value);

        return this;
    }

    public get(key: string): string | undefined {
        const item = sessionStorage.getItem(key);
        if (item !== null) {
            return item;
        }
    }
}
