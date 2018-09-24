import { Storage } from './storage';

export class LocalStorage implements Storage {
    public set(key: string, value: string): LocalStorage {
        localStorage.setItem(key, value);

        return this;
    }

    public get(key: string): string | undefined {
        const item = localStorage.getItem(key);
        if (item !== null) {
            return item;
        }
    }
}
