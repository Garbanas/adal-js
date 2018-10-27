type SimpleQueryParamsMap<T extends string = string> = { [key in T | string]: string[]};

const find = /[!'\(\)~]|%20|%00/g;
const plus = /\+/g;
const replace: {[key: string]: string} = {
    '!': '%21',
    "'": '%27',
    '(': '%28',
    ')': '%29',
    '~': '%7E',
    '%20': '+',
    '%00': '\x00',
};
const replacer = (match: string) => replace[match];

function set(dictionary: any, name: string, value: string): void {
    dictionary[name] = [value];
}

function appendTo(dictionary: any, name: string, value: string): void {
    if (name in dictionary) {
        dictionary[name].push(value);
    } else {
        dictionary[name] = [value];
    }
}

function decode(uriComponent: string): string {
    return decodeURIComponent(uriComponent.replace(plus, ' '));
}

function encode(uriComponent: string): string {
    return encodeURIComponent(uriComponent)
        .replace(find, replacer);
}

export class SimpleURLSearchParams<T extends string = string> {
    private readonly paramsMap: SimpleQueryParamsMap<T>;

    constructor(query?: string, flatMap: boolean = false) {
        const dict: SimpleQueryParamsMap<T> = Object.create(null);
        this.paramsMap = dict;

        if (!query) {
            return;
        }

        const setterVariant = (flatMap ? set : appendTo);

        if (query.charAt(0) === '?') {
            query = query.slice(1);
        }

        const pairs = query.split('&');
        let index;
        for (const pair of pairs) {
            index = pair.indexOf('=');
            if (index > -1) {
                setterVariant(
                    dict,
                    decode(pair.slice(0, index)),
                    decode(pair.slice(index + 1))
                );
            } else if (pair.length) {
                setterVariant(
                    dict,
                    decode(pair),
                    ''
                );
            }
        }
    }

    public append(name: T, value: string): void {
        appendTo(this.paramsMap, name, value);
    }

    public delete(name: T): void {
        delete this.paramsMap[name];
    }

    public get(name: T): string | null {
        const dict = this.paramsMap;

        return name in dict ? dict[name][0] : null;
    }

    public getAll(name: T): string[] {
        const dict = this.paramsMap;

        return name in dict ? dict[name].slice(0) : [];
    }

    public has(name: T): boolean {
        return name in this.paramsMap;
    }

    public set(name: T, value: string): void {
        set(this.paramsMap, name, value);
    }

    public forEach(callback: (value: string, name: T) => void, thisArg?: any): void {
        const dict = this.paramsMap;
        Object.getOwnPropertyNames(dict)
            .forEach((name) => {
                dict[name].forEach((value) => {
                    callback.call(thisArg, value, name, this);
                }, this);
            }, this);
    }

    public toString(): string {
        const dict = this.paramsMap;
        const query = [];

        let i;
        let key;
        let name;
        let value;

        for (key in dict) { // tslint:disable-line forin
            name = encode(key);
            for (i = 0, value = dict[key]; i < value.length; i += 1) {
                query.push(name + '=' + encode(value[i]));
            }
        }

        return query.join('&');
    }
}
