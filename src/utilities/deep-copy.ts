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
