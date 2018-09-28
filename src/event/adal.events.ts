/**
 * Class for event subscription.
 */
export class AdalEvents {
  /**
   * Event names in keys and arrays with listeners in values.
   * @type {object}
   */
  public events: {[key: string]: ((...args: any[]) => void)[]};

  constructor() {
    this.events = Object.create(null);
  }

  /**
   * Add a listener for a given event.
   *
   * @param {string} event  -  The event name.
   * @param {function} callback  -  The listener function.
   *
   * @return {function} Unbind listener from event.
   */
  public on<T extends (...args: any[]) => void>(event: string, callback: T): () => void {
    this.events[event] = this.events[event] || [];
    const events = this.events[event];
    events.push(callback);

    return () => {
      // a.splice(i >>> 0, 1) === if (i !== -1) a.splice(i, 1)
      // -1 >>> 0 === 0xFFFFFFFF, max possible array length
      events.splice(events.indexOf(callback) >>> 0, 1); // tslint:disable-line no-bitwise
    };
  }

  /**
   * Add a listener for a given event that is only executed once.
   *
   * @param {string} event  -  The event name.
   * @param {function} callback  -  The listener function.
   *
   * @return {function} Unbind listener from event.
   */
  public once(event: string, callback: (...args: any[]) => void): () => void {
    const unbind = this.on(event, (...args: any[]) => {
      unbind();
      callback(...args);
    });

    return unbind;
  }

  /**
   * Calls each of the listeners registered for a given event.
   *
   * @param {string} event  -  The event name.
   * @param {...*} arguments  -  The arguments for listeners.
   */
  public emit(event: string, ...args: any[]): void {
    const list = this.events[event];
    if (!list || !list[0]) { // list[0] === Array.isArray(list)
      return;
    }

    list.slice()
      .map((callback) => {
        callback(...args);
      });
  }
}
