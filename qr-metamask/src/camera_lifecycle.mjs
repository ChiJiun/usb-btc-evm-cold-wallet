/** Ignore late camera starts/callbacks after cancel or a newer scan begins.
 * A BrowserQRCodeReader start is asynchronous and may resolve after Stop.
 * Each scan owns one generation; stale controls are stopped immediately.
 */
export class CameraLifecycle {
  #epoch = 0;
  #pending = false;
  #controls = null;

  begin() {
    if (this.#pending || this.#controls) return null;
    this.#pending = true;
    return ++this.#epoch;
  }

  isCurrent(epoch) {
    return epoch === this.#epoch && (this.#pending || this.#controls !== null);
  }

  attach(epoch, controls) {
    if (!this.isCurrent(epoch)) {
      controls?.stop?.();
      return false;
    }
    this.#pending = false;
    this.#controls = controls;
    return true;
  }

  cancel() {
    ++this.#epoch;
    this.#pending = false;
    this.#controls?.stop?.();
    this.#controls = null;
  }
}
