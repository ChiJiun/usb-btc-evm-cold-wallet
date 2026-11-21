/**
 * One QR display generation owns one frame encoder promise and one timer.
 * Invalidating a generation makes late async QR renders harmless.
 */
export class QrFrameDisplay {
  #generation = 0;
  #timer = null;
  #encode;
  #image;
  #label;
  #schedule;
  #unschedule;
  #onError;
  #delay;

  constructor({ encode, image, label,
    // Browser timers must retain their window receiver; passing bare
    // setTimeout/clearTimeout as methods throws "Illegal invocation".
    schedule = (callback, delay) => setTimeout(callback, delay),
    unschedule = (timer) => clearTimeout(timer),
    onError = () => {}, delay = 400 }) {
    this.#encode = encode;
    this.#image = image;
    this.#label = label;
    this.#schedule = schedule;
    this.#unschedule = unschedule;
    this.#onError = onError;
    this.#delay = delay;
  }

  clear() {
    ++this.#generation;
    if (this.#timer !== null) this.#unschedule(this.#timer);
    this.#timer = null;
    this.#image.hidden = true;
    this.#image.removeAttribute('src');
    this.#label.textContent = '';
  }

  async show(ur, frames) {
    if (!ur || !Array.isArray(frames) || frames.length === 0 ||
        frames.some((frame) => typeof frame !== 'string' || frame.length === 0)) {
      throw new Error('Invalid QR display frames');
    }
    this.clear();
    const generation = this.#generation;
    const render = async (index) => {
      if (generation !== this.#generation) return false;
      // Never advance the frame or schedule its successor until this encoding
      // has finished. An old encode cannot paint a new session after cancel.
      const src = await this.#encode(frames[index], {
        errorCorrectionLevel: 'M', margin: 1, width: 400,
      });
      if (generation !== this.#generation) return false;
      this.#image.src = src;
      this.#image.hidden = false;
      this.#label.textContent = ur.type + ' · ' + (index + 1) + '/' + frames.length;
      if (frames.length > 1) {
        this.#timer = this.#schedule(() => {
          this.#timer = null;
          void render((index + 1) % frames.length).catch((err) => {
            if (generation !== this.#generation) return;
            this.clear();
            this.#onError(err);
          });
        }, this.#delay);
      }
      return true;
    };
    return render(0);
  }
}
