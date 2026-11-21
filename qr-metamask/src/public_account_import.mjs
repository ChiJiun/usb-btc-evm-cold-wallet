/** Discard stale public account File.text() completions and errors. */
export class PublicAccountImport {
  #generation=0;
  #validate;
  constructor(validate) {
    if(typeof validate!=='function') throw new TypeError('Validator required');
    this.#validate=validate;
  }
  cancel() { ++this.#generation; }
  async read(file,maxBytes=10_000) {
    const epoch=++this.#generation;
    try {
      if(!file || file.size<=0 || file.size>maxBytes) {
        throw new Error('只接受大小有限的 JSON 檔案');
      }
      const raw=await file.text();
      if(epoch!==this.#generation) return null;
      const info=JSON.parse(raw);
      const validated=this.#validate(info);
      if(epoch!==this.#generation) return null;
      return {info,validated};
    } catch(err) {
      if(epoch!==this.#generation) return null;
      throw err;
    }
  }
}
