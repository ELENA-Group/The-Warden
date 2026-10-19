export class ElenaMissionError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'ElenaMissionError';
    this.status = status;
    this.code = code;
  }
}
