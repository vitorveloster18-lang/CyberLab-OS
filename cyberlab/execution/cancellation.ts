export type AbortCauseKind = "cancelled" | "timed_out"

export class ManagedExecutionAbort {
  private readonly controller = new AbortController()
  private timer: ReturnType<typeof setTimeout> | undefined
  private causeKind: AbortCauseKind | undefined
  private causeReason: string | undefined

  constructor(timeoutMs: number, parentSignal?: AbortSignal) {
    if (parentSignal) {
      if (parentSignal.aborted) {
        this.cancel("Aborted by parent execution signal")
      } else {
        parentSignal.addEventListener(
          "abort",
          () => {
            this.cancel("Aborted by parent execution signal")
          },
          { once: true },
        )
      }
    }

    if (timeoutMs > 0 && !this.controller.signal.aborted) {
      this.timer = setTimeout(() => {
        if (!this.controller.signal.aborted) {
          this.causeKind = "timed_out"
          this.causeReason = `Execution exceeded timeout of ${timeoutMs}ms`
          this.controller.abort(new Error(this.causeReason))
        }
      }, timeoutMs)
    }
  }

  get signal(): AbortSignal {
    return this.controller.signal
  }

  get kind(): AbortCauseKind | undefined {
    return this.causeKind
  }

  get reason(): string | undefined {
    return this.causeReason
  }

  cancel(reason: string): void {
    if (this.controller.signal.aborted) return
    this.causeKind = "cancelled"
    this.causeReason = reason
    this.controller.abort(new Error(reason))
    this.dispose()
  }

  dispose(): void {
    if (this.timer !== undefined) {
      clearTimeout(this.timer)
      this.timer = undefined
    }
  }
}

export function capOutputBytes(input: string, maxBytes: number): { text: string; truncated: boolean; originalBytes: number } {
  const encoded = new TextEncoder().encode(input)
  if (encoded.byteLength <= maxBytes) {
    return { text: input, truncated: false, originalBytes: encoded.byteLength }
  }
  const sliced = encoded.subarray(0, maxBytes)
  const decoded = new TextDecoder("utf-8", { fatal: false }).decode(sliced)
  return {
    text: `${decoded}\n...[cyberlab: output truncated at ${maxBytes} bytes; original=${encoded.byteLength} bytes]`,
    truncated: true,
    originalBytes: encoded.byteLength,
  }
}
