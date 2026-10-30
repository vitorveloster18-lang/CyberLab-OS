export interface CyberLabServerTarget {
  baseUrl?: string
  password?: string
  directory?: string
}

function buildHeaders(password?: string): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" }
  if (password) {
    headers.Authorization = `Basic ${btoa(`opencode:${password}`)}`
  }
  return headers
}

export async function cyberlabFetch<T>(
  target: CyberLabServerTarget,
  endpointPath: string,
  init?: RequestInit,
): Promise<T> {
  const origin = target.baseUrl || (typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:4096")
  const url = new URL(endpointPath, origin.endsWith("/") ? origin : `${origin}/`)
  if (target.directory) {
    url.searchParams.set("location[directory]", target.directory)
  }

  const extraHeaders: Record<string, string> = {}
  if (init?.headers && !(init.headers instanceof Headers) && !Array.isArray(init.headers)) {
    for (const [k, v] of Object.entries(init.headers)) {
      if (typeof v === "string") extraHeaders[k] = v
    }
  }

  const response = await fetch(url.toString(), {
    ...init,
    credentials: "include",
    headers: {
      ...buildHeaders(target.password),
      ...extraHeaders,
    },
  })

  if (!response.ok) {
    const errText = await response.text().catch(() => "")
    throw new Error(`HTTP ${response.status}${errText ? `: ${errText.slice(0, 260)}` : ""}`)
  }

  const json = (await response.json()) as { data?: T }
  return (json && "data" in json ? json.data : json) as T
}
