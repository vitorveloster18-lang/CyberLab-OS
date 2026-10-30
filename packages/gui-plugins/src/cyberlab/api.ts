import type { ServerRef } from "@opencode/plugin/gui"

function buildAuthHeaders(password?: string): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" }
  if (password) {
    headers.Authorization = `Basic ${btoa(`opencode:${password}`)}`
  }
  return headers
}

export async function cyberlabRequest<T>(
  server: Pick<ServerRef, "url" | "password"> | undefined,
  directory: string | undefined,
  endpointPath: string,
  init?: RequestInit,
): Promise<T> {
  const baseUrl = server?.url || window.location.origin
  const url = new URL(endpointPath, baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`)
  if (directory) {
    url.searchParams.set("location[directory]", directory)
  }
  const response = await fetch(url.toString(), {
    ...init,
    credentials: "include",
    headers: {
      ...buildAuthHeaders(server?.password),
      ...(init?.headers ? (init.headers as Record<string, string>) : {}),
    },
  })
  if (!response.ok) {
    const errText = await response.text().catch(() => "")
    throw new Error(`HTTP ${response.status}${errText ? `: ${errText.slice(0, 180)}` : ""}`)
  }
  const payload = (await response.json()) as { data: T }
  return payload.data
}
